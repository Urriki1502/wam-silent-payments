"""BIP174/370 maps and P2TR key-path signing. Draft SP fields use adapters.

Unknown fields survive parsing, combining, signing and finalization. Unsupported
signing policies fail closed; the map container is not a consensus validator.
"""

import base64
from dataclasses import dataclass, field, replace
from hashlib import sha256
from coincurve import PublicKeyXOnly
from .core import tagged, compressed
from .transaction import compact, blob, output

MAX_BYTES = 1_000_000
MAX_INPUTS = 128
MAX_OUTPUTS = 256


class Reader:
    def __init__(self, data):
        if not isinstance(data, bytes) or len(data) > MAX_BYTES:
            raise ValueError("PSBT_LIMIT")
        self.data, self.pos = data, 0

    def take(self, n):
        if type(n) is not int or n < 0 or self.pos + n > len(self.data):
            raise ValueError("TRUNCATED")
        x = self.data[self.pos : self.pos + n]
        self.pos += n
        return x

    def size(self, limit=MAX_BYTES):
        first = self.take(1)[0]
        n = (
            first
            if first < 253
            else int.from_bytes(self.take({253: 2, 254: 4, 255: 8}[first]), "little")
        )
        if (
            (first == 253 and n < 253)
            or (first == 254 and n < 65536)
            or (first == 255 and n < 2**32)
            or n > limit
        ):
            raise ValueError("NONCANONICAL_OR_LIMIT")
        return n

    def blob(self, limit=MAX_BYTES):
        return self.take(self.size(limit))

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError("TRAILING_DATA")


@dataclass(frozen=True, repr=False)
class Tx:
    inputs: tuple[tuple[str, int], ...]
    outputs: tuple[tuple[int, bytes], ...]
    sequence: int = 0xFFFFFFFD
    version: int = 2
    locktime: int = 0
    sequences: tuple[int, ...] = ()

    def sequence_values(self):
        return self.sequences or (self.sequence,) * len(self.inputs)

    def serialize(self, witness=None):
        if not 1 <= len(self.inputs) <= MAX_INPUTS or not 1 <= len(self.outputs) <= MAX_OUTPUTS:
            raise ValueError("TRANSACTION_LIMIT")
        if len(set(self.inputs)) != len(self.inputs):
            raise ValueError("DUPLICATE_INPUT")
        seqs = self.sequence_values()
        if len(seqs) != len(self.inputs) or any(
            type(s) is not int or not 0 <= s < 2**32 for s in seqs
        ):
            raise ValueError("SEQUENCE_RANGE")
        if (
            type(self.version) is not int
            or not -(2**31) <= self.version < 2**31
            or type(self.locktime) is not int
            or not 0 <= self.locktime < 2**32
        ):
            raise ValueError("TX_HEADER")
        result = (
            self.version.to_bytes(4, "little", signed=True)
            + (b"\x00\x01" if witness is not None else b"")
            + compact(len(self.inputs))
        )
        for (txid, vout), seq in zip(self.inputs, seqs):
            if (
                not isinstance(txid, str)
                or len(txid) != 64
                or type(vout) is not int
                or not 0 <= vout < 2**32
            ):
                raise ValueError("INVALID_OUTPOINT")
            result += (
                bytes.fromhex(txid)[::-1]
                + vout.to_bytes(4, "little")
                + b"\x00"
                + seq.to_bytes(4, "little")
            )
        if any(not isinstance(s, bytes) or len(s) > 10000 for _, s in self.outputs):
            raise ValueError("SCRIPT_LIMIT")
        if sum(v for v, _ in self.outputs) > 22_000_000 * 100_000_000:
            raise ValueError("AMOUNT_RANGE")
        result += compact(len(self.outputs)) + b"".join(output(v, s) for v, s in self.outputs)
        if witness is not None:
            if len(witness) != len(self.inputs):
                raise ValueError("WITNESS_COUNT")
            result += b"".join(
                compact(len(items)) + b"".join(blob(x) for x in items) for items in witness
            )
        return result + self.locktime.to_bytes(4, "little")

    @classmethod
    def parse(cls, data):
        r = Reader(data)
        version = int.from_bytes(r.take(4), "little", signed=True)
        inputs, seqs, outputs = [], [], []
        for _ in range(r.size(MAX_INPUTS)):
            inputs.append((r.take(32)[::-1].hex(), int.from_bytes(r.take(4), "little")))
            if r.blob(10000):
                raise ValueError("UNSIGNED_SCRIPTSIG")
            seqs.append(int.from_bytes(r.take(4), "little"))
        for _ in range(r.size(MAX_OUTPUTS)):
            outputs.append((int.from_bytes(r.take(8), "little"), r.blob(10000)))
        locktime = int.from_bytes(r.take(4), "little")
        r.finish()
        tx = cls(
            tuple(inputs),
            tuple(outputs),
            seqs[0] if seqs else 0xFFFFFFFF,
            version,
            locktime,
            () if len(set(seqs)) <= 1 else tuple(seqs),
        )
        if tx.serialize() != data:
            raise ValueError("NONCANONICAL_TX")
        return tx

    def sighash(self, utxos, index, sighash=0):
        if len(utxos) != len(self.inputs) or not 0 <= index < len(self.inputs):
            raise ValueError("UTXO_COUNT")
        if sighash not in (0, 1):
            raise ValueError("SIGHASH_POLICY")

        def h(b):
            return sha256(b).digest()

        return tagged(
            "TapSighash",
            bytes([0, sighash])
            + self.version.to_bytes(4, "little", signed=True)
            + self.locktime.to_bytes(4, "little")
            + h(b"".join(bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v in self.inputs))
            + h(b"".join(v.to_bytes(8, "little") for v, _ in utxos))
            + h(b"".join(blob(s) for _, s in utxos))
            + h(b"".join(s.to_bytes(4, "little") for s in self.sequence_values()))
            + h(b"".join(output(v, s) for v, s in self.outputs))
            + b"\x00"
            + index.to_bytes(4, "little"),
        )


def _read_map(r, allowed=None):
    result = {}
    while True:
        key = r.blob(10000)
        if not key:
            return result
        kr = Reader(key)
        kr.size(2**32 - 1)  # key type is a canonical CompactSize, not one byte only
        if key in result or len(result) >= 4096:
            raise ValueError("PSBT_DUPLICATE_OR_LIMIT")
        result[key] = r.blob()


def _map(items):
    return b"".join(blob(k) + blob(v) for k, v in sorted(items.items())) + b"\x00"


def _number(fields, key, length=4, default=None, signed=False):
    if key not in fields:
        if default is None:
            raise ValueError("PSBT_REQUIRED_FIELD")
        return default
    if len(fields[key]) != length:
        raise ValueError("PSBT_FIELD_LENGTH")
    return int.from_bytes(fields[key], "little", signed=signed)


def _count(raw, limit):
    r = Reader(raw)
    n = r.size(limit)
    r.finish()
    if not n:
        raise ValueError("PSBT_EMPTY_TRANSACTION")
    return n


def _shape(fields, singleton):
    for key in fields:
        if key[0] in singleton and len(key) != 1:
            raise ValueError("PSBT_KEYDATA")


def _merge(left, right):
    result = dict(left)
    for k, v in right.items():
        if k in result and result[k] != v:
            raise ValueError("PSBT_CONFLICT")
        result[k] = v
    return result


@dataclass(frozen=True, repr=False)
class PSBT:
    tx: Tx
    utxos: tuple[tuple[int, bytes], ...]
    signatures: tuple[bytes | None, ...] = ()
    version: int = 2
    global_extra: dict = field(default_factory=dict)
    input_extra: tuple[dict, ...] = ()
    output_extra: tuple[dict, ...] = ()

    def maps(self):
        self.tx.serialize()
        n = len(self.tx.inputs)
        if self.version not in (0, 2) or len(self.utxos) != n:
            raise ValueError("PSBT_VERSION_OR_UTXO_COUNT")
        sigs = self.signatures or (None,) * n
        ie = self.input_extra or tuple({} for _ in range(n))
        oe = self.output_extra or tuple({} for _ in self.tx.outputs)
        if len(sigs) != n or len(ie) != n or len(oe) != len(self.tx.outputs):
            raise ValueError("PSBT_MAP_COUNT")
        g = (
            {b"\x00": self.tx.serialize()}
            if self.version == 0
            else {
                b"\xfb": (2).to_bytes(4, "little"),
                b"\x02": self.tx.version.to_bytes(4, "little", signed=True),
                b"\x03": self.tx.locktime.to_bytes(4, "little"),
                b"\x04": compact(n),
                b"\x05": compact(len(oe)),
                b"\x06": self.global_extra.get(b"\x06", b"\x00"),
            }
        )
        g = _merge(g, self.global_extra)
        ins, outs = [], []
        for index, ((v, s), sig, extra) in enumerate(zip(self.utxos, sigs, ie)):
            compressed(b"\x02" + s[2:]) if len(s) == 34 and s[:2] == b"\x51\x20" else None
            fields = {b"\x01": output(v, s)}
            if len(s) > 10000:
                raise ValueError("SCRIPT_LIMIT")
            if self.version == 2:
                txid, vout = self.tx.inputs[index]
                fields.update(
                    {
                        b"\x0e": bytes.fromhex(txid)[::-1],
                        b"\x0f": vout.to_bytes(4, "little"),
                        b"\x10": self.tx.sequence_values()[index].to_bytes(4, "little"),
                    }
                )
            if sig is not None:
                if len(sig) != 64 and not (len(sig) == 65 and sig[-1] == 1):
                    raise ValueError("SIGHASH_POLICY")
                fields[b"\x13"] = sig
            ins.append(_merge(fields, extra))
        for (v, s), extra in zip(self.tx.outputs, oe):
            fields = {} if self.version == 0 else {b"\x03": v.to_bytes(8, "little"), b"\x04": s}
            outs.append(_merge(fields, extra))
        return g, ins, outs

    def encode(self):
        g, ins, outs = self.maps()
        result = b"psbt\xff" + _map(g) + b"".join(_map(x) for x in [*ins, *outs])
        if len(result) > MAX_BYTES:
            raise ValueError("PSBT_LIMIT")
        return result

    def base64(self):
        return base64.b64encode(self.encode()).decode("ascii")

    @classmethod
    def decode(cls, raw):
        r = Reader(raw)
        if r.take(5) != b"psbt\xff":
            raise ValueError("PSBT_MAGIC")
        g = _read_map(r)
        _shape(g, {0, 2, 3, 4, 5, 6, 0xFB})
        version = _number(g, b"\xfb", default=0)
        if version == 0:
            if b"\x00" not in g or any(
                k in g for k in (b"\x02", b"\x03", b"\x04", b"\x05", b"\x06")
            ):
                raise ValueError("PSBT_V0_FIELDS")
            tx = Tx.parse(g.pop(b"\x00"))
            ni, no = len(tx.inputs), len(tx.outputs)
        elif version == 2:
            if b"\x00" in g:
                raise ValueError("PSBT_V2_UNSIGNED_TX")
            tv = _number(g, b"\x02", signed=True)
            if tv < 2:
                raise ValueError("PSBT_V2_TX_VERSION")
            fallback = _number(g, b"\x03", default=0)
            if b"\x04" not in g or b"\x05" not in g:
                raise ValueError("PSBT_REQUIRED_FIELD")
            ni, no = _count(g[b"\x04"], MAX_INPUTS), _count(g[b"\x05"], MAX_OUTPUTS)
            flags = _number(g, b"\x06", 1, 0)
            if flags & ~7:
                raise ValueError("PSBT_MODIFIABLE_FLAGS")
        else:
            raise ValueError("PSBT_VERSION")
        ins = [_read_map(r) for _ in range(ni)]
        outs = [_read_map(r) for _ in range(no)]
        r.finish()
        utxos, sigs = [], []
        for m in ins:
            _shape(m, {0, 1, 3, 4, 5, 7, 8, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x17, 0x18, 0x20})
            if b"\x01" not in m:
                raise ValueError("WITNESS_UTXO_REQUIRED")
            u = Reader(m.pop(b"\x01"))
            val, script = int.from_bytes(u.take(8), "little"), u.blob(10000)
            u.finish()
            output(val, script)
            utxos.append((val, script))
            sig = m.pop(b"\x13", None)
            if sig is not None and len(sig) != 64 and not (len(sig) == 65 and sig[-1] == 1):
                raise ValueError("SIGHASH_POLICY")
            sigs.append(sig)
            if b"\x03" in m and _number(m, b"\x03") not in (0, 1):
                raise ValueError("SIGHASH_POLICY")
            if version == 0 and any(k in m for k in (b"\x0e", b"\x0f", b"\x10", b"\x11", b"\x12")):
                raise ValueError("PSBT_V0_FIELDS")
        for m in outs:
            _shape(m, {0, 1, 3, 4, 5, 6, 9, 10})
            if version == 0 and (b"\x03" in m or b"\x04" in m):
                raise ValueError("PSBT_V0_FIELDS")
        if version == 2:
            inputs, seqs, output_values = [], [], []
            time_locks, height_locks, allowed = [], [], {"time", "height"}
            for m in ins:
                if len(m.get(b"\x0e", b"")) != 32:
                    raise ValueError("PSBT_PREVIOUS_TXID")
                inputs.append((m.pop(b"\x0e")[::-1].hex(), _number(m, b"\x0f")))
                seqs.append(_number(m, b"\x10", default=0xFFFFFFFF))
                present = set()
                for k, group in ((b"\x11", "time"), (b"\x12", "height")):
                    if k in m:
                        value = _number(m, k)
                        if (group == "time" and value < 500000000) or (
                            group == "height" and not 0 < value < 500000000
                        ):
                            raise ValueError("PSBT_LOCKTIME_RANGE")
                        (time_locks if group == "time" else height_locks).append(value)
                        present.add(group)
                if present:
                    allowed &= present
                    if seqs[-1] == 0xFFFFFFFF:
                        raise ValueError("PSBT_LOCKTIME_DISABLED")
                for k in (b"\x0f", b"\x10"):
                    m.pop(k, None)
            if not allowed:
                raise ValueError("PSBT_LOCKTIME_CONFLICT")
            locktime = (
                max(height_locks)
                if height_locks and "height" in allowed
                else max(time_locks)
                if time_locks
                else fallback
            )
            for m in outs:
                value = _number(m, b"\x03", 8, signed=True)
                if b"\x04" not in m:
                    raise ValueError("PSBT_OUTPUT_UNRESOLVED")
                output_values.append((value, m.pop(b"\x04")))
                m.pop(b"\x03")
            tx = Tx(
                tuple(inputs),
                tuple(output_values),
                seqs[0],
                tv,
                locktime,
                () if len(set(seqs)) == 1 else tuple(seqs),
            )
            for k in (b"\xfb", b"\x02", b"\x03", b"\x04", b"\x05"):
                g.pop(k, None)
            if g.get(b"\x06") == b"\x00":
                g.pop(b"\x06")
        else:
            g.pop(b"\xfb", None)
        result = cls(tx, tuple(utxos), tuple(sigs), version, g, tuple(ins), tuple(outs))
        result.maps()
        from .adapters.sp_psbt import validate_fields

        validate_fields(result)
        return result

    @classmethod
    def from_base64(cls, value):
        if not isinstance(value, str) or len(value) > MAX_BYTES * 2:
            raise ValueError("PSBT_LIMIT")
        try:
            return cls.decode(base64.b64decode(value, validate=True))
        except (ValueError, TypeError):
            raise ValueError("PSBT_ENCODING") from None

    def sign(self, keys):
        # Roundtrip validates the same boundary for constructed and received PSBTs.
        p = self.decode(self.encode())
        if sum(v for v, _ in p.tx.outputs) > sum(v for v, _ in p.utxos):
            raise ValueError("NEGATIVE_FEE")
        if len(keys) != len(p.tx.inputs):
            raise ValueError("KEY_COUNT")
        if p.global_extra.get(b"\x06", b"\x00") != b"\x00":
            raise ValueError("PSBT_NOT_FROZEN")
        from .adapters.sp_psbt import verify_sender

        verify_sender(p)
        signatures = list(p.signatures)
        for i, (key, (_, script), extra) in enumerate(zip(keys, p.utxos, p.input_extra)):
            if key is None:
                continue
            if (
                len(script) != 34
                or script[:2] != b"\x51\x20"
                or key.public_key.format()[1:] != script[2:]
            ):
                raise ValueError("INPUT_KEY_MISMATCH")
            if b"\x04" in extra or b"\x05" in extra or b"\x07" in extra or b"\x08" in extra:
                raise ValueError("PSBT_SIGNING_POLICY")
            sighash = _number(
                extra, b"\x03", default=1 if any(b"\x09" in m for m in p.output_extra) else 0
            )
            if any(b"\x09" in m for m in p.output_extra) and sighash != 1:
                raise ValueError("SP_SIGHASH_ALL_REQUIRED")
            sig = key.sign_schnorr(p.tx.sighash(p.utxos, i, sighash)) + (
                b"\x01" if sighash else b""
            )
            if signatures[i] is not None:
                p._verify_signature(i, signatures[i])
            signatures[i] = sig
        return replace(p, signatures=tuple(signatures))

    def _verify_signature(self, i, sig):
        script = self.utxos[i][1]
        if sig is None or len(script) != 34 or script[:2] != b"\x51\x20":
            raise ValueError("SIGNATURE_INVALID")
        sighash = 0 if len(sig) == 64 else sig[-1] if len(sig) == 65 else -1
        fields = (self.input_extra or ({},) * len(self.utxos))[i]
        if b"\x03" in fields and _number(fields, b"\x03") != sighash:
            raise ValueError("PSBT_SIGHASH_MISMATCH")
        if any(b"\x09" in m for m in self.output_extra) and sighash != 1:
            raise ValueError("SP_SIGHASH_ALL_REQUIRED")
        if sighash not in (0, 1) or not PublicKeyXOnly(script[2:]).verify(
            sig[:64], self.tx.sighash(self.utxos, i, sighash)
        ):
            raise ValueError("SIGNATURE_INVALID")

    def finalize(self):
        p = self.decode(self.encode())
        if sum(v for v, _ in p.tx.outputs) > sum(v for v, _ in p.utxos):
            raise ValueError("NEGATIVE_FEE")
        from .adapters.sp_psbt import verify_sender

        verify_sender(p)
        sigs = []
        for i, (sig, m) in enumerate(zip(p.signatures, p.input_extra)):
            if b"\x08" in m:
                r = Reader(m[b"\x08"])
                if r.size(1) != 1:
                    raise ValueError("FINAL_WITNESS_POLICY")
                final = r.blob(65)
                r.finish()
                if sig is not None and sig != final:
                    raise ValueError("PSBT_CONFLICT")
                sig = final
            p._verify_signature(i, sig)
            sigs.append(sig)
        return p.tx.serialize([(s,) for s in sigs])

    def finalized(self):
        self.finalize()
        extras = []
        for sig, m in zip(self.signatures, self.input_extra or ({},) * len(self.utxos)):
            clean = {k: v for k, v in m.items() if k[0] not in (3, 0x13, 0x1F, 0x20)}
            if b"\x08" not in clean:
                clean[b"\x08"] = b"\x01" + blob(sig)
            extras.append(clean)
        return replace(self, signatures=(None,) * len(self.utxos), input_extra=tuple(extras))

    def combine(self, other):
        if (
            self.tx.serialize() != other.tx.serialize()
            or self.utxos != other.utxos
            or self.version != other.version
        ):
            raise ValueError("PSBT_CONFLICT")
        a, ai, ao = self.maps()
        b, bi, bo = other.maps()
        raw = (
            b"psbt\xff"
            + _map(_merge(a, b))
            + b"".join(_map(_merge(x, y)) for x, y in zip(ai + ao, bi + bo))
        )
        return self.decode(raw)

    def to_v0(self):
        """Explicit Core compatibility export. Reject draft fields; never drop them silently."""
        g, ins, outs = self.maps()
        if (
            any(k[0] in (7, 8) for k in g)
            or any(k[0] in (0x1D, 0x1E, 0x1F, 0x20) for m in ins for k in m)
            or any(k[0] in (9, 10) for m in outs for k in m)
        ):
            raise ValueError("DRAFT_FIELDS_REQUIRE_V2")
        return replace(
            self,
            version=0,
            global_extra={k: v for k, v in self.global_extra.items() if k != b"\x06"},
            input_extra=tuple(
                {k: v for k, v in m.items() if k not in (b"\x11", b"\x12")}
                for m in (self.input_extra or ({},) * len(ins))
            ),
        )

    def txid(self):
        raw = self.tx.serialize()
        return sha256(sha256(raw).digest()).digest()[::-1].hex()
