"""PSBTv2 workflow container including unresolved BIP375 output scripts.

This API validates sender metadata independently of the restricted P2TR signer.
It preserves all unknown fields and does not assert consensus-valid signatures.
"""

from dataclasses import dataclass
from coincurve import PublicKey
from ..core import compressed, scalar, tagged, ser, K_MAX
from ..psbt import Reader, PSBT, _read_map, _map, _number, _count, _shape, MAX_INPUTS, MAX_OUTPUTS
from ..transaction import output
from ..chain import RawTransaction
from .sp_psbt import eligible_keys, validate_fields
from .dleq import verify


@dataclass(repr=False)
class Document:
    global_map: dict
    inputs: list
    outputs: list

    @classmethod
    def decode(cls, raw):
        r = Reader(raw)
        if r.take(5) != b"psbt\xff":
            raise ValueError("PSBT_MAGIC")
        g = _read_map(r)
        _shape(g, {0, 2, 3, 4, 5, 6, 0xFB})
        if _number(g, b"\xfb", default=0) != 2 or b"\x00" in g:
            raise ValueError("PSBT_V2_REQUIRED")
        if _number(g, b"\x02", signed=True) < 2:
            raise ValueError("PSBT_TRANSACTION_VERSION")
        if b"\x04" not in g or b"\x05" not in g:
            raise ValueError("PSBT_COUNTS_REQUIRED")
        ni, no = _count(g[b"\x04"], MAX_INPUTS), _count(g[b"\x05"], MAX_OUTPUTS)
        ins = [_read_map(r) for _ in range(ni)]
        outs = [_read_map(r) for _ in range(no)]
        r.finish()
        return cls(g, ins, outs)

    def encode(self):
        return (
            b"psbt\xff"
            + _map(self.global_map)
            + b"".join(_map(m) for m in self.inputs + self.outputs)
        )

    def _transaction(self):
        ins = [dict(m) for m in self.inputs]
        outs = [dict(m) for m in self.outputs]
        for m in ins:
            if b"\x00" in m:
                previous = RawTransaction.parse(m[b"\x00"])
                index = _number(m, b"\x0f")
                if m.get(b"\x0e") != bytes.fromhex(previous.txid())[::-1] or index >= len(
                    previous.outputs
                ):
                    raise ValueError("PSBT_NONWITNESS_UTXO_MISMATCH")
                utxo = output(*previous.outputs[index])
                if b"\x01" in m and m[b"\x01"] != utxo:
                    raise ValueError("PSBT_UTXO_CONFLICT")
                m[b"\x01"] = utxo
        for m in outs:
            if b"\x04" not in m:
                if b"\x09" not in m:
                    raise ValueError("PSBT_OUTPUT_REQUIRED")
                m[b"\x04"] = b""  # private parse placeholder, never signable/exported
        raw = b"psbt\xff" + _map(self.global_map) + b"".join(_map(m) for m in ins + outs)
        return PSBT.decode(raw)

    def validate(self, checks=None, strict_inputs=True):
        checks = set(
            checks or ("structure", "input_eligibility", "ecdh_coverage", "output_scripts")
        )
        if not checks <= {"structure", "input_eligibility", "ecdh_coverage", "output_scripts"}:
            raise ValueError("PSBT_VALIDATION_STAGE")
        p = self._transaction()
        validate_fields(p)
        if not any(b"\x09" in m for m in self.outputs):
            return {"complete": True}
        if "structure" in checks:
            for m in self.outputs:
                if b"\x09" in m and b"\x04" in m and self.global_map.get(b"\x06") != b"\x00":
                    raise ValueError("SP_INPUTS_OUTPUTS_NOT_FROZEN")
        if "input_eligibility" in checks:
            for (_, script), m in zip(p.utxos, self.inputs):
                if (
                    4 <= len(script) <= 42
                    and 0x52 <= script[0] <= 0x60
                    and script[1] == len(script) - 2
                ):
                    raise ValueError("INELIGIBLE_TRANSACTION")
                if b"\x03" in m and _number(m, b"\x03") != 1:
                    raise ValueError("SP_SIGHASH_ALL_REQUIRED")
        if not checks & {"ecdh_coverage", "output_scripts"}:
            return {"complete": False}
        keys = eligible_keys(p, bind_prevout=strict_inputs)
        total = PublicKey.combine_keys([PublicKey(k) for k in keys if k]).format()
        minout = min(bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v in p.tx.inputs)
        h = scalar(tagged("BIP0352/Inputs", minout + total))
        groups = {}
        complete = True
        for m in self.outputs:
            if b"\x09" not in m:
                continue
            scan, spend = m[b"\x09"][:33], m[b"\x09"][33:]
            if scan not in groups:
                share = self.global_map.get(b"\x07" + scan)
                if share is not None and not verify(
                    total, scan, share, self.global_map.get(b"\x08" + scan)
                ):
                    raise ValueError("SP_DLEQ_INVALID")
                pieces = []
                covered = True
                for key, fields in zip(keys, self.inputs):
                    if key is None:
                        continue
                    item = fields.get(b"\x1d" + scan)
                    if item is None:
                        covered = False
                        continue
                    if not verify(key, scan, item, fields.get(b"\x1e" + scan)):
                        raise ValueError("SP_DLEQ_INVALID")
                    pieces.append(PublicKey(item))
                if share is None and covered:
                    share = PublicKey.combine_keys(pieces).format()
                groups[scan] = [PublicKey(share).multiply(ser(h)).format() if share else None, 0]
            shared, k = groups[scan]
            if k >= K_MAX:
                raise ValueError("RECIPIENT_LIMIT")
            if shared is None:
                if b"\x04" in m:
                    raise ValueError("SP_SHARE_COVERAGE")
                complete = False
            elif b"\x04" in m and "output_scripts" in checks:
                t = scalar(tagged("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")))
                if m[b"\x04"] != b"\x51\x20" + compressed(spend).add(ser(t)).format()[1:]:
                    raise ValueError("SP_OUTPUT_MISMATCH")
            if b"\x04" not in m:
                complete = False
            groups[scan][1] += 1
        return {"complete": complete, "inputs_bound": strict_inputs, "signable": False}

    def resolve(self):
        self.validate()
        p = self._transaction()
        keys = eligible_keys(p)
        total = PublicKey.combine_keys([PublicKey(k) for k in keys if k]).format()
        h = scalar(
            tagged(
                "BIP0352/Inputs",
                min(bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v in p.tx.inputs)
                + total,
            )
        )
        outs = [dict(m) for m in self.outputs]
        groups = {}
        for m in outs:
            if b"\x09" not in m:
                continue
            scan, spend = m[b"\x09"][:33], m[b"\x09"][33:]
            if scan not in groups:
                C = self.global_map.get(b"\x07" + scan)
                if C is None:
                    shares = [
                        fields.get(b"\x1d" + scan) for key, fields in zip(keys, self.inputs) if key
                    ]
                    if not all(shares):
                        raise ValueError("SP_SHARE_COVERAGE")
                    C = PublicKey.combine_keys([PublicKey(x) for x in shares]).format()
                groups[scan] = [PublicKey(C).multiply(ser(h)).format(), 0]
            shared, k = groups[scan]
            t = scalar(tagged("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")))
            m[b"\x04"] = b"\x51\x20" + compressed(spend).add(ser(t)).format()[1:]
            groups[scan][1] += 1
        g = dict(self.global_map)
        g[b"\x06"] = b"\x00"
        result = Document(g, [dict(m) for m in self.inputs], outs)
        result.validate()
        return result
