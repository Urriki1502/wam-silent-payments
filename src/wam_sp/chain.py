"""Bounded consensus-format transaction decoder; validation remains the node's job."""

from dataclasses import dataclass
from hashlib import sha256
from .transaction import compact, blob, output
from .limits import DEFAULT


@dataclass(frozen=True, repr=False)
class RawInput:
    txid: str
    vout: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...] = ()


@dataclass(frozen=True, repr=False)
class RawTransaction:
    version: int
    inputs: tuple[RawInput, ...]
    outputs: tuple[tuple[int, bytes], ...]
    locktime: int
    segwit: bool = False

    def serialize(self, include_witness=True):
        witness = include_witness and self.segwit
        raw = (
            self.version.to_bytes(4, "little", signed=True)
            + (b"\x00\x01" if witness else b"")
            + compact(len(self.inputs))
        )
        for i in self.inputs:
            raw += (
                bytes.fromhex(i.txid)[::-1]
                + i.vout.to_bytes(4, "little")
                + blob(i.script_sig)
                + i.sequence.to_bytes(4, "little")
            )
        raw += compact(len(self.outputs)) + b"".join(output(v, s) for v, s in self.outputs)
        if witness:
            raw += b"".join(
                compact(len(i.witness)) + b"".join(blob(w) for w in i.witness) for i in self.inputs
            )
        return raw + self.locktime.to_bytes(4, "little")

    def txid(self):
        raw = self.serialize(False)
        return sha256(sha256(raw).digest()).digest()[::-1].hex()

    @classmethod
    def parse(cls, data):
        from .psbt import Reader
        from dataclasses import replace

        r = Reader(data)
        version = int.from_bytes(r.take(4), "little", signed=True)
        ni = r.size(DEFAULT.max_inputs)
        segwit = False
        if ni == 0:
            if r.take(1) != b"\x01":
                raise ValueError("WITNESS_FLAG")
            segwit = True
            ni = r.size(DEFAULT.max_inputs)
        if ni == 0:
            raise ValueError("TRANSACTION_EMPTY")
        inputs = []
        seen = set()
        for _ in range(ni):
            i = RawInput(
                r.take(32)[::-1].hex(),
                int.from_bytes(r.take(4), "little"),
                r.blob(DEFAULT.max_script),
                int.from_bytes(r.take(4), "little"),
            )
            if (i.txid, i.vout) in seen:
                raise ValueError("DUPLICATE_INPUT")
            seen.add((i.txid, i.vout))
            inputs.append(i)
        outputs = []
        for _ in range(r.size(DEFAULT.max_outputs)):
            value = int.from_bytes(r.take(8), "little")
            script = r.blob(DEFAULT.max_script)
            output(value, script)
            outputs.append((value, script))
        if not outputs or sum(v for v, _ in outputs) > 22_000_000 * 100_000_000:
            raise ValueError("TRANSACTION_AMOUNT_OR_EMPTY")
        if segwit:
            for index, i in enumerate(inputs):
                witness = tuple(
                    r.blob(DEFAULT.max_transaction_bytes)
                    for _ in range(r.size(DEFAULT.max_witness_items))
                )
                inputs[index] = replace(i, witness=witness)
            if not any(i.witness for i in inputs):
                raise ValueError("SUPERFLUOUS_WITNESS")
        locktime = int.from_bytes(r.take(4), "little")
        r.finish()
        result = cls(version, tuple(inputs), tuple(outputs), locktime, segwit)
        if result.serialize() != data:
            raise ValueError("NONCANONICAL_TRANSACTION")
        return result
