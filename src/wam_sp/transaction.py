"""Small demo-only serializer: one input, SIGHASH_ALL (v0) / DEFAULT (v1)."""

from hashlib import sha256
from coincurve import PrivateKey
from .core import hash160, pub, ser, tagged


def compact(n):
    if type(n) is not int or not 0 <= n < 2**64:
        raise ValueError("INVALID_LENGTH")
    return (
        bytes([n])
        if n < 253
        else (
            b"\xfd" + n.to_bytes(2, "little")
            if n <= 65535
            else b"\xfe" + n.to_bytes(4, "little")
            if n <= 2**32 - 1
            else b"\xff" + n.to_bytes(8, "little")
        )
    )


def blob(data):
    return compact(len(data)) + data


def output(value, script):
    if type(value) is not int or not 0 <= value <= 22_000_000 * 100_000_000:
        raise ValueError("INVALID_AMOUNT")
    return value.to_bytes(8, "little") + blob(script)


def p2wpkh(secret):
    return b"\x00\x14" + hash160(pub(secret))


def signed_single_input(txin, amount, outputs, secret, taproot=False):
    """No coin selection, retries, remote signing, TapTweak, or mainnet RPC."""
    output(amount, txin.script)
    if not outputs or sum(v for v, _ in outputs) >= amount:
        raise ValueError("INVALID_FEE")
    encoded = b"".join(output(v, s) for v, s in outputs)
    outpoint = txin.outpoint()
    version, sequence, locktime = b"\x02\x00\x00\x00", b"\xfd\xff\xff\xff", bytes(4)

    def digest(x):
        return sha256(x).digest()

    def double(x):
        return digest(digest(x))

    if taproot:
        if txin.script != b"\x51\x20" + pub(secret)[1:]:
            raise ValueError("INPUT_KEY_MISMATCH")
        sighash = tagged(
            "TapSighash",
            b"\x00\x00"
            + version
            + locktime
            + digest(outpoint)
            + digest(amount.to_bytes(8, "little"))
            + digest(blob(txin.script))
            + digest(sequence)
            + digest(encoded)
            + b"\x00"
            + bytes(4),
        )
        witness = [PrivateKey(ser(secret)).sign_schnorr(sighash)]
    else:
        if txin.script != p2wpkh(secret):
            raise ValueError("INPUT_KEY_MISMATCH")
        scriptcode = b"\x76\xa9\x14" + hash160(pub(secret)) + b"\x88\xac"
        sighash = double(
            version
            + double(outpoint)
            + double(sequence)
            + outpoint
            + blob(scriptcode)
            + amount.to_bytes(8, "little")
            + sequence
            + double(encoded)
            + locktime
            + b"\x01\x00\x00\x00"
        )
        witness = [PrivateKey(ser(secret)).sign(sighash, hasher=None) + b"\x01", pub(secret)]
    return (
        version
        + b"\x00\x01\x01"
        + outpoint
        + b"\x00"
        + sequence
        + compact(len(outputs))
        + encoded
        + compact(len(witness))
        + b"".join(blob(x) for x in witness)
        + locktime
    ).hex()
