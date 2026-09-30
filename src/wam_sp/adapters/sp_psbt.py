"""Pinned BIP375/BIP376 map adapter; no draft fields in persistent state."""

from dataclasses import replace
from coincurve import PublicKey, PrivateKey
from ..core import N, compressed, pub, ser, hash160, tagged, scalar, K_MAX, NUMS
from .dleq import verify, prove


def validate_fields(psbt):
    g, ins, outs = psbt.maps()
    for fields, share_type, proof_type in [(g, 7, 8), *((m, 0x1D, 0x1E) for m in ins)]:
        for k, v in fields.items():
            if k[0] in (share_type, proof_type):
                if psbt.version != 2 or len(k) != 34:
                    raise ValueError("SP_FIELD_VERSION_OR_KEY")
                compressed(k[1:])
                if k[0] == share_type:
                    compressed(v)
                    if bytes([proof_type]) + k[1:] not in fields:
                        raise ValueError("SP_PROOF_REQUIRED")
                elif len(v) != 64 or bytes([share_type]) + k[1:] not in fields:
                    raise ValueError("SP_SHARE_REQUIRED")
    for m in ins:
        for k, v in m.items():
            if k[0] == 0x1F:
                if psbt.version != 2 or len(k) != 34 or len(v) < 4 or len(v) % 4:
                    raise ValueError("SP_KEY_ORIGIN")
                compressed(k[1:])
            if k[0] == 0x20:
                if (
                    psbt.version != 2
                    or k != b"\x20"
                    or len(v) != 32
                    or int.from_bytes(v, "big") >= N
                ):
                    raise ValueError("SP_TWEAK")
    for m in outs:
        if b"\x09" in m:
            if psbt.version != 2 or len(m[b"\x09"]) != 66:
                raise ValueError("SP_OUTPUT_INFO")
            compressed(m[b"\x09"][:33])
            compressed(m[b"\x09"][33:])
        if b"\x0a" in m and (b"\x09" not in m or len(m[b"\x0a"]) != 4):
            raise ValueError("SP_OUTPUT_LABEL")


def eligible_keys(psbt, bind_prevout=True):
    result = []
    for (_, script), m in zip(psbt.utxos, psbt.input_extra or ({},) * len(psbt.utxos)):
        key = None
        if 4 <= len(script) <= 42 and 0x52 <= script[0] <= 0x60 and script[1] == len(script) - 2:
            raise ValueError("INELIGIBLE_TRANSACTION")
        if len(script) == 34 and script[:2] == b"\x51\x20":
            if bind_prevout and b"\x17" in m:
                internal = m[b"\x17"]
                merkle = m.get(b"\x18", b"")
                if len(internal) != 32 or len(merkle) not in (0, 32):
                    raise ValueError("TAPROOT_ORIGIN")
                tweak = tagged("TapTweak", internal + merkle)
                if (
                    int.from_bytes(tweak, "big") >= N
                    or compressed(b"\x02" + internal).add(tweak).format()[1:] != script[2:]
                ):
                    raise ValueError("TAPROOT_ORIGIN")
            if m.get(b"\x17") != NUMS:
                key = compressed(b"\x02" + script[2:]).format()
        else:
            if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
                redeem = m.get(b"\x04", b"")
                script = redeem if hash160(redeem) == script[2:22] else b""
            digest = (
                script[2:]
                if len(script) == 22 and script[:2] == b"\x00\x14"
                else script[3:23]
                if len(script) == 25
                and script[:3] == b"\x76\xa9\x14"
                and script[-2:] == b"\x88\xac"
                else None
            )
            if digest:
                candidates = [
                    k[1:]
                    for k in m
                    if k[0] == 6 and len(k) == 34 and (not bind_prevout or hash160(k[1:]) == digest)
                ]
                if len(candidates) != 1:
                    raise ValueError("SP_INPUT_PUBLIC_KEY_REQUIRED")
                key = compressed(candidates[0]).format()
        result.append(key)
    if not any(result):
        raise ValueError("NO_ELIGIBLE_INPUTS")
    return result


def verify_sender(psbt):
    validate_fields(psbt)
    g, ins, outs = psbt.maps()
    if not any(b"\x09" in m for m in outs):
        return
    if g.get(b"\x06", b"\x00") != b"\x00":
        raise ValueError("SP_INPUTS_OUTPUTS_NOT_FROZEN")
    keys = eligible_keys(psbt)
    total = PublicKey.combine_keys([PublicKey(k) for k in keys if k]).format()
    outpoints = [bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v in psbt.tx.inputs]
    h = scalar(tagged("BIP0352/Inputs", min(outpoints) + total))
    groups = {}
    for (_, script), m in zip(psbt.tx.outputs, outs):
        if b"\x09" not in m:
            continue
        scan, spend = m[b"\x09"][:33], m[b"\x09"][33:]
        if scan not in groups:
            if b"\x07" + scan in g:
                C = g[b"\x07" + scan]
                if not verify(total, scan, C, g[b"\x08" + scan]):
                    raise ValueError("SP_DLEQ_INVALID")
            else:
                shares = []
                for key, fields in zip(keys, ins):
                    if key:
                        C = fields.get(b"\x1d" + scan)
                        proof = fields.get(b"\x1e" + scan)
                        if C is None or proof is None or not verify(key, scan, C, proof):
                            raise ValueError("SP_DLEQ_INVALID")
                        shares.append(PublicKey(C))
                C = PublicKey.combine_keys(shares).format()
            groups[scan] = [PublicKey(C).multiply(ser(h)).format(), 0]
        shared, k = groups[scan]
        if k >= K_MAX:
            raise ValueError("RECIPIENT_LIMIT")
        t = scalar(tagged("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")))
        if script != b"\x51\x20" + PublicKey(spend).add(ser(t)).format()[1:]:
            raise ValueError("SP_OUTPUT_MISMATCH")
        groups[scan][1] += 1


def add_sender(psbt, keys, codes):
    from ..core import decode_address

    if psbt.version != 2 or len(keys) != len(psbt.utxos) or len(codes) != len(psbt.tx.outputs):
        raise ValueError("SP_ADAPTER_ARGUMENTS")
    outs = [dict(m) for m in (psbt.output_extra or ({},) * len(codes))]
    scans = set()
    for code, m in zip(codes, outs):
        if code is not None:
            scan, spend = decode_address(code)
            m[b"\x09"] = scan.format() + spend.format()
            scans.add(scan.format())
    ins = [dict(m) for m in (psbt.input_extra or ({},) * len(keys))]
    expected = eligible_keys(psbt)
    for key, pk, m in zip(keys, expected, ins):
        if pk is None or key is None:
            continue
        secret = key.secret
        if key.public_key.format()[1:] == pk[1:] and key.public_key.format() != pk:
            secret = (N - int.from_bytes(secret, "big")).to_bytes(32, "big")
        if pub(int.from_bytes(secret, "big")) != pk:
            raise ValueError("INPUT_KEY_MISMATCH")
        for scan in scans:
            share, proof = prove(int.from_bytes(secret, "big"), scan)
            m[b"\x1d" + scan] = share
            m[b"\x1e" + scan] = proof
        m[b"\x03"] = (1).to_bytes(4, "little")
    result = replace(psbt, input_extra=tuple(ins), output_extra=tuple(outs))
    verify_sender(result)
    return result


def add_spend(psbt, coins, accounts):
    lookup = {a.epoch: a for a in accounts}
    ins = [dict(m) for m in (psbt.input_extra or ({},) * len(psbt.utxos))]
    for coin, m in zip(coins, ins):
        m[b"\x20"] = int(coin["tweak"], 16).to_bytes(32, "big")
        m[b"\x1f" + lookup[coin["epoch"]].spend_public] = bytes(4)
    result = replace(psbt, input_extra=tuple(ins))
    validate_fields(result)
    return result


def sign_spend(psbt, spend_keys):
    validate_fields(psbt)
    keys = []
    for m, (_, script) in zip(psbt.input_extra, psbt.utxos):
        bases = [k[1:] for k in m if k[0] == 0x1F and k[1:] in spend_keys]
        if not bases:
            keys.append(None)
            continue
        if len(bases) != 1 or b"\x20" not in m:
            raise ValueError("SP_SPEND_KEY")
        key = PrivateKey(ser(spend_keys[bases[0]])).add(m[b"\x20"])
        if key.public_key.format()[1:] != script[2:]:
            raise ValueError("SP_TWEAK_MISMATCH")
        keys.append(key)
    return psbt.sign(keys)


def core_v0_export(psbt):
    """Verified final transaction handoff to WAM Core v0.1.11's PSBTv0 parser.

    The explicit adapter removes completed SP derivation metadata for privacy. No
    other unknown fields are discarded. This is not a roundtrip storage format.
    """
    psbt.finalize()
    g = {k: v for k, v in psbt.global_extra.items() if k[0] not in (6, 7, 8)}
    ins = tuple(
        {k: v for k, v in m.items() if k[0] not in (0x11, 0x12, 0x1D, 0x1E, 0x1F, 0x20)}
        for m in (psbt.input_extra or ({},) * len(psbt.utxos))
    )
    outs = tuple(
        {k: v for k, v in m.items() if k[0] not in (9, 10)}
        for m in (psbt.output_extra or ({},) * len(psbt.tx.outputs))
    )
    return replace(psbt, version=0, global_extra=g, input_extra=ins, output_extra=outs)
