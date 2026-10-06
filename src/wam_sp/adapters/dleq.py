"""BIP374 v0.3.0, pinned in adapters.BIPS_REVISION; secp256k1 only."""

import secrets
from coincurve import PublicKey
from ..core import N, pub, ser, scalar, tagged, compressed
from ..crypto import shared_point

G = pub(1)


def _message(message):
    if message is None:
        return b""
    if not isinstance(message, bytes) or len(message) != 32:
        raise ValueError("DLEQ_MESSAGE")
    return message


def _difference(s, p, e, q):
    points = []
    if s:
        points.append(compressed(p).multiply(ser(s)))
    if e:
        v = compressed(q).multiply(ser(e)).format()
        points.append(PublicKey(bytes([v[0] ^ 1]) + v[1:]))
    if not points:
        raise ValueError("DLEQ_INFINITY")
    return PublicKey.combine_keys(points).format()


def verify(A, B, C, proof, message=None, generator=G):
    try:
        m = _message(message)
        for p in (A, B, C, generator):
            compressed(p)
        if not isinstance(proof, bytes) or len(proof) != 64:
            return False
        e, s = int.from_bytes(proof[:32], "big"), int.from_bytes(proof[32:], "big")
        if e >= N or s >= N:
            return False
        r1, r2 = _difference(s, generator, e, A), _difference(s, B, e, C)
        return (
            e
            == int.from_bytes(
                tagged("BIP0374/challenge", A + B + C + generator + r1 + r2 + m), "big"
            )
            % N
        )
    except (ValueError, TypeError, OverflowError):
        return False


def prove(secret, B, auxiliary=None, message=None, generator=G):
    from ..crypto import secret_product, secret_sum

    a = ser(secret)
    B = compressed(B).format()
    auxiliary = secrets.token_bytes(32) if auxiliary is None else auxiliary
    if not isinstance(auxiliary, bytes) or len(auxiliary) != 32:
        raise ValueError("DLEQ_AUXILIARY")
    m = _message(message)
    generator = compressed(generator).format()
    A, C = shared_point(a, generator), shared_point(a, B)
    t = bytes(x ^ y for x, y in zip(a, tagged("BIP0374/aux", auxiliary)))
    k = scalar(int.from_bytes(tagged("BIP0374/nonce", t + A + C + m), "big") % N)
    r1, r2 = shared_point(ser(k), generator), shared_point(ser(k), B)
    e = int.from_bytes(tagged("BIP0374/challenge", A + B + C + generator + r1 + r2 + m), "big") % N
    if e:
        try:
            s = secret_sum(ser(k), secret_product(a, ser(e)))
        except ValueError:  # native scalar sum equal to zero is valid in a proof
            s = bytes(32)
    else:
        s = ser(k)
    proof = e.to_bytes(32, "big") + s
    if not verify(A, B, C, proof, message, generator):
        raise ValueError("DLEQ_SELF_CHECK")
    return C, proof
