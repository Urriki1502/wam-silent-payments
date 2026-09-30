"""Native libsecp256k1 secret multiplication; no Python elliptic-curve code.

The ECDH callback only serializes the native result. Python memory lifetime and
control flow are not claimed constant-time or securely zeroized.
"""

from coincurve import PrivateKey, PublicKey
from coincurve._libsecp256k1 import ffi, lib
from coincurve.context import GLOBAL_CONTEXT


@ffi.callback("int(unsigned char *, unsigned char *, unsigned char *, void *)")
def _compressed_result(out, x, y, data):
    out[0] = 2 | (y[31] & 1)
    ffi.memmove(out + 1, x, 32)
    return 1


def shared_point(secret, point):
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("INVALID_SCALAR")
    key = PublicKey(point)
    out = ffi.new("unsigned char[33]")
    if not lib.secp256k1_ecdh(
        GLOBAL_CONTEXT.ctx, out, key.public_key, secret, _compressed_result, ffi.NULL
    ):
        raise ValueError("ECDH_FAILED")
    return bytes(ffi.buffer(out, 33))


def secret_product(a, b):
    return PrivateKey(a).multiply(b).secret


def secret_sum(a, b):
    return PrivateKey(a).add(b).secret
