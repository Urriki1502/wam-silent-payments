"""BIP32 private derivation with native secp256k1 scalar operations."""

import hmac
from dataclasses import dataclass
from coincurve import PrivateKey
from .core import N, hash160

HARDENED = 1 << 31


@dataclass(frozen=True, repr=False)
class ExtendedPrivate:
    secret: bytes
    chain_code: bytes

    @classmethod
    def master(cls, seed):
        if not isinstance(seed, bytes) or not 16 <= len(seed) <= 64:
            raise ValueError("HD_SEED")
        i = hmac.digest(b"Bitcoin seed", seed, "sha512")
        PrivateKey(i[:32])
        return cls(i[:32], i[32:])

    @property
    def public(self):
        return PrivateKey(self.secret).public_key.format()

    @property
    def fingerprint(self):
        return hash160(self.public)[:4]

    def child(self, index):
        if type(index) is not int or not 0 <= index < 2**32:
            raise ValueError("HD_INDEX")
        data = (b"\x00" + self.secret if index & HARDENED else self.public) + index.to_bytes(
            4, "big"
        )
        i = hmac.digest(self.chain_code, data, "sha512")
        if int.from_bytes(i[:32], "big") >= N:
            raise ValueError("HD_INVALID_CHILD_RETRY_NEXT_INDEX")
        try:
            key = PrivateKey(self.secret).add(i[:32]).secret
        except ValueError:
            raise ValueError("HD_INVALID_CHILD_RETRY_NEXT_INDEX") from None
        return ExtendedPrivate(key, i[32:])

    def derive(self, path):
        if len(path) > 255:
            raise ValueError("HD_DEPTH")
        node = self
        for index in path:
            node = node.child(index)
        return node


def silent_key(seed, account, role, coin_type=1):
    if type(account) is not int or not 0 <= account < HARDENED or role not in ("scan", "spend"):
        raise ValueError("HD_ACCOUNT")
    if type(coin_type) is not int or not 0 <= coin_type < HARDENED:
        raise ValueError("HD_COIN_TYPE")
    path = (
        352 | HARDENED,
        coin_type | HARDENED,
        account | HARDENED,
        (1 if role == "scan" else 0) | HARDENED,
        0,
    )
    return int.from_bytes(ExtendedPrivate.master(seed).derive(path).secret, "big")
