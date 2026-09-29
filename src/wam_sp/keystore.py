"""Versioned, network-bound deterministic research keys and authenticated backups."""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from .core import N, pub, address, scalar, compressed
from .watcher import GENESIS

MAGIC = b"WAMSP02\x00"
MAX_BACKUP = 32 * 1024 * 1024
AAD = MAGIC + bytes.fromhex(GENESIS)


def _key(password, salt):
    if not isinstance(password, bytes) or not 12 <= len(password) <= 1024:
        raise ValueError("PASSPHRASE_LENGTH")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)


def seal(payload, password, purpose):
    if not isinstance(payload, bytes) or len(payload) > MAX_BACKUP:
        raise ValueError("BACKUP_LIMIT")
    if purpose not in (b"keys", b"scan", b"checkpoint", b"intent", b"recovery"):
        raise ValueError("BACKUP_PURPOSE")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    return (
        MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, payload, AAD + purpose)
    )


def unseal(envelope, password, purpose):
    if (
        not isinstance(envelope, bytes)
        or not 52 <= len(envelope) <= MAX_BACKUP + 52
        or envelope[:8] != MAGIC
    ):
        raise ValueError("BACKUP_FORMAT")
    if purpose not in (b"keys", b"scan", b"checkpoint", b"intent", b"recovery"):
        raise ValueError("BACKUP_PURPOSE")
    try:
        return AESGCM(_key(password, envelope[8:24])).decrypt(
            envelope[24:36], envelope[36:], AAD + purpose
        )
    except InvalidTag:
        raise ValueError("BACKUP_AUTHENTICATION") from None


def derive(seed, epoch, role):
    if (
        len(seed) != 32
        or type(epoch) is not int
        or not 0 <= epoch < 2**31
        or role not in ("scan", "spend")
    ):
        raise ValueError("KEY_DERIVATION")
    # Custom experimental hierarchy, NOT BIP32/BIP39-compatible.
    domain = b"WAM-SP-v2/" + bytes.fromhex(GENESIS) + epoch.to_bytes(4, "big") + role.encode()
    for counter in range(256):
        d = int.from_bytes(hmac.digest(seed, domain + bytes([counter]), "sha256"), "big")
        if 0 < d < N:
            return d
    raise ValueError("KEY_DERIVATION")


@dataclass(frozen=True, repr=False)
class ScanAccount:
    epoch: int
    scan_secret: int
    spend_public: bytes
    birthday: int = 1
    labels: tuple[int, ...] = ()

    def __post_init__(self):
        scalar(self.scan_secret)
        compressed(self.spend_public)
        if (
            type(self.epoch) is not int
            or not 0 <= self.epoch < 2**31
            or type(self.birthday) is not int
            or not 1 <= self.birthday < 2**31
        ):
            raise ValueError("ACCOUNT_METADATA")
        if (
            len(self.labels) > 1000
            or len(set(self.labels)) != len(self.labels)
            or any(type(m) is not int or not 1 <= m < 2**32 for m in self.labels)
        ):
            raise ValueError("ACCOUNT_LABELS")

    @property
    def account_id(self):
        return hashlib.sha256(
            bytes.fromhex(GENESIS) + pub(self.scan_secret) + self.spend_public
        ).hexdigest()

    def identity(self):
        return {
            "id": self.account_id,
            "epoch": self.epoch,
            "scan_public": pub(self.scan_secret).hex(),
            "spend_public": self.spend_public.hex(),
            "birthday": self.birthday,
            "labels": list(self.labels),
        }

    def payment_code(self, label=None):
        if label == 0:
            raise ValueError("CHANGE_LABEL_PRIVATE")
        if label is not None and label not in self.labels:
            raise ValueError("UNREGISTERED_LABEL")
        return address(self.scan_secret, self.spend_public, label)


class Keyring:
    """Offline role. Scanner must receive accounts(), never this seed-bearing object."""

    def __init__(self, seed=None, epochs=None, algorithm="bip32-352-testnet"):
        if algorithm not in ("legacy-v2", "bip32-352-testnet"):
            raise ValueError("KEY_ALGORITHM")
        self.algorithm = algorithm
        self._closed = False
        self._seed = secrets.token_bytes(32) if seed is None else seed
        if not isinstance(self._seed, bytes) or len(self._seed) != 32:
            raise ValueError("SEED_LENGTH")
        self._seed = bytearray(self._seed)
        self._epochs = {0: {"birthday": 1, "labels": []}} if epochs is None else epochs
        if not self._epochs or len(self._epochs) > 16:
            raise ValueError("EPOCH_LIMIT")
        for e, meta in self._epochs.items():
            self._derive(e, "scan")
            if (
                set(meta) != {"birthday", "labels"}
                or type(meta["birthday"]) is not int
                or not 1 <= meta["birthday"] < 2**31
            ):
                raise ValueError("KEY_METADATA")
            if len(meta["labels"]) > 1000 or len(set(meta["labels"])) != len(meta["labels"]):
                raise ValueError("LABEL_LIMIT")
            if any(type(m) is not int or not 1 <= m < 2**32 for m in meta["labels"]):
                raise ValueError("KEY_METADATA")

    def close(self):
        # Best effort only: native/interpreter temporary copies may remain.
        self._seed[:] = bytes(len(self._seed))
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _derive(self, epoch, role):
        if self._closed:
            raise ValueError("KEYRING_CLOSED")
        if self.algorithm == "legacy-v2":
            return derive(self._seed, epoch, role)
        from .hd import silent_key

        return silent_key(bytes(self._seed), epoch, role)

    def spend_secret(self, epoch):
        if epoch not in self._epochs:
            raise ValueError("UNKNOWN_EPOCH")
        return self._derive(epoch, "spend")

    def accounts(self):
        return tuple(
            ScanAccount(
                e,
                self._derive(e, "scan"),
                pub(self.spend_secret(e)),
                m["birthday"],
                tuple(m["labels"]),
            )
            for e, m in sorted(self._epochs.items())
        )

    def add_label(self, epoch, label):
        if epoch not in self._epochs or type(label) is not int or not 1 <= label < 2**32:
            raise ValueError("INVALID_LABEL")
        labels = self._epochs[epoch]["labels"]
        if label not in labels:
            if len(labels) >= 1000:
                raise ValueError("LABEL_LIMIT")
            labels.append(label)

    def rotate(self, birthday):
        if len(self._epochs) >= 16 or type(birthday) is not int or not 1 <= birthday < 2**31:
            raise ValueError("ROTATION_LIMIT")
        e = max(self._epochs) + 1
        self._epochs[e] = {"birthday": birthday, "labels": []}
        return self.accounts()[-1]

    def backup(self, password):
        if self._closed:
            raise ValueError("KEYRING_CLOSED")
        payload = {
            "version": 3,
            "profile": "WSP-1",
            "algorithm": self.algorithm,
            "network": GENESIS,
            "seed": self._seed.hex(),
            "epochs": {str(e): m for e, m in self._epochs.items()},
        }
        return seal(json.dumps(payload, separators=(",", ":")).encode(), password, b"keys")

    @classmethod
    def restore(cls, encrypted, password):
        try:
            data = json.loads(unseal(encrypted, password, b"keys"))
            version = data.get("version")
            fields = (
                {"version", "network", "seed", "epochs"}
                if version == 2
                else {"version", "profile", "algorithm", "network", "seed", "epochs"}
            )
            if (
                set(data) != fields
                or version not in (2, 3)
                or data["network"] != GENESIS
                or (version == 3 and data["profile"] != "WSP-1")
            ):
                raise ValueError
            return cls(
                bytes.fromhex(data["seed"]),
                {int(e): m for e, m in data["epochs"].items()},
                "legacy-v2" if version == 2 else data["algorithm"],
            )
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            raise ValueError("BACKUP_RESTORE") from None


def export_scan(accounts, password):
    data = [
        {"identity": a.identity(), "scan_secret": format(a.scan_secret, "064x")} for a in accounts
    ]
    return seal(json.dumps(data, separators=(",", ":")).encode(), password, b"scan")


def import_scan(encrypted, password):
    try:
        data = json.loads(unseal(encrypted, password, b"scan"))
        if not isinstance(data, list) or not 1 <= len(data) <= 16:
            raise ValueError
        result = []
        for d in data:
            i = d["identity"]
            a = ScanAccount(
                i["epoch"],
                scalar(int(d["scan_secret"], 16)),
                bytes.fromhex(i["spend_public"]),
                i["birthday"],
                tuple(i["labels"]),
            )
            if a.identity() != i:
                raise ValueError
            result.append(a)
        return tuple(result)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("SCAN_BACKUP_RESTORE") from None


def save_private(path, envelope):
    """Create a new encrypted backup with private permissions; never overwrite silently."""
    import os
    from pathlib import Path

    path = Path(path)
    if (
        not isinstance(envelope, bytes)
        or not 52 <= len(envelope) <= MAX_BACKUP + 52
        or envelope[:8] != MAGIC
    ):
        raise ValueError("BACKUP_FORMAT")
    if path.parent.is_symlink() or (os.name == "posix" and path.parent.stat().st_mode & 0o077):
        raise ValueError("PRIVATE_DIRECTORY_REQUIRED")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(envelope)
        stream.flush()
        os.fsync(stream.fileno())


def load_private(path):
    import os
    import stat

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or (os.name == "posix" and st.st_mode & 0o077)
            or st.st_size > MAX_BACKUP + 52
        ):
            raise ValueError("UNSAFE_BACKUP_FILE")
        return stream.read(MAX_BACKUP + 53)
