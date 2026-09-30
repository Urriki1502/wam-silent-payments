"""Versioned internal scan descriptor; wire descriptor drafts live in adapters."""

from dataclasses import dataclass
from .keystore import ScanAccount
from .watcher import GENESIS


@dataclass(frozen=True, repr=False)
class Descriptor:
    account: ScanAccount
    network: str = GENESIS
    version: int = 1
    origin: str | None = None

    def __post_init__(self):
        if self.network != GENESIS or self.version != 1:
            raise ValueError("DESCRIPTOR_NETWORK_OR_VERSION")
        if self.origin is not None:
            from .adapters.descriptor import validate_origin

            validate_origin(self.origin)

    def record(self):
        return {
            "version": self.version,
            "profile": "WSP-1",
            "network": self.network,
            "identity": self.account.identity(),
            "scan_secret": format(self.account.scan_secret, "064x"),
            "origin": self.origin,
        }

    @classmethod
    def from_record(cls, record):
        if (
            not isinstance(record, dict)
            or set(record) != {"version", "profile", "network", "identity", "scan_secret", "origin"}
            or record["profile"] != "WSP-1"
        ):
            raise ValueError("DESCRIPTOR_RECORD")
        try:
            i = record["identity"]
            a = ScanAccount(
                i["epoch"],
                int(record["scan_secret"], 16),
                bytes.fromhex(i["spend_public"]),
                i["birthday"],
                tuple(i["labels"]),
            )
            if a.identity() != i:
                raise ValueError
            return cls(a, record["network"], record["version"], record["origin"])
        except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
            raise ValueError("DESCRIPTOR_RECORD") from None
