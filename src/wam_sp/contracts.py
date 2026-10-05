"""Stable capability/data contracts for the node-scanner-wallet boundary.

These types do not grant new authority. ScanCapability is the existing
ScanAccount type; it is named here to make the security role explicit without
duplicating key material or derivation logic.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, TypeAlias, Any

from .keystore import ScanAccount

ScanCapability: TypeAlias = ScanAccount

_HASH = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True, repr=False)
class ScannerStatus:
    """Process-local scanner readiness bound to one durable chain tip."""

    height: int
    tip: str
    ready: bool
    mempool_ready: bool
    accounts: int

    def __post_init__(self):
        if (
            type(self.height) is not int
            or self.height < 0
            or not isinstance(self.tip, str)
            or _HASH.fullmatch(self.tip) is None
            or type(self.ready) is not bool
            or type(self.mempool_ready) is not bool
            or type(self.accounts) is not int
            or self.accounts < 1
        ):
            raise ValueError("SCANNER_STATUS")


@dataclass(frozen=True, slots=True, repr=False)
class MatchedOutput:
    """Sensitive scan result. It is metadata, not spend authority."""

    txid: str
    vout: int
    account_id: str
    epoch: int
    atoms: int
    public_key: str
    tweak: str
    label: int | None
    k: int
    received: int
    spent: int | None

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "MatchedOutput":
        item = cls(
            txid=row["txid"],
            vout=row["vout"],
            account_id=row["account"],
            epoch=row["epoch"],
            atoms=row["atoms"],
            public_key=row["public_key"],
            tweak=row["tweak"],
            label=row["label"],
            k=row["k"],
            received=row["received"],
            spent=row["spent"],
        )
        item.validate()
        return item

    def validate(self) -> None:
        if (
            not isinstance(self.txid, str)
            or _HASH.fullmatch(self.txid) is None
            or type(self.vout) is not int
            or not 0 <= self.vout < 2**32
            or not isinstance(self.account_id, str)
            or _HASH.fullmatch(self.account_id) is None
            or type(self.epoch) is not int
            or not 0 <= self.epoch < 2**31
            or type(self.atoms) is not int
            or not 0 <= self.atoms <= 22_000_000 * 100_000_000
            or not isinstance(self.public_key, str)
            or _HASH.fullmatch(self.public_key) is None
            or not isinstance(self.tweak, str)
            or _HASH.fullmatch(self.tweak) is None
            or self.label is not None
            and (type(self.label) is not int or not 0 <= self.label < 2**32)
            or type(self.k) is not int
            or not 0 <= self.k < 2323
            or type(self.received) is not int
            or self.received < 1
            or self.spent is not None
            and (type(self.spent) is not int or self.spent < self.received)
        ):
            raise ValueError("MATCHED_OUTPUT")
