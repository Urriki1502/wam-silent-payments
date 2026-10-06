"""Public, bounded health counters; never wallet IDs, balances or keys."""

from ..profile import PROFILE, API_VERSION
from ..store import SCHEMA_VERSION

CODES = frozenset(
    {
        "SCANNER_BEHIND",
        "CHAIN_MISMATCH",
        "DATABASE_CORRUPTION",
        "REORG_DETECTED",
        "RPC_FAILURE",
        "STALE_CHECKPOINT",
        "INCOMPATIBLE_SCHEMA",
        "INCOMPATIBLE_WSP_VERSION",
    }
)


def health(scanner, node_height=None, last_error=None):
    height = scanner.store.tip()[0]
    signals = []
    if not scanner.ready:
        signals.append("STALE_CHECKPOINT")
    if node_height is not None:
        if type(node_height) is not int or node_height < 0:
            raise ValueError("HEALTH_HEIGHT")
        if height < node_height:
            signals.append("SCANNER_BEHIND")
    if scanner.metrics.rollback:
        signals.append("REORG_DETECTED")
    if last_error is not None:
        if last_error not in CODES:
            raise ValueError("HEALTH_ERROR_CODE")
        signals.append(last_error)
    return {
        "profile": PROFILE,
        "api_version": API_VERSION,
        "schema": SCHEMA_VERSION,
        "height": height,
        "behind": max(0, (node_height or height) - height),
        "signals": sorted(set(signals)),
    }
