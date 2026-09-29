"""Allowlisted structured operational events; no free-form text/debug escape."""

import json

EVENTS = frozenset(
    {
        "scan_complete",
        "scan_failed",
        "reorg_detected",
        "rpc_failure",
        "database_corruption",
        "chain_mismatch",
        "stale_checkpoint",
        "incompatible_schema",
        "incompatible_profile",
        "backup_complete",
    }
)
FIELDS = frozenset(
    {
        "height",
        "behind",
        "blocks",
        "transactions",
        "rollback",
        "duration_ms",
        "schema",
        "api_version",
    }
)


class RedactedLog:
    def __init__(self, stream, debug=False):
        self.stream = stream
        self.debug = bool(debug)  # enables counters only, never secrets or transaction identifiers

    def emit(self, event, **values):
        if event not in EVENTS or any(k not in FIELDS for k in values):
            raise ValueError("LOG_FIELD_DENIED")
        if any(type(v) is not int or not 0 <= v < 2**63 for v in values.values()):
            raise ValueError("LOG_VALUE_DENIED")
        data = {"event": event}
        if self.debug:
            data.update(values)
        self.stream.write(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
        self.stream.flush()
