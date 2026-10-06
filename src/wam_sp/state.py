"""Bounded storage transport decoder, separate from SQLite commit validation."""

import json
from .backup import unique


def decode_checkpoint(raw, expected_identity):
    from .store import TABLES, LEGACY_TABLES

    if not isinstance(raw, bytes) or len(raw) > 32 * 1024 * 1024:
        raise ValueError("CHECKPOINT_LIMIT")
    try:
        data = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(data, dict) or data.get("identity") != expected_identity:
            raise ValueError
        legacy = "schema" not in data
        if set(data) != ({"identity", "tables"} if legacy else {"schema", "identity", "tables"}):
            raise ValueError
        tables = LEGACY_TABLES if legacy else TABLES
        if (
            not legacy
            and data["schema"] != 3
            or not isinstance(data["tables"], dict)
            or set(data["tables"]) != set(tables)
        ):
            raise ValueError
        for table, width in tables.items():
            rows = data["tables"][table]
            if (
                not isinstance(rows, list)
                or len(rows) > 200000
                or any(not isinstance(r, list) or len(r) != width for r in rows)
            ):
                raise ValueError
        return data
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("CHECKPOINT_FORMAT") from None
