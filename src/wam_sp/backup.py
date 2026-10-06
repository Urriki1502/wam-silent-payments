"""WSP-1 recovery bundle v1: authenticated keys, descriptors and local metadata.

Chain state is reconstructed from a validating node, not trusted from backup.
"""

import base64
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from .keystore import Keyring, seal, unseal
from .descriptors import Descriptor
from .watcher import GENESIS
from .store import SCHEMA_VERSION, TABLES

LOCAL_TABLES = ("contacts", "reservations", "labels", "intents", "outbox")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def parse_document(raw):
    if not isinstance(raw, bytes) or len(raw) > 32 * 1024 * 1024:
        raise ValueError("RECOVERY_LIMIT")
    try:
        data = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")),
        )
        if not isinstance(data, dict) or set(data) != {"payload", "checksum"}:
            raise ValueError
        body = data["payload"]
        if not isinstance(data["checksum"], str) or not hmac.compare_digest(
            hashlib.sha256(canonical(body)).hexdigest(), data["checksum"]
        ):
            raise ValueError
        if (
            set(body) != {"version", "profile", "network", "schema", "keys", "descriptors", "local"}
            or body["version"] != 1
            or body["profile"] != "WSP-1"
            or body["network"] != GENESIS
            or body["schema"] != SCHEMA_VERSION
        ):
            raise ValueError
        if (
            not isinstance(body["keys"], str)
            or len(body["keys"]) > 1000000
            or not isinstance(body["descriptors"], list)
            or not 1 <= len(body["descriptors"]) <= 16
        ):
            raise ValueError
        descriptors = tuple(Descriptor.from_record(x) for x in body["descriptors"])
        if len({x.account.account_id for x in descriptors}) != len(descriptors):
            raise ValueError
        if set(body["local"]) != set(LOCAL_TABLES):
            raise ValueError
        for table, rows in body["local"].items():
            if (
                not isinstance(rows, list)
                or len(rows) > 100000
                or any(not isinstance(r, list) or len(r) != TABLES[table] for r in rows)
            ):
                raise ValueError
        return body, descriptors
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        raise ValueError("RECOVERY_FORMAT_OR_CHECKSUM") from None


def create(keyring, scanner, password):
    # Labels can be allocated on a scan-only merchant host. Carry that metadata
    # into the offline seed bundle, without changing any derived private key.
    restored = Keyring.restore(keyring.backup(password), password)
    accounts = {a.account_id: a for a in restored.accounts()}
    for a in scanner.accounts:
        if a.account_id not in accounts or a.birthday != accounts[a.account_id].birthday:
            raise ValueError("RECOVERY_ACCOUNT_MISMATCH")
        for label in a.labels:
            restored.add_label(a.epoch, label)
    if restored.accounts() != scanner.accounts:
        raise ValueError("RECOVERY_ACCOUNT_MISMATCH")
    with scanner.store.transaction():
        scanner.store.validate()
        local = {
            t: [list(r) for r in scanner.store.db.execute("SELECT * FROM " + t)]
            for t in LOCAL_TABLES
        }
    payload = {
        "version": 1,
        "profile": "WSP-1",
        "network": GENESIS,
        "schema": SCHEMA_VERSION,
        "keys": base64.b64encode(restored.backup(password)).decode(),
        "descriptors": [Descriptor(a).record() for a in restored.accounts()],
        "local": local,
    }
    raw = canonical(
        {"payload": payload, "checksum": hashlib.sha256(canonical(payload)).hexdigest()}
    )
    parse_document(raw)
    return seal(raw, password, b"recovery")


def restore(envelope, password, path):
    from .scanner import Scanner

    if Path(path).exists():
        raise ValueError("RECOVERY_NEEDS_NEW_DATABASE")
    # Detect envelope purpose by authentication. Old keyring envelopes remain
    # recoverable, but they did not contain contacts/locks/invoice metadata.
    try:
        raw = unseal(envelope, password, b"recovery")
    except ValueError as exc:
        if str(exc) != "BACKUP_AUTHENTICATION":
            raise
        ring = Keyring.restore(envelope, password)
        return ring, Scanner(path, ring.accounts())
    body, descriptors = parse_document(raw)
    ring = Keyring.restore(base64.b64decode(body["keys"], validate=True), password)
    if ring.accounts() != tuple(d.account for d in descriptors):
        raise ValueError("RECOVERY_IDENTITY_MISMATCH")
    scanner = Scanner(path, ring.accounts())
    try:
        with scanner.store.transaction():
            for table, rows in body["local"].items():
                scanner.store.db.executemany(
                    "INSERT INTO " + table + " VALUES(" + ",".join("?" * TABLES[table]) + ")", rows
                )
            scanner.store.validate()
    except (ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        # Cleanup of our newly created failed restore, then propagate a fixed
        # failure. No backup contents or underlying SQL errors cross this API.
        scanner.close()
        Path(path).unlink(missing_ok=True)
        raise ValueError("RECOVERY_STATE_INVALID") from None
    return ring, scanner
