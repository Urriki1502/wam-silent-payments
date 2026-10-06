"""Versioned SQLite, full synchronous commits, integrity and ownership validation."""

import json
import os
from pathlib import Path
import sqlite3
import threading
from .keystore import seal, unseal
from .watcher import GENESIS
from .errors import StorageError

SCHEMA_VERSION = 3
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,previous TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coins(txid TEXT,vout INTEGER,account TEXT,epoch INTEGER,atoms INTEGER,public_key TEXT,tweak TEXT,label INTEGER,k INTEGER,received INTEGER,spent INTEGER,PRIMARY KEY(txid,vout));
CREATE INDEX IF NOT EXISTS coins_account ON coins(account,spent);
CREATE INDEX IF NOT EXISTS coins_height ON coins(received,spent);
CREATE TABLE IF NOT EXISTS cache(txid TEXT PRIMARY KEY,point TEXT,height INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY,name TEXT NOT NULL,code TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reservations(txid TEXT,vout INTEGER,token TEXT,state TEXT,created INTEGER,PRIMARY KEY(txid,vout));
CREATE TABLE IF NOT EXISTS history(txid TEXT PRIMARY KEY,height INTEGER NOT NULL,credit INTEGER NOT NULL,debit INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mempool_coins(txid TEXT,vout INTEGER,account TEXT,epoch INTEGER,atoms INTEGER,public_key TEXT,tweak TEXT,label INTEGER,k INTEGER,PRIMARY KEY(txid,vout));
CREATE TABLE IF NOT EXISTS mempool_spends(txid TEXT,vout INTEGER,spending TEXT,PRIMARY KEY(txid,vout));
CREATE TABLE IF NOT EXISTS labels(account TEXT,label INTEGER,name TEXT NOT NULL,PRIMARY KEY(account,label));
CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY,account TEXT,label INTEGER,atoms INTEGER,confirmations INTEGER,expires INTEGER,status TEXT,credited INTEGER);
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,intent TEXT,event TEXT,payload TEXT,delivered INTEGER DEFAULT 0);
"""
TABLES = {
    "blocks": 3,
    "coins": 11,
    "cache": 3,
    "contacts": 3,
    "reservations": 5,
    "history": 4,
    "mempool_coins": 9,
    "mempool_spends": 3,
    "labels": 3,
    "intents": 8,
    "outbox": 5,
}
LEGACY_TABLES = {
    k: v for k, v in TABLES.items() if k in ("blocks", "coins", "cache", "contacts", "reservations")
}


class Store:
    def __init__(self, path, identity):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.closed = False
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise StorageError("UNSAFE_PATH")
        if os.name == "posix" and self.path.parent.stat().st_mode & 0o077:
            raise StorageError("PRIVATE_DIRECTORY_REQUIRED")
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        elif not self.path.is_file() or os.name == "posix" and self.path.stat().st_mode & 0o077:
            raise StorageError("PRIVATE_FILE_REQUIRED")
        if self.path.stat().st_size > 1024**3:
            raise StorageError("DATABASE_SIZE_LIMIT")
        self.identity = json.dumps(
            {"version": 2, "network": GENESIS, "accounts": identity},
            sort_keys=True,
            separators=(",", ":"),
        )
        self.db = sqlite3.connect(
            self.path, timeout=5, isolation_level=None, check_same_thread=False
        )
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA trusted_schema=OFF")
            if self.db.execute("PRAGMA quick_check").fetchall()[0][0] != "ok":
                raise StorageError("DATABASE_CORRUPTION")
            if self.db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')"
            ).fetchone()[0]:
                raise StorageError("DATABASE_UNEXPECTED_SCHEMA")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 2, 3):
                raise StorageError("INCOMPATIBLE_SCHEMA")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA max_page_count=262144")
            self.db.execute("PRAGMA cache_size=-4096")
            names = {
                r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            legacy = bool(names) and version in (0, 2)
            if names and not (set(LEGACY_TABLES) | {"meta"}) <= names:
                raise StorageError("DATABASE_UNEXPECTED_SCHEMA")
            if names - set(TABLES) - {"meta", "sqlite_sequence"}:
                raise StorageError("DATABASE_UNEXPECTED_SCHEMA")
            with self.transaction():
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        self.db.execute(statement)
                existing = self.db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
                if existing and existing[0] != self.identity:
                    raise StorageError("STATE_WALLET_MISMATCH_RESCAN_REQUIRED")
                profile = self.db.execute("SELECT value FROM meta WHERE key='profile'").fetchone()
                if profile and profile[0] != "WSP-1":
                    raise StorageError("INCOMPATIBLE_WSP_VERSION")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('identity',?)", (self.identity,))
                if legacy:
                    # v0.2 does not record spending txids. Rebuild history from the chain;
                    # preserve irreversible signing reservations and private address book.
                    for table in ("blocks", "coins", "history", "mempool_coins", "mempool_spends"):
                        self.db.execute("DELETE FROM " + table)
                    self.db.execute(
                        "INSERT OR REPLACE INTO meta VALUES('migration','v2-to-v3-rescan')"
                    )
                self.db.execute("PRAGMA user_version=3")
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('profile','WSP-1')")
            with self.transaction():
                self.validate()
        except StorageError:
            self.db.close()
            self.closed = True
            raise
        except (sqlite3.DatabaseError, ValueError, TypeError, KeyError):
            self.db.close()
            self.closed = True
            raise StorageError("DATABASE_CORRUPTION_OR_INCOMPATIBLE") from None

    def close(self):
        with self.lock:
            if not self.closed:
                self.db.close()
                self.closed = True

    def tip(self):
        row = self.db.execute(
            "SELECT height,hash FROM blocks ORDER BY height DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def transaction(self):
        return Atomic(self.db, self.lock)

    def validate(self):
        from .core import N, compressed
        from .core import decode_address
        import re

        def hashes(s):
            return isinstance(s, str) and re.fullmatch("[0-9a-f]{64}", s) is not None

        def integer(x, lo, hi):
            return type(x) is int and lo <= x <= hi

        def text(x, limit):
            return isinstance(x, str) and len(x) <= limit and not any(ord(c) < 32 for c in x)

        # Compare names, types, nullability and primary keys, not only row width.
        expected = sqlite3.connect(":memory:")
        try:
            expected.executescript(SCHEMA)
            for table in (*TABLES, "meta"):
                actual = [tuple(r) for r in self.db.execute("PRAGMA table_info(" + table + ")")]
                if actual != expected.execute("PRAGMA table_info(" + table + ")").fetchall():
                    raise StorageError("DATABASE_SCHEMA")
        finally:
            expected.close()
        previous = GENESIS
        for expected, row in enumerate(self.db.execute("SELECT * FROM blocks ORDER BY height"), 1):
            if row["height"] != expected or row["previous"] != previous or not hashes(row["hash"]):
                raise StorageError("DATABASE_CHAIN")
            previous = row["hash"]
        height = self.tip()[0]
        accounts = {a["id"]: a for a in json.loads(self.identity)["accounts"]}
        for row in self.db.execute(
            "SELECT *,received IS NOT NULL AS confirmed FROM coins UNION ALL SELECT *,NULL,NULL,0 FROM mempool_coins"
        ):
            if (
                not hashes(row["txid"])
                or type(row["vout"]) is not int
                or not 0 <= row["vout"] < 2**32
                or row["account"] not in accounts
            ):
                raise StorageError("DATABASE_COIN")
            a = accounts[row["account"]]
            if (
                row["epoch"] != a["epoch"]
                or type(row["atoms"]) is not int
                or not 0 <= row["atoms"] <= 22_000_000 * 100_000_000
            ):
                raise StorageError("DATABASE_COIN")
            if (
                not hashes(row["tweak"])
                or not hashes(row["public_key"])
                or not 0 <= int(row["tweak"], 16) < N
            ):
                raise StorageError("DATABASE_COIN")
            p = (
                compressed(bytes.fromhex(a["spend_public"]))
                .add(bytes.fromhex(row["tweak"]))
                .format()[1:]
                .hex()
            )
            if (
                p != row["public_key"]
                or row["label"] not in (None, 0, *a["labels"])
                or type(row["k"]) is not int
                or not 0 <= row["k"] < 2323
            ):
                raise StorageError("DATABASE_OWNERSHIP")
            if row["confirmed"] and (
                type(row["received"]) is not int
                or not 1 <= row["received"] <= height
                or row["spent"] is not None
                and not row["received"] <= row["spent"] <= height
            ):
                raise StorageError("DATABASE_HEIGHT")
        for r in self.db.execute("SELECT * FROM mempool_spends"):
            if (
                not hashes(r["txid"])
                or not hashes(r["spending"])
                or not integer(r["vout"], 0, 2**32 - 1)
            ):
                raise StorageError("DATABASE_MEMPOOL")
        for r in self.db.execute("SELECT * FROM reservations"):
            if (
                not hashes(r["txid"])
                or not integer(r["vout"], 0, 2**32 - 1)
                or r["state"] not in ("draft", "signed", "uncertain", "broadcast", "manual")
                or not text(r["token"], 128)
                or not r["token"]
                or not integer(r["created"], 0, 2**63 - 1)
            ):
                raise StorageError("DATABASE_RESERVATION")
        for r in self.db.execute("SELECT * FROM history"):
            if (
                not hashes(r["txid"])
                or not integer(r["height"], 1, height)
                or not all(integer(r[k], 0, 22_000_000 * 100_000_000) for k in ("credit", "debit"))
            ):
                raise StorageError("DATABASE_HISTORY")
        for r in self.db.execute("SELECT * FROM cache"):
            if not hashes(r["txid"]) or not integer(r["height"], 1, 2**31 - 1):
                raise StorageError("DATABASE_CACHE")
            if r["point"] is not None:
                compressed(bytes.fromhex(r["point"]))
        for r in self.db.execute("SELECT * FROM contacts"):
            if not text(r["id"], 128) or not text(r["name"], 128) or not text(r["code"], 256):
                raise StorageError("DATABASE_CONTACT")
            decode_address(r["code"])
        for r in self.db.execute("SELECT * FROM labels"):
            if (
                r["account"] not in accounts
                or r["label"] not in accounts[r["account"]]["labels"]
                or not text(r["name"], 128)
            ):
                raise StorageError("DATABASE_LABEL")
        for r in self.db.execute("SELECT * FROM intents"):
            if (
                not isinstance(r["id"], str)
                or not re.fullmatch("[0-9a-f]{32}", r["id"])
                or r["account"] not in accounts
                or r["label"] not in accounts[r["account"]]["labels"]
                or not integer(r["atoms"], 330, 22_000_000 * 100_000_000)
                or not integer(r["confirmations"], 1, 1000)
                or not integer(r["expires"], 0, 2**63 - 1)
                or r["status"] not in ("pending", "partial", "confirming", "paid", "expired")
                or not integer(r["credited"], 0, 22_000_000 * 100_000_000)
            ):
                raise StorageError("DATABASE_INTENT")
        for r in self.db.execute("SELECT * FROM outbox"):
            if (
                not integer(r["id"], 1, 2**63 - 1)
                or not integer(r["delivered"], 0, 1)
                or r["event"]
                not in (
                    "payment.pending",
                    "payment.partial",
                    "payment.confirming",
                    "payment.paid",
                    "payment.expired",
                    "payment.reorg",
                )
                or not isinstance(r["payload"], str)
                or len(r["payload"]) > 1024
            ):
                raise StorageError("DATABASE_OUTBOX")
            body = json.loads(r["payload"])
            if (
                not isinstance(body, dict)
                or set(body)
                != {"version", "intent_id", "status", "confirmed_atoms", "observed_atoms"}
                or body["version"] != 1
                or body["intent_id"] != r["intent"]
                or body["status"] not in ("pending", "partial", "confirming", "paid", "expired")
                or not all(
                    integer(body[k], 0, 22_000_000 * 100_000_000)
                    for k in ("confirmed_atoms", "observed_atoms")
                )
            ):
                raise StorageError("DATABASE_OUTBOX")
            if not self.db.execute("SELECT 1 FROM intents WHERE id=?", (r["intent"],)).fetchone():
                raise StorageError("DATABASE_OUTBOX")

    def rollback_to(self, height):
        if type(height) is not int or not 0 <= height <= self.tip()[0]:
            raise StorageError("ROLLBACK_HEIGHT")
        with self.transaction():
            self._rollback(height)

    def _rollback(self, height):
        self.db.execute("DELETE FROM coins WHERE received>?", (height,))
        self.db.execute("UPDATE coins SET spent=NULL WHERE spent>?", (height,))
        self.db.execute("DELETE FROM blocks WHERE height>?", (height,))
        self.db.execute("DELETE FROM history WHERE height>?", (height,))
        self.db.execute("DELETE FROM mempool_coins")
        self.db.execute("DELETE FROM mempool_spends")

    def export_checkpoint(self, password):
        with self.transaction():
            self.validate()
            data = {
                "schema": 3,
                "identity": self.identity,
                "tables": {
                    t: [list(r) for r in self.db.execute("SELECT * FROM " + t)] for t in TABLES
                },
            }
        return seal(json.dumps(data, separators=(",", ":")).encode(), password, b"checkpoint")

    def restore_checkpoint(self, envelope, password):
        if self.tip()[0] or self.db.execute("SELECT count(*) FROM coins").fetchone()[0]:
            raise StorageError("CHECKPOINT_NEEDS_EMPTY_STORE")
        try:
            from .state import decode_checkpoint

            data = decode_checkpoint(unseal(envelope, password, b"checkpoint"), self.identity)
            legacy = "schema" not in data
            tables = LEGACY_TABLES if legacy else TABLES
            if (
                data["identity"] != self.identity
                or set(data["tables"]) != set(tables)
                or not legacy
                and data["schema"] != 3
            ):
                raise ValueError
            with self.transaction():
                for table, width in tables.items():
                    rows = data["tables"][table]
                    if (
                        not isinstance(rows, list)
                        or len(rows) > 200000
                        or any(not isinstance(r, list) or len(r) != width for r in rows)
                    ):
                        raise ValueError
                    self.db.execute("DELETE FROM " + table)
                    self.db.executemany(
                        "INSERT INTO " + table + " VALUES(" + ",".join("?" * width) + ")", rows
                    )
                self.validate()
                if legacy:
                    self._rollback(0)
        except (ValueError, KeyError, TypeError, sqlite3.DatabaseError):
            raise StorageError("CHECKPOINT_RESTORE") from None


class Atomic:
    def __init__(self, db, lock):
        self.db, self.lock = db, lock

    def __enter__(self):
        self.lock.acquire()
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except sqlite3.DatabaseError:
            self.lock.release()
            raise StorageError("DATABASE_BUSY_OR_CORRUPT") from None
        return self.db

    def __exit__(self, typ, value, tb):
        try:
            if typ:
                self.db.execute("ROLLBACK")
            else:
                try:
                    self.db.execute("COMMIT")
                except sqlite3.DatabaseError:
                    if self.db.in_transaction:
                        self.db.execute("ROLLBACK")
                    raise StorageError("DATABASE_COMMIT_FAILED") from None
        finally:
            self.lock.release()
