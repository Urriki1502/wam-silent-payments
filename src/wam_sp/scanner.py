"""Incremental local full-node scanner with durable undo, public tweak LRU and work caps."""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from contextlib import contextmanager
from .transaction import blob
from .file_lock import exclusive_file_lock
from .core import Input, Receiver, prepare
from .limits import DEFAULT, check_inputs
from .store import Store


@dataclass
class Metrics:
    blocks: int = 0
    transactions: int = 0
    candidates: int = 0
    cache_hits: int = 0
    prepared: int = 0
    ecdh: int = 0
    curve_operations: int = 0
    rollback: int = 0


def atoms(value):
    try:
        amount = Decimal(str(value)) * 100_000_000
    except (InvalidOperation, ValueError):
        raise ValueError("INVALID_AMOUNT") from None
    if (
        not amount.is_finite()
        or amount != amount.to_integral_value()
        or not 0 <= amount <= 2**63 - 1
    ):
        raise ValueError("INVALID_AMOUNT")
    return int(amount)


def transaction_inputs(tx):
    if not isinstance(tx, dict) or not isinstance(tx.get("vin"), list) or not tx["vin"]:
        raise ValueError("INVALID_TRANSACTION")
    if len(tx["vin"]) > DEFAULT.max_inputs:
        raise ValueError("INPUT_LIMIT")
    result = []
    encoded_total = 0
    for i in tx["vin"]:
        if not isinstance(i, dict) or "prevout" not in i:
            raise ValueError("PREVOUT_DATA_REQUIRED")
        w = i.get("txinwitness", [])
        if not isinstance(w, list) or len(w) > DEFAULT.max_witness_items:
            raise ValueError("WITNESS_LIMIT")
        # Bound encoded fields before allocating decoded blobs.
        prev = i["prevout"]
        sig = i.get("scriptSig", {})
        if (
            not isinstance(prev, dict)
            or not isinstance(prev.get("scriptPubKey"), dict)
            or not isinstance(sig, dict)
        ):
            raise ValueError("TRANSACTION_FORMAT")
        fields = [prev["scriptPubKey"].get("hex"), sig.get("hex", ""), *w]
        if any(not isinstance(x, str) for x in fields):
            raise ValueError("TRANSACTION_FORMAT")
        encoded_total += sum(map(len, fields))
        if encoded_total > 2 * DEFAULT.max_transaction_bytes or any(
            len(x) > 2 * DEFAULT.max_script for x in fields[:2]
        ):
            raise ValueError("TRANSACTION_LIMIT")
        result.append(
            Input(
                i.get("txid", ""),
                i.get("vout"),
                bytes.fromhex(fields[0]),
                bytes.fromhex(fields[1]),
                tuple(bytes.fromhex(x) for x in w),
            )
        )
    check_inputs(result)
    return result


class Scanner:
    def __init__(self, path, accounts, limits=DEFAULT, logger=None):
        if not 1 <= len(accounts) <= limits.max_accounts or len(
            {a.account_id for a in accounts}
        ) != len(accounts):
            raise ValueError("ACCOUNT_LIMIT")
        self.logger = logger
        self.accounts = tuple(accounts)
        self.receivers = {
            a.account_id: Receiver(a.scan_secret, a.spend_public, a.labels, limits)
            for a in accounts
        }
        self.store = Store(path, [a.identity() for a in accounts])
        self.limits = limits
        self.ready = False
        self.verified_tip = None
        self.mempool_ready = False
        self.metrics = Metrics()

    def close(self):
        self.store.close()

    @contextmanager
    def _lease(self):
        with exclusive_file_lock(str(self.store.path) + ".scan.lock"):
            with self.store.lock:
                yield

    def sync(self, rpc, max_blocks=None, cancel=None):
        try:
            with self._lease():
                result = self._sync(rpc, max_blocks, cancel)
        except (ValueError, ConnectionError, TimeoutError, OSError):
            if self.logger:
                self.logger.emit("scan_failed")
            raise
        if self.logger:
            self.logger.emit(
                "scan_complete",
                height=self.store.tip()[0],
                blocks=result.blocks,
                transactions=result.transactions,
            )
            if result.rollback:
                self.logger.emit("reorg_detected", rollback=result.rollback)
        return result

    def _sync(self, rpc, max_blocks=None, cancel=None):
        self.ready = False
        self.mempool_ready = False
        self.metrics = Metrics()
        rpc.attest()
        target = rpc.call("getbestblockhash")
        end = rpc.call("getblockcount")
        if (
            type(end) is not int
            or end < 0
            or not isinstance(target, str)
            or not re.fullmatch("[0-9a-f]{64}", target)
            or rpc.call("getblockhash", [end]) != target
        ):
            raise ValueError("CHAIN_INCONSISTENT_TIP")
        height, tip = self.store.tip()
        if max_blocks is not None and (type(max_blocks) is not int or max_blocks < 1):
            raise ValueError("BLOCK_BATCH_LIMIT")
        ancestor = min(height, end)
        if height - ancestor > self.limits.max_reorg:
            raise ValueError("REORG_LIMIT_RESCAN_REQUIRED")
        if ancestor > 0:

            def matches(h):
                if h == 0:
                    return True
                local = self.store.db.execute(
                    "SELECT hash FROM blocks WHERE height=?", (h,)
                ).fetchone()
                if local is None:
                    raise ValueError("DATABASE_CHAIN_GAP")
                return local[0] == rpc.call("getblockhash", [h])

            if not matches(ancestor):
                low, high = 0, ancestor
                while low + 1 < high:
                    middle = (low + high) // 2
                    if matches(middle):
                        low = middle
                    else:
                        high = middle
                ancestor = low
            if height - ancestor > self.limits.max_reorg:
                raise ValueError("REORG_LIMIT_RESCAN_REQUIRED")
        if ancestor < height:
            self.store.rollback_to(ancestor)
            self.metrics.rollback = height - ancestor
        stop = end if max_blocks is None else min(end, ancestor + max_blocks)
        for h in range(ancestor + 1, stop + 1):
            if cancel and cancel():
                raise ValueError("SCAN_CANCELLED")
            blockhash = rpc.call("getblockhash", [h])
            block = rpc.call("getblock", [blockhash, 3])
            if (
                not isinstance(block, dict)
                or block.get("hash") != blockhash
                or block.get("height") != h
                or block.get("previousblockhash") != self.store.tip()[1]
            ):
                raise ValueError("CHAIN_CHANGED_RETRY")
            if (
                not isinstance(block.get("tx"), list)
                or len(block["tx"]) > self.limits.max_block_transactions
            ):
                raise ValueError("BLOCK_LIMIT")
            self._block(block, h)
            if rpc.call("getblockhash", [h]) != blockhash:
                raise ValueError("CHAIN_CHANGED_RETRY")
        if rpc.call("getbestblockhash") != target:
            raise ValueError("CHAIN_CHANGED_RETRY")
        self.ready = self.store.tip()[0] == end
        self.verified_tip = self.store.tip() if self.ready else None
        return self.metrics

    def _block(self, block, height):
        db = self.store.db
        with self.store.transaction():
            if self.store.tip() != (height - 1, block["previousblockhash"]):
                raise ValueError("CONCURRENT_CHAIN_CHANGE")
            seen = set()
            for tx in block["tx"]:
                validate_transaction_shape(tx)
                if tx["txid"] in seen:
                    raise ValueError("DUPLICATE_TRANSACTION")
                seen.add(tx["txid"])
                credit = debit = 0
                self.metrics.transactions += 1
                if not isinstance(tx.get("vin"), list) or not tx["vin"]:
                    raise ValueError("INVALID_TRANSACTION")
                if "coinbase" in tx["vin"][0]:
                    continue
                if (
                    len(tx["vin"]) > self.limits.max_inputs
                    or len(tx.get("vout", [])) > self.limits.max_outputs
                ):
                    raise ValueError("TRANSACTION_LIMIT")
                for i in tx["vin"]:
                    row = db.execute(
                        "SELECT atoms FROM coins WHERE txid=? AND vout=? AND spent IS NULL",
                        (i["txid"], i["vout"]),
                    ).fetchone()
                    if row:
                        debit += row[0]
                    db.execute(
                        "UPDATE coins SET spent=? WHERE txid=? AND vout=? AND spent IS NULL",
                        (height, i["txid"], i["vout"]),
                    )
                candidates = []
                for o in tx["vout"]:
                    s = o["scriptPubKey"]["hex"]
                    if len(s) == 68 and s.startswith("5120"):
                        candidates.append(o)
                if debit:
                    db.execute("INSERT INTO history VALUES(?,?,0,?)", (tx["txid"], height, debit))
                if not candidates:
                    continue
                active = [a for a in self.accounts if a.birthday <= height]
                if not active:
                    continue
                self.metrics.candidates += 1
                # Parse before cache use so malformed data cannot bypass limits.
                inputs = transaction_inputs(tx)
                context_key = sha256(
                    b"".join(
                        i.outpoint()
                        + blob(i.script)
                        + blob(i.script_sig)
                        + blob(b"".join(blob(w) for w in i.witness))
                        for i in inputs
                    )
                ).hexdigest()
                row = db.execute("SELECT point FROM cache WHERE txid=?", (context_key,)).fetchone()
                if row:
                    point = bytes.fromhex(row[0]) if row[0] else None
                    self.metrics.cache_hits += 1
                else:
                    try:
                        point = prepare(inputs)
                        self.metrics.prepared += 1
                    except ValueError as e:
                        if str(e) not in {
                            "INELIGIBLE_TRANSACTION",
                            "NO_ELIGIBLE_INPUTS",
                            "INPUT_SUM_ZERO",
                        }:
                            raise
                        point = None
                    db.execute(
                        "INSERT INTO cache VALUES(?,?,?)",
                        (context_key, point.hex() if point else None, height),
                    )
                db.execute("UPDATE cache SET height=? WHERE txid=?", (height, context_key))
                if point is None:
                    continue
                outputs = [bytes.fromhex(o["scriptPubKey"]["hex"][4:]) for o in candidates]
                for account in active:
                    receiver = self.receivers[account.account_id]
                    found = receiver.scan_prepared(point, outputs)
                    self.metrics.ecdh += 1
                    self.metrics.curve_operations += receiver.operations
                    for m in found:
                        o = candidates[m.output_index]
                        credit += atoms(o["value"])
                        db.execute(
                            "INSERT INTO coins VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                            (
                                tx["txid"],
                                o["n"],
                                account.account_id,
                                account.epoch,
                                atoms(o["value"]),
                                m.public_key.hex(),
                                format(m.tweak, "064x"),
                                m.label,
                                m.k,
                                height,
                            ),
                        )
                if credit:
                    db.execute(
                        "INSERT INTO history VALUES(?,?,?,0) ON CONFLICT(txid) DO UPDATE SET credit=excluded.credit",
                        (tx["txid"], height, credit),
                    )
            db.execute(
                "INSERT INTO blocks VALUES(?,?,?)",
                (height, block["hash"], block["previousblockhash"]),
            )
            db.execute(
                "DELETE FROM cache WHERE txid IN (SELECT txid FROM cache ORDER BY height DESC,txid LIMIT -1 OFFSET ?)",
                (self.limits.max_cache,),
            )
        self.metrics.blocks += 1

    def coins(self, min_confirmations=1):
        self.assert_current()
        if type(min_confirmations) is not int or min_confirmations < 1:
            raise ValueError("CONFIRMATION_POLICY")
        height = self.store.tip()[0]
        return [
            dict(r)
            for r in self.store.db.execute(
                "SELECT * FROM coins WHERE spent IS NULL AND received<=? ORDER BY txid,vout",
                (height - min_confirmations + 1,),
            )
        ]

    def assert_current(self):
        identity = self.store.db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        if (
            not self.ready
            or self.verified_tip != self.store.tip()
            or not identity
            or identity[0] != self.store.identity
        ):
            self.ready = False
            raise ValueError("SCAN_NOT_CURRENT")

    def sync_mempool(self, rpc):
        with self._lease():
            self.assert_current()
            self.mempool_ready = False
            rpc.attest()
            if rpc.call("getbestblockhash") != self.verified_tip[1]:
                raise ValueError("CHAIN_CHANGED_RETRY")
            ids = rpc.call("getrawmempool")
            if not isinstance(ids, list) or len(ids) > 10000 or len(set(ids)) != len(ids):
                raise ValueError("MEMPOOL_LIMIT")
            with self.store.transaction():
                self.assert_current()
                db = self.store.db
                db.execute("DELETE FROM mempool_coins")
                db.execute("DELETE FROM mempool_spends")
                # Fetch/process one transaction at a time. An error rolls back
                # the entire snapshot; never retain a whole mempool in RAM.
                for txid in sorted(ids):
                    tx = rpc.call("getrawtransaction", [txid, 2])
                    if not isinstance(tx, dict) or tx.get("txid") != txid:
                        raise ValueError("MEMPOOL_TRANSACTION_MISMATCH")
                    validate_transaction_shape(tx)
                    for vin in tx["vin"]:
                        if "coinbase" in vin:
                            raise ValueError("MEMPOOL_COINBASE")
                        if "prevout" not in vin:
                            prev = rpc.call("getrawtransaction", [vin["txid"], 1])
                            if (
                                not isinstance(prev, dict)
                                or prev.get("txid") != vin["txid"]
                                or not isinstance(prev.get("vout"), list)
                                or not 0 <= vin["vout"] < len(prev["vout"])
                            ):
                                raise ValueError("PREVOUT_DATA_REQUIRED")
                            vin["prevout"] = prev["vout"][vin["vout"]]
                    for i in tx["vin"]:
                        db.execute(
                            "INSERT INTO mempool_spends VALUES(?,?,?)",
                            (i["txid"], i["vout"], tx["txid"]),
                        )
                    candidates = [
                        o
                        for o in tx["vout"]
                        if len(o["scriptPubKey"]["hex"]) == 68
                        and o["scriptPubKey"]["hex"].startswith("5120")
                    ]
                    if not candidates:
                        continue
                    try:
                        point = prepare(transaction_inputs(tx))
                    except ValueError as exc:
                        if str(exc) in {
                            "INELIGIBLE_TRANSACTION",
                            "NO_ELIGIBLE_INPUTS",
                            "INPUT_SUM_ZERO",
                        }:
                            continue
                        raise
                    for a in self.accounts:
                        for m in self.receivers[a.account_id].scan_prepared(
                            point, [bytes.fromhex(o["scriptPubKey"]["hex"][4:]) for o in candidates]
                        ):
                            o = candidates[m.output_index]
                            db.execute(
                                "INSERT INTO mempool_coins VALUES(?,?,?,?,?,?,?,?,?)",
                                (
                                    tx["txid"],
                                    o["n"],
                                    a.account_id,
                                    a.epoch,
                                    atoms(o["value"]),
                                    m.public_key.hex(),
                                    format(m.tweak, "064x"),
                                    m.label,
                                    m.k,
                                ),
                            )
                if (
                    set(rpc.call("getrawmempool")) != set(ids)
                    or rpc.call("getbestblockhash") != self.verified_tip[1]
                ):
                    raise ValueError("MEMPOOL_CHANGED_RETRY")
            self.mempool_ready = True
            return len(ids)

    def checkpoint(self, password):
        if not self.ready:
            raise ValueError("SCAN_NOT_CURRENT")
        return self.store.export_checkpoint(password)

    def restore(self, envelope, password):
        self.ready = False
        self.store.restore_checkpoint(envelope, password)

    def rescan(self):
        self.ready = False
        self.store.rollback_to(0)

    def reconfigure(self, accounts):
        """Add rotated epochs/labels; retain old identities and rewind affected history."""
        if not 1 <= len(accounts) <= self.limits.max_accounts or len(
            {a.account_id for a in accounts}
        ) != len(accounts):
            raise ValueError("ACCOUNT_LIMIT")
        previous = {a.account_id: a for a in self.accounts}
        current = {a.account_id: a for a in accounts}
        if not previous.keys() <= current.keys():
            raise ValueError("OLD_ACCOUNTS_REQUIRED")
        floor = self.store.tip()[0]
        for identifier, a in current.items():
            if identifier in previous:
                old = previous[identifier]
                if (
                    a.epoch != old.epoch
                    or not set(old.labels) <= set(a.labels)
                    or a.birthday > old.birthday
                ):
                    raise ValueError("RECOVERY_METADATA_REGRESSION")
                if a != old:
                    floor = min(floor, a.birthday - 1)
            else:
                floor = min(floor, a.birthday - 1)
        receivers = {
            a.account_id: Receiver(a.scan_secret, a.spend_public, a.labels, self.limits)
            for a in accounts
        }
        from .watcher import GENESIS

        identity = json.dumps(
            {"version": 2, "network": GENESIS, "accounts": [a.identity() for a in accounts]},
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.store.transaction():
            db = self.store.db
            if (
                db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()[0]
                != self.store.identity
            ):
                raise ValueError("CONCURRENT_ACCOUNT_CHANGE")
            self.store._rollback(floor)
            db.execute("UPDATE meta SET value=? WHERE key='identity'", (identity,))
        self.store.identity = identity
        self.accounts = tuple(accounts)
        self.receivers = receivers
        self.ready = False


def validate_transaction_shape(tx):
    if (
        not isinstance(tx, dict)
        or not isinstance(tx.get("txid"), str)
        or not re.fullmatch("[0-9a-f]{64}", tx["txid"])
    ):
        raise ValueError("TRANSACTION_FORMAT")
    vin, vout = tx.get("vin"), tx.get("vout")
    if (
        not isinstance(vin, list)
        or not 1 <= len(vin) <= DEFAULT.max_inputs
        or not isinstance(vout, list)
        or not 1 <= len(vout) <= DEFAULT.max_outputs
    ):
        raise ValueError("TRANSACTION_LIMIT")
    seen = set()
    for i in vin:
        if not isinstance(i, dict):
            raise ValueError("TRANSACTION_FORMAT")
        if "coinbase" in i:
            if len(vin) != 1:
                raise ValueError("MALFORMED_COINBASE")
            continue
        outpoint = Input(i.get("txid", ""), i.get("vout"), b"").outpoint()
        if outpoint in seen:
            raise ValueError("DUPLICATE_INPUT")
        seen.add(outpoint)
    total = 0
    for expected, o in enumerate(vout):
        if not isinstance(o, dict) or type(o.get("n")) is not int or o["n"] != expected:
            raise ValueError("OUTPUT_INDEX")
        spk = o.get("scriptPubKey")
        if not isinstance(spk, dict):
            raise ValueError("SCRIPT_ENCODING")
        script = spk.get("hex")
        if not isinstance(script, str) or len(script) > 2 * DEFAULT.max_script or len(script) % 2:
            raise ValueError("SCRIPT_LIMIT")
        try:
            bytes.fromhex(script)
        except ValueError:
            raise ValueError("SCRIPT_ENCODING") from None
        total += atoms(o.get("value"))
        if total > 22_000_000 * 100_000_000:
            raise ValueError("AMOUNT_RANGE")
