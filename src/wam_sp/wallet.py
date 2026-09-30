"""Confirmed-coin wallet, privacy-aware selection and an isolated signing role."""

import secrets
import time
from dataclasses import dataclass
from .core import Input, Match, address, decode_address, send, spending_key
from .psbt import PSBT, Tx, MAX_INPUTS
from .scanner import atoms


@dataclass(frozen=True, repr=False)
class Intent:
    code: str
    atoms: int

    def validate(self):
        decode_address(self.code)
        if type(self.atoms) is not int or not 330 <= self.atoms <= 22_000_000 * 100_000_000:
            raise ValueError("PAYMENT_AMOUNT")


@dataclass(frozen=True, repr=False)
class Proposal:
    coins: tuple[dict, ...]
    intents: tuple[Intent, ...]
    fee: int
    change_epoch: int
    token: str


@dataclass(frozen=True, repr=False)
class Prepared:
    proposal: Proposal
    psbt: bytes


class Wallet:
    """Coordinator role. Holds no spend secret; outputs contain no private keys."""

    def __init__(self, scanner):
        self.scanner = scanner

    @property
    def db(self):
        return self.scanner.store.db

    def add_contact(self, name, code):
        decode_address(code)
        if not isinstance(name, str) or not 1 <= len(name) <= 64 or any(ord(c) < 32 for c in name):
            raise ValueError("CONTACT_NAME")
        identifier = secrets.token_hex(16)
        self.db.execute("INSERT INTO contacts VALUES(?,?,?)", (identifier, name, code.lower()))
        return identifier

    def contacts(self):
        return [dict(r) for r in self.db.execute("SELECT id,name FROM contacts ORDER BY name")]

    def contact_intent(self, identifier, value):
        row = self.db.execute("SELECT code FROM contacts WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise ValueError("CONTACT_NOT_FOUND")
        result = Intent(row[0], value)
        result.validate()
        return result

    def balance(self, min_confirmations=1):
        with self.scanner.store.transaction():
            return self._balance(min_confirmations)

    def _balance(self, min_confirmations):
        coins = self.scanner.coins(min_confirmations)
        reserved = {(r[0], r[1]) for r in self.db.execute("SELECT txid,vout FROM reservations")}
        locked = sum(c["atoms"] for c in coins if (c["txid"], c["vout"]) in reserved)
        total = sum(c["atoms"] for c in coins)
        unavailable = {
            (r[0], r[1]) for r in self.db.execute("SELECT txid,vout FROM mempool_spends")
        }
        available = sum(
            c["atoms"] for c in coins if (c["txid"], c["vout"]) not in reserved | unavailable
        )
        pending = None
        pending_spent = None
        if self.scanner.mempool_ready:
            pending = self.db.execute(
                "SELECT coalesce(sum(atoms),0) FROM mempool_coins c WHERE NOT EXISTS(SELECT 1 FROM mempool_spends s WHERE s.txid=c.txid AND s.vout=c.vout)"
            ).fetchone()[0]
            pending_spent = self.db.execute(
                "SELECT coalesce(sum(atoms),0) FROM coins c WHERE spent IS NULL AND EXISTS(SELECT 1 FROM mempool_spends s WHERE s.txid=c.txid AND s.vout=c.vout)"
            ).fetchone()[0]
        return {
            "confirmed_atoms": total,
            "reserved_atoms": locked,
            "available_atoms": available,
            "unconfirmed_atoms": pending,
            "pending_spent_atoms": pending_spent,
        }

    def propose(
        self,
        intents,
        fee,
        change_epoch=None,
        min_confirmations=1,
        allow_cluster_merge=False,
        coin_control=None,
    ):
        if not 1 <= len(intents) <= 128:
            raise ValueError("RECIPIENT_LIMIT")
        for i in intents:
            i.validate()
        if type(fee) is not int or not 1 <= fee <= 1_000_000:
            raise ValueError("FEE_POLICY")
        if change_epoch is None:
            change_epoch = max(a.epoch for a in self.scanner.accounts)
        if type(change_epoch) is not int or change_epoch not in {
            a.epoch for a in self.scanner.accounts
        }:
            raise ValueError("UNKNOWN_EPOCH")
        needed = sum(i.atoms for i in intents) + fee
        with self.scanner.store.transaction():
            coins = self.scanner.coins(min_confirmations)
            if len(coins) > 10000:
                raise ValueError("COIN_SELECTION_LIMIT")
            locked = {(r[0], r[1]) for r in self.db.execute("SELECT txid,vout FROM reservations")}
            locked.update(
                (r[0], r[1]) for r in self.db.execute("SELECT txid,vout FROM mempool_spends")
            )
            available = [c for c in coins if (c["txid"], c["vout"]) not in locked]
            if coin_control is not None:
                if not 1 <= len(coin_control) <= MAX_INPUTS or len(set(coin_control)) != len(
                    coin_control
                ):
                    raise ValueError("COIN_CONTROL")
                available = [c for c in available if (c["txid"], c["vout"]) in set(coin_control)]
                if len(available) != len(coin_control):
                    raise ValueError("COIN_CONTROL_UNAVAILABLE")
            groups = {}
            for c in available:
                cluster = "merged" if allow_cluster_merge else (c["account"], c["label"])
                groups.setdefault(cluster, []).append(c)
            options = []
            for group in groups.values():
                # Bounded deterministic greedy: prefer one coin, then few large inputs.
                for candidate in sorted(group, key=lambda c: (c["atoms"], c["txid"], c["vout"])):
                    rest = candidate["atoms"] - needed
                    if rest == 0 or rest >= 330:
                        options.append([candidate])
                        break
                chosen = []
                total = 0
                for c in sorted(group, key=lambda c: (-c["atoms"], c["txid"], c["vout"]))[
                    :MAX_INPUTS
                ]:
                    chosen.append(c)
                    total += c["atoms"]
                    if total == needed or total >= needed + 330:
                        options.append(chosen)
                        break
            if coin_control is not None:
                if not allow_cluster_merge and len(groups) > 1:
                    raise ValueError("COIN_CONTROL_CLUSTER_MERGE")
                total = sum(c["atoms"] for c in available)
                options = [available] if total == needed or total >= needed + 330 else []
            if not options:
                raise ValueError("INSUFFICIENT_SINGLE_CLUSTER_FUNDS")
            selected = min(options, key=lambda cs: (len(cs), sum(c["atoms"] for c in cs) - needed))
            token = secrets.token_hex(16)
            for c in selected:
                self.db.execute(
                    "INSERT INTO reservations VALUES(?,?,?,?,?)",
                    (c["txid"], c["vout"], token, "draft", int(time.time())),
                )
        return Proposal(tuple(selected), tuple(intents), fee, change_epoch, token)

    def lock(self, outpoints):
        with self.scanner.store.transaction():
            available = {(c["txid"], c["vout"]) for c in self.scanner.coins()}
            if (
                not outpoints
                or len(set(outpoints)) != len(outpoints)
                or not set(outpoints) <= available
            ):
                raise ValueError("COIN_CONTROL")
            token = secrets.token_hex(16)
            for txid, vout in outpoints:
                self.db.execute(
                    "INSERT INTO reservations VALUES(?,?,?,?,?)",
                    (txid, vout, token, "manual", int(time.time())),
                )
        return token

    def unlock(self, token):
        with self.scanner.store.transaction():
            rows = self.db.execute(
                "SELECT state FROM reservations WHERE token=?", (token,)
            ).fetchall()
            if not rows or any(r[0] != "manual" for r in rows):
                raise ValueError("LOCK_NOT_MANUAL")
            self.db.execute("DELETE FROM reservations WHERE token=?", (token,))

    def history(self, limit=100, offset=0):
        with self.scanner.store.transaction():
            return self._history(limit, offset)

    def _history(self, limit, offset):
        self.scanner.assert_current()
        if (
            type(limit) is not int
            or not 1 <= limit <= 1000
            or type(offset) is not int
            or not 0 <= offset <= 1000000
        ):
            raise ValueError("HISTORY_PAGE")
        tip = self.scanner.store.tip()[0]
        return [
            dict(r) | {"confirmations": tip - r["height"] + 1}
            for r in self.db.execute(
                "SELECT * FROM history ORDER BY height,txid LIMIT ? OFFSET ?", (limit, offset)
            )
        ]

    def release_draft(self, token):
        # Never automatically expire a signed/uncertain/broadcast input lock.
        with self.scanner.store.transaction():
            rows = self.db.execute(
                "SELECT state FROM reservations WHERE token=?", (token,)
            ).fetchall()
            if not rows or any(r[0] != "draft" for r in rows):
                raise ValueError("RESERVATION_NOT_DRAFT")
            self.db.execute("DELETE FROM reservations WHERE token=?", (token,))

    def mark_signed(self, token):
        with self.scanner.store.transaction():
            result = self.db.execute(
                "UPDATE reservations SET state='signed' WHERE token=? AND state='draft'", (token,)
            )
            if not result.rowcount:
                raise ValueError("RESERVATION_NOT_DRAFT")

    def export_request(self, proposal, password):
        locked = {
            (r[0], r[1])
            for r in self.db.execute(
                "SELECT txid,vout FROM reservations WHERE token=?", (proposal.token,)
            )
        }
        if locked != {(c["txid"], c["vout"]) for c in proposal.coins}:
            raise ValueError("RESERVATION_MISMATCH")
        envelope = encode_request(proposal, password)
        self.mark_signed(proposal.token)
        return envelope

    def broadcast(self, psbt_bytes, token, rpc):
        if not self.scanner.ready:
            raise ValueError("SCAN_NOT_CURRENT")
        psbt = PSBT.decode(psbt_bytes)
        raw = psbt.finalize()
        rpc.attest()
        locked = {
            (r[0], r[1])
            for r in self.db.execute("SELECT txid,vout FROM reservations WHERE token=?", (token,))
        }
        if locked != set(psbt.tx.inputs):
            raise ValueError("RESERVATION_MISMATCH")
        for (txid, vout), (value, script) in zip(psbt.tx.inputs, psbt.utxos):
            utxo = rpc.call("gettxout", [txid, vout, True])
            if (
                not utxo
                or atoms(utxo["value"]) != value
                or utxo["scriptPubKey"]["hex"] != script.hex()
            ):
                raise ValueError("UTXO_CHANGED")
        accepted = rpc.call("testmempoolaccept", [[raw.hex()]])
        if not accepted[0].get("allowed"):
            raise ValueError("MEMPOOL_REJECTED")
        self.db.execute("UPDATE reservations SET state='uncertain' WHERE token=?", (token,))
        actual = rpc.call("sendrawtransaction", [raw.hex()])
        if actual != psbt.txid():
            raise ValueError("BROADCAST_UNCERTAIN")
        self.db.execute("UPDATE reservations SET state='broadcast' WHERE token=?", (token,))
        return actual  # Sensitive local return value; never included in public reports.


class Signer:
    """Offline role: recompute destinations/change and verify approved intent before signing."""

    def __init__(self, keyring):
        self._keyring = keyring

    def _build(self, proposal):
        if not 1 <= len(proposal.coins) <= MAX_INPUTS or not 1 <= len(proposal.intents) <= 128:
            raise ValueError("SIGNING_LIMIT")
        accounts = {a.epoch: a for a in self._keyring.accounts()}
        if proposal.change_epoch not in accounts:
            raise ValueError("UNKNOWN_EPOCH")
        keys = []
        inputs = []
        utxos = []
        for c in proposal.coins:
            if c["epoch"] not in accounts or c["account"] != accounts[c["epoch"]].account_id:
                raise ValueError("ACCOUNT_MISMATCH")
            m = Match(
                c["vout"], bytes.fromhex(c["public_key"]), int(c["tweak"], 16), c["label"], c["k"]
            )
            key = spending_key(self._keyring.spend_secret(c["epoch"]), m)
            script = b"\x51\x20" + m.public_key
            inputs.append(
                Input(
                    c["txid"],
                    c["vout"],
                    script,
                    witness=(bytes(64),),
                    secret=int.from_bytes(key.secret, "big"),
                )
            )
            keys.append(key)
            utxos.append((c["atoms"], script))
        for i in proposal.intents:
            i.validate()
        if type(proposal.fee) is not int or not 1 <= proposal.fee <= 1_000_000:
            raise ValueError("FEE_POLICY")
        codes = [i.code for i in proposal.intents]
        values = [i.atoms for i in proposal.intents]
        change = sum(v for v, _ in utxos) - sum(values) - proposal.fee
        if change < 0 or 0 < change < 330:
            raise ValueError("CHANGE_POLICY")
        if change:
            a = accounts[proposal.change_epoch]
            codes.append(address(a.scan_secret, a.spend_public, 0))
            values.append(change)
        outputs = send(inputs, codes)
        tx = Tx(
            tuple((i.txid, i.vout) for i in inputs),
            tuple((value, b"\x51\x20" + p) for value, p in zip(values, outputs)),
        )
        from .adapters.sp_psbt import add_sender, add_spend

        psbt = add_sender(PSBT(tx, tuple(utxos)), keys, codes)
        psbt = add_spend(psbt, proposal.coins, self._keyring.accounts())
        return psbt, keys

    def prepare(self, proposal):
        psbt, _ = self._build(proposal)
        return Prepared(proposal, psbt.encode())

    def sign(self, prepared, approved_intents, approved_max_fee):
        if tuple(approved_intents) != prepared.proposal.intents:
            raise ValueError("INTENT_NOT_APPROVED")
        if type(approved_max_fee) is not int or not 0 < prepared.proposal.fee <= approved_max_fee:
            raise ValueError("FEE_NOT_APPROVED")
        expected, keys = self._build(prepared.proposal)
        supplied = PSBT.decode(prepared.psbt)
        if (
            supplied.tx != expected.tx
            or supplied.utxos != expected.utxos
            or any(supplied.signatures)
        ):
            raise ValueError("PSBT_INTENT_MISMATCH")
        from .adapters.sp_psbt import verify_sender

        verify_sender(supplied)
        for a, b in zip(expected.input_extra, supplied.input_extra):
            if {k: v for k, v in a.items() if k[0] in (0x1F, 0x20)} != {
                k: v for k, v in b.items() if k[0] in (0x1F, 0x20)
            }:
                raise ValueError("PSBT_SPEND_METADATA_MISMATCH")
        for a, b in zip(expected.output_extra, supplied.output_extra):
            if {k: v for k, v in a.items() if k[0] in (9, 10)} != {
                k: v for k, v in b.items() if k[0] in (9, 10)
            }:
                raise ValueError("PSBT_INTENT_MISMATCH")
        return supplied.sign(keys).encode()


def encode_request(proposal, password):
    """Private transport sidecar; contains intent/UTXO metadata, never spending keys."""
    import json
    from .keystore import seal

    data = {
        "version": 2,
        "coins": proposal.coins,
        "intents": [{"code": i.code, "atoms": i.atoms} for i in proposal.intents],
        "fee": proposal.fee,
        "change_epoch": proposal.change_epoch,
        "token": proposal.token,
    }
    raw = json.dumps(data, separators=(",", ":")).encode()
    if len(raw) > 1_000_000:
        raise ValueError("REQUEST_LIMIT")
    return seal(raw, password, b"intent")


def decode_request(envelope, password):
    import json
    from .keystore import unseal

    try:
        raw = unseal(envelope, password, b"intent")
        if len(raw) > 1_000_000:
            raise ValueError
        d = json.loads(raw)
        if (
            set(d) != {"version", "coins", "intents", "fee", "change_epoch", "token"}
            or d["version"] != 2
        ):
            raise ValueError
        if (
            not 1 <= len(d["coins"]) <= MAX_INPUTS
            or not 1 <= len(d["intents"]) <= 128
            or not isinstance(d["token"], str)
            or len(d["token"]) > 64
        ):
            raise ValueError
        fields = {"txid", "vout", "account", "epoch", "atoms", "public_key", "tweak", "label", "k"}
        coins = []
        for c in d["coins"]:
            if not fields <= c.keys() or not c.keys() <= fields | {"received", "spent"}:
                raise ValueError
            coins.append({k: c[k] for k in fields})
        intents = tuple(Intent(i["code"], i["atoms"]) for i in d["intents"])
        for i in intents:
            i.validate()
        return Proposal(tuple(coins), intents, d["fee"], d["change_epoch"], d["token"])
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("REQUEST_RESTORE") from None
