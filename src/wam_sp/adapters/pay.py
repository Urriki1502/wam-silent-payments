"""Scan-only merchant intents and durable webhook outbox, no network sender."""

import hashlib
import hmac
import json
import secrets
import time


class Merchant:
    def __init__(self, wallet):
        self.wallet = wallet

    @property
    def db(self):
        return self.wallet.scanner.store.db

    def create_intent(self, atoms, confirmations=6, expires=None):
        if (
            type(atoms) is not int
            or not 330 <= atoms <= 22_000_000 * 100_000_000
            or type(confirmations) is not int
            or not 1 <= confirmations <= 1000
        ):
            raise ValueError("INTENT_POLICY")
        now = int(time.time())
        if expires is None:
            expires = now + 3600
        if type(expires) is not int or not now < expires <= now + 365 * 86400:
            raise ValueError("INTENT_EXPIRY")
        allocated = self.wallet.create_labeled_address()
        a = self.wallet._account(allocated["epoch"])
        identifier = secrets.token_hex(16)
        self.db.execute(
            "INSERT INTO intents VALUES(?,?,?,?,?,?,?,0)",
            (
                identifier,
                a.account_id,
                allocated["label"],
                atoms,
                confirmations,
                expires,
                "pending",
            ),
        )
        return {
            "id": identifier,
            "destination": allocated["address"],
            "atoms": atoms,
            "confirmations": confirmations,
            "expires": expires,
        }

    def refresh(self, now=None):
        now = int(time.time()) if now is None else now
        if type(now) is not int or now < 0:
            raise ValueError("INTENT_TIME")
        scanner = self.wallet.scanner
        with scanner.store.transaction():
            scanner.assert_current()
            tip = scanner.store.tip()[0]
            changes = 0
            for row in self.db.execute("SELECT * FROM intents ORDER BY id").fetchall():
                matches = self.db.execute(
                    "SELECT atoms,received FROM coins WHERE account=? AND label=?",
                    (row["account"], row["label"]),
                ).fetchall()
                observed = sum(x["atoms"] for x in matches)
                confirmed = sum(
                    x["atoms"] for x in matches if tip - x["received"] + 1 >= row["confirmations"]
                )
                status = (
                    "paid"
                    if confirmed >= row["atoms"]
                    else "confirming"
                    if observed >= row["atoms"]
                    else "partial"
                    if observed
                    else "expired"
                    if now >= row["expires"]
                    else "pending"
                )
                if status != row["status"] or confirmed != row["credited"]:
                    event = (
                        "payment.reorg"
                        if row["status"] == "paid" and status != "paid"
                        else "payment." + status
                    )
                    payload = json.dumps(
                        {
                            "version": 1,
                            "intent_id": row["id"],
                            "status": status,
                            "confirmed_atoms": confirmed,
                            "observed_atoms": observed,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    self.db.execute(
                        "UPDATE intents SET status=?,credited=? WHERE id=?",
                        (status, confirmed, row["id"]),
                    )
                    self.db.execute(
                        "INSERT INTO outbox(intent,event,payload) VALUES(?,?,?)",
                        (row["id"], event, payload),
                    )
                    changes += 1
            return changes

    def events(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("EVENT_LIMIT")
        return [
            dict(row)
            for row in self.db.execute(
                "SELECT id,event,payload FROM outbox WHERE delivered=0 ORDER BY id LIMIT ?",
                (limit,),
            )
        ]

    def acknowledge(self, event_id):
        if type(event_id) is not int or event_id < 1:
            raise ValueError("EVENT_ID")
        self.db.execute("UPDATE outbox SET delivered=1 WHERE id=?", (event_id,))

    @staticmethod
    def webhook(event, secret, timestamp):
        if (
            not isinstance(secret, bytes)
            or len(secret) < 32
            or type(timestamp) is not int
            or timestamp < 0
        ):
            raise ValueError("WEBHOOK_CREDENTIALS")
        body = json.dumps(
            {
                "version": 1,
                "event_id": event["id"],
                "event": event["event"],
                "data": json.loads(event["payload"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest = hmac.new(secret, str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()
        return body, {
            "WSP-Timestamp": str(timestamp),
            "WSP-Signature": "sha256=" + digest,
            "WSP-Event-ID": str(event["id"]),
        }
