import hashlib
import hmac
import io
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from coincurve import PrivateKey
from wam_sp.api import SilentWallet
from wam_sp.keystore import Keyring
from wam_sp.adapters.pay import Merchant
from wam_sp.adapters.watchtower import health
from wam_sp.privacy import RedactedLog
from wam_sp.psbt import PSBT, Tx
from wam_sp.rpc import RPC, Cookie
from test_scanner_wallet import Chain, payment


class IntegrationsV1(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "wallet.db"
        self.ring = Keyring(bytes(range(32)))
        self.wallet = SilentWallet(self.path, self.ring.accounts())
        self.addCleanup(self.wallet.close)
        self.chain = Chain()

    def test_merchant_confirm_spend_reorg_reconfirm_outbox(self):
        merchant = Merchant(self.wallet)
        intent = merchant.create_intent(100000, 2)
        account = self.wallet.scanner.accounts[0]
        tx = payment(account, label=1)
        self.chain.append([tx])
        self.wallet.scan(self.chain)
        merchant.refresh()
        self.assertEqual(merchant.events()[-1]["event"], "payment.confirming")
        self.chain.append()
        self.wallet.scan(self.chain)
        merchant.refresh()
        self.assertEqual(merchant.events()[-1]["event"], "payment.paid")
        self.assertEqual(merchant.refresh(), 0)
        event = merchant.events()[-1]
        body, headers = merchant.webhook(event, b"s" * 32, 123)
        self.assertEqual(
            headers["WSP-Signature"],
            "sha256=" + hmac.new(b"s" * 32, b"123." + body, hashlib.sha256).hexdigest(),
        )
        self.assertNotIn(intent["destination"], body.decode())
        self.chain.append(
            [
                {
                    "txid": "aa" * 32,
                    "vin": [{"txid": tx["txid"], "vout": 0}],
                    "vout": [{"n": 0, "value": 0.0009, "scriptPubKey": {"hex": "51"}}],
                }
            ]
        )
        self.wallet.scan(self.chain)
        self.assertEqual(merchant.refresh(), 0)
        self.chain.blocks = []
        self.chain.append()
        self.wallet.scan(self.chain)
        merchant.refresh()
        self.assertEqual(merchant.events()[-1]["event"], "payment.reorg")
        self.chain.append([tx])
        self.chain.append()
        self.wallet.scan(self.chain)
        merchant.refresh()
        self.assertEqual(merchant.events()[-1]["event"], "payment.paid")
        self.wallet.scanner.store.validate()
        for event in merchant.events():
            merchant.acknowledge(event["id"])
        self.assertEqual(merchant.events(), [])

    def test_intent_expiry_and_backup_restores_outbox(self):
        merchant = Merchant(self.wallet)
        intent = merchant.create_intent(100000, 1)
        self.wallet.scan(self.chain)
        merchant.refresh(now=intent["expires"])
        self.assertEqual(merchant.events()[-1]["event"], "payment.expired")
        encrypted = self.wallet.backup(self.ring, b"synthetic recovery password")
        ring, w = SilentWallet.restore(
            encrypted, b"synthetic recovery password", Path(self.tmp.name) / "restored.db"
        )
        self.addCleanup(w.close)
        self.addCleanup(ring.close)
        self.assertEqual(Merchant(w).events(), merchant.events())

    def test_health_and_integrated_logging_no_identifiers(self):
        stream = io.StringIO()
        self.wallet.scanner.logger = RedactedLog(stream, debug=True)
        self.chain.append([payment(self.ring.accounts()[0])])
        self.wallet.scan(self.chain)
        report = health(self.wallet.scanner, node_height=5, last_error="RPC_FAILURE")
        self.assertEqual(report["behind"], 4)
        combined = json.dumps(report) + stream.getvalue()
        for forbidden in (
            "txid",
            "scan_secret",
            "spend_secret",
            "account",
            "public_key",
            self.ring.accounts()[0].payment_code(),
        ):
            self.assertNotIn(forbidden, combined)
        with self.assertRaises(ValueError):
            health(self.wallet.scanner, last_error="secret details")

    def test_profile_and_local_state_tampering_rejected(self):
        self.wallet.scanner.store.db.execute("UPDATE meta SET value='WSP-999' WHERE key='profile'")
        with self.assertRaisesRegex(ValueError, "INCOMPATIBLE_WSP_VERSION"):
            SilentWallet(self.path, self.ring.accounts())
        self.wallet.scanner.store.db.execute("UPDATE meta SET value='WSP-1' WHERE key='profile'")
        self.wallet.scanner.store.db.execute("INSERT INTO labels VALUES('unknown',1,'name')")
        with self.assertRaisesRegex(ValueError, "DATABASE_LABEL"):
            self.wallet.backup(self.ring, b"synthetic recovery password")

    def test_finalizer_rejects_signature_sighash_mismatch(self):
        key = PrivateKey.from_int(31)
        script = b"\x51\x20" + key.public_key.format()[1:]
        p = PSBT(Tx((("ab" * 32, 0),), ((900, script),)), ((1000, script),)).sign([key])
        bad = replace(p, input_extra=({b"\x03": (1).to_bytes(4, "little")},))
        with self.assertRaisesRegex(ValueError, "PSBT_SIGHASH_MISMATCH"):
            bad.finalize()
        with self.assertRaisesRegex(ValueError, "NEGATIVE_FEE"):
            replace(p, utxos=((800, script),)).finalize()

    def test_keyring_close_and_rotation_preserve_old_recovery(self):
        before = self.ring.accounts()[0]
        self.ring.rotate(20)
        restored = Keyring.restore(
            self.ring.backup(b"synthetic recovery password"), b"synthetic recovery password"
        )
        self.assertEqual(restored.accounts()[0], before)
        self.assertEqual(len(restored.accounts()), 2)
        self.ring.close()
        self.assertFalse(any(self.ring._seed))
        with self.assertRaisesRegex(ValueError, "KEYRING_CLOSED"):
            self.ring.backup(b"synthetic recovery password")
        with self.assertRaisesRegex(ValueError, "KEYRING_CLOSED"):
            self.ring.accounts()

    def test_production_rpc_read_only_capabilities(self):
        rpc = RPC("http://127.0.0.1:1", Cookie(Path(self.tmp.name) / "cookie"))
        for method in ("sendrawtransaction", "stop", "generatetoaddress", "sendtoaddress"):
            with self.assertRaisesRegex(ValueError, "RPC_METHOD_DENIED"):
                rpc.call(method, [])
        with self.assertRaisesRegex(ValueError, "RPC_ENVELOPE"):
            RPC(rpc.url, rpc.cookie, max_response=-1)

    def test_fuzz_regressions(self):
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fuzz"))
        from targets import one

        for path in (Path(__file__).resolve().parents[1] / "fuzz" / "regressions").glob("crash-*"):
            one(path.read_bytes())
