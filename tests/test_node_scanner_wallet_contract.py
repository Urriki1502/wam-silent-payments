from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from wam_sp import MatchedOutput, ScanCapability, ScannerStatus
from wam_sp import backup
from wam_sp.keystore import Keyring, export_scan, import_scan, unseal
from wam_sp.scanner import Scanner
from wam_sp.wallet import Intent, Signer, Wallet

from test_scanner_wallet import Chain, payment


PASSWORD = b"node scanner wallet contract"


class AttestedChain(Chain):
    def __init__(self):
        super().__init__()
        self.attest_calls = 0

    def attest(self):
        self.attest_calls += 1


class NodeScannerWalletContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ring = Keyring(bytes(range(32)))
        self.ring.add_label(0, 7)
        self.accounts = self.ring.accounts()
        self.chain = AttestedChain()
        self.opened = []

    def tearDown(self):
        for scanner in self.opened:
            try:
                scanner.close()
            except Exception:
                pass
        try:
            self.ring.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def scanner(self, name="wallet.db", accounts=None):
        scanner = Scanner(self.root / name, accounts or self.accounts)
        self.opened.append(scanner)
        return scanner

    def test_public_contract_types_name_authority_without_copying_secrets(self):
        account = self.accounts[0]
        self.assertIsInstance(account, ScanCapability)
        self.assertFalse(hasattr(account, "seed"))
        self.assertFalse(hasattr(account, "spend_secret"))

        scanner = self.scanner()
        status = scanner.status()
        self.assertIsInstance(status, ScannerStatus)
        self.assertFalse(status.ready)
        self.assertEqual(status.accounts, 1)

    def test_restart_begins_noncurrent_reconciles_tip_and_is_idempotent(self):
        self.chain.append([payment(self.accounts[0], label=7)])
        scanner = self.scanner()
        scanner.sync(self.chain)
        self.assertTrue(scanner.status().ready)
        durable_tip = scanner.store.tip()
        scanner.close()
        self.opened.remove(scanner)

        reopened = self.scanner()
        self.assertEqual(reopened.store.tip(), durable_tip)
        self.assertFalse(reopened.status().ready)
        with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
            reopened.coins()

        before = self.chain.attest_calls
        metrics = reopened.sync(self.chain)
        self.assertEqual(self.chain.attest_calls, before + 1)
        self.assertEqual(metrics.blocks, 0)
        self.assertTrue(reopened.status().ready)
        self.assertEqual(reopened.sync(self.chain).blocks, 0)

    def test_partial_sync_never_serves_balance(self):
        for _ in range(3):
            self.chain.append()
        scanner = self.scanner()
        metrics = scanner.sync(self.chain, max_blocks=1)
        self.assertEqual(metrics.blocks, 1)
        self.assertFalse(scanner.status().ready)
        with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
            Wallet(scanner).balance()

        scanner.sync(self.chain)
        self.assertTrue(scanner.status().ready)

    def test_empty_database_recovery_rebuilds_matches_without_spend_authority(self):
        self.chain.append([payment(self.accounts[0], label=7)])
        scanner = self.scanner()
        scanner.sync(self.chain)
        before_matches = scanner.matched_outputs()
        before_balance = Wallet(scanner).balance()
        self.assertEqual(len(before_matches), 1)
        self.assertIsInstance(before_matches[0], MatchedOutput)

        envelope = backup.create(self.ring, scanner, PASSWORD)
        scanner.close()
        self.opened.remove(scanner)
        (self.root / "wallet.db").unlink()

        restored_ring, restored = backup.restore(envelope, PASSWORD, self.root / "recovered.db")
        self.opened.append(restored)
        self.addCleanup(restored_ring.close)

        for account in restored.accounts:
            self.assertFalse(hasattr(account, "seed"))
            self.assertFalse(hasattr(account, "spend_secret"))

        self.assertFalse(restored.status().ready)
        with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
            restored.matched_outputs()

        restored.sync(self.chain)
        self.assertEqual(restored.matched_outputs(), before_matches)
        self.assertEqual(Wallet(restored).balance(), before_balance)

    def test_corrupt_and_wrong_identity_checkpoints_are_rejected(self):
        self.chain.append([payment(self.accounts[0])])
        scanner = self.scanner()
        scanner.sync(self.chain)
        checkpoint = scanner.checkpoint(PASSWORD)

        corrupt = checkpoint[:-1] + bytes([checkpoint[-1] ^ 1])
        empty = self.scanner("corrupt.db")
        with self.assertRaises(ValueError):
            empty.restore(corrupt, PASSWORD)

        other_ring = Keyring(b"x" * 32)
        self.addCleanup(other_ring.close)
        wrong = self.scanner("wrong.db", other_ring.accounts())
        with self.assertRaises(ValueError):
            wrong.restore(checkpoint, PASSWORD)

    def test_stale_checkpoint_cannot_override_reorged_node_truth(self):
        self.chain.append([payment(self.accounts[0])])
        scanner = self.scanner()
        scanner.sync(self.chain)
        checkpoint = scanner.checkpoint(PASSWORD)

        restored = self.scanner("checkpoint.db")
        restored.restore(checkpoint, PASSWORD)
        self.assertFalse(restored.status().ready)

        # Replace height 1 with a different local branch carrying no payment.
        self.chain.blocks = []
        self.chain.append()
        metrics = restored.sync(self.chain)
        self.assertEqual(metrics.rollback, 1)
        self.assertEqual(restored.matched_outputs(), ())

    def test_structurally_valid_omission_is_repaired_by_full_rescan(self):
        self.chain.append([payment(self.accounts[0])])
        scanner = self.scanner()
        scanner.sync(self.chain)
        original = scanner.matched_outputs()
        self.assertEqual(len(original), 1)

        # Model a compromised/local DB omission. This is intentionally a direct
        # test-only mutation: schema validation cannot prove completeness.
        with scanner.store.transaction():
            scanner.store.db.execute(
                "DELETE FROM coins WHERE txid=? AND vout=?",
                (original[0].txid, original[0].vout),
            )
            scanner.store.db.execute(
                "DELETE FROM history WHERE txid=?",
                (original[0].txid,),
            )

        self.assertEqual(scanner.matched_outputs(), ())
        scanner.rescan()
        self.assertFalse(scanner.status().ready)
        scanner.sync(self.chain)
        self.assertEqual(scanner.matched_outputs(), original)

    def _proposal_fixture(self):
        self.chain.append([payment(self.accounts[0])])
        scanner = self.scanner()
        scanner.sync(self.chain)
        wallet = Wallet(scanner)
        destination = Keyring(b"d" * 32)
        self.addCleanup(destination.close)
        intent = Intent(destination.accounts()[0].payment_code(), 50000)
        proposal = wallet.propose([intent], 1000)
        return scanner, wallet, proposal

    def test_signer_rejects_tampered_matched_output_identity_metadata(self):
        _scanner, _wallet, proposal = self._proposal_fixture()
        signer = Signer(self.ring)
        original = proposal.coins[0]

        mutations = {
            "public_key": "00" * 32,
            "tweak": ("00" * 31) + "01",
            "account": "ff" * 32,
            "epoch": original["epoch"] + 1,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                coin = dict(original)
                coin[field] = value
                changed = replace(proposal, coins=(coin,))
                with self.assertRaises(ValueError):
                    signer.prepare(changed)

    def test_coordinator_rejects_tampered_txid_vout_association(self):
        _scanner, wallet, proposal = self._proposal_fixture()
        original = proposal.coins[0]
        for field, value in (
            ("txid", "aa" * 32),
            ("vout", original["vout"] + 1),
        ):
            with self.subTest(field=field):
                coin = dict(original)
                coin[field] = value
                changed = replace(proposal, coins=(coin,))
                with self.assertRaisesRegex(ValueError, "RESERVATION_MISMATCH"):
                    wallet.export_request(changed, PASSWORD)

    def test_scanner_provisioning_serialization_contains_no_spend_authority(self):
        envelope = export_scan(self.accounts, PASSWORD)
        payload = unseal(envelope, PASSWORD, b"scan")
        document = json.loads(payload)

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key.lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        names = set(keys(document))
        self.assertTrue({"identity", "scan_secret", "spend_public"} <= names)
        forbidden = {"seed", "spend_secret", "private_key", "keyring", "derived_spend_key"}
        self.assertTrue(names.isdisjoint(forbidden))

        imported = import_scan(envelope, PASSWORD)
        self.ring.close()
        self.assertEqual(imported, self.accounts)
        self.assertFalse(hasattr(imported[0], "spend_secret"))


if __name__ == "__main__":
    unittest.main()
