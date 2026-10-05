import json
import tempfile
import unittest
from pathlib import Path

from wam_sp.keystore import Keyring, export_scan, import_scan, unseal
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet

PASSWORD = b"scan capability boundary test"


class ArchitectureBoundaries(unittest.TestCase):
    def test_scan_capability_has_no_seed_or_spend_secret(self):
        ring = Keyring(bytes(range(32)))
        account = ring.accounts()[0]

        self.assertTrue(hasattr(account, "scan_secret"))
        self.assertTrue(hasattr(account, "spend_public"))
        self.assertFalse(hasattr(account, "seed"))
        self.assertFalse(hasattr(account, "_seed"))
        self.assertFalse(hasattr(account, "spend_secret"))

    def test_scan_export_contains_scan_capability_not_spend_authority(self):
        ring = Keyring(bytes(range(32)))
        spend_secret = format(ring.spend_secret(0), "064x")
        envelope = export_scan(ring.accounts(), PASSWORD)

        payload = unseal(envelope, PASSWORD, b"scan")
        text = payload.decode("utf-8")

        self.assertNotIn(spend_secret, text)
        decoded = json.loads(text)
        self.assertEqual(set(decoded[0]), {"identity", "scan_secret"})
        self.assertEqual(
            set(decoded[0]["identity"]),
            {"id", "epoch", "scan_public", "spend_public", "birthday", "labels"},
        )

    def test_imported_scan_capability_operates_after_seed_owner_is_closed(self):
        ring = Keyring(bytes(range(32)))
        envelope = export_scan(ring.accounts(), PASSWORD)
        accounts = import_scan(envelope, PASSWORD)
        ring.close()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            path.chmod(0o700)
            scanner = Scanner(path / "wallet.db", accounts)
            try:
                wallet = Wallet(scanner)
                self.assertEqual(scanner.accounts, accounts)
                self.assertEqual(
                    wallet.scanner.accounts[0].payment_code(),
                    accounts[0].payment_code(),
                )
                self.assertFalse(hasattr(wallet.scanner.accounts[0], "spend_secret"))
            finally:
                scanner.close()


if __name__ == "__main__":
    unittest.main()
