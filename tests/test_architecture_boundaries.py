import inspect
import os
from pathlib import Path
import tempfile
import unittest

from wam_sp.block_source import BlockSource
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.wallet import Signer, Wallet
from wam_sp.watcher import GENESIS


class EmptyChainSource:
    def __init__(self):
        self.attested = False
        self.calls = []

    def attest(self):
        self.attested = True

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == "getbestblockhash":
            return GENESIS
        if method == "getblockcount":
            return 0
        if method == "getblockhash" and params == [0]:
            return GENESIS
        raise AssertionError((method, params))


class ArchitectureBoundaryTests(unittest.TestCase):
    def private_dir(self):
        path = Path(tempfile.mkdtemp(prefix="wsp-boundary-"))
        if os.name == "posix":
            os.chmod(path, 0o700)
        self.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
        return path

    def test_minimal_block_source_can_drive_scanner_without_wallet_capability(self):
        source = EmptyChainSource()
        self.assertIsInstance(source, BlockSource)
        with Keyring(bytes.fromhex("01" * 32)) as ring:
            accounts = ring.accounts()
            scanner = Scanner(self.private_dir() / "wallet.db", accounts)
            self.addCleanup(scanner.close)
            metrics = scanner.sync(source)
            self.assertTrue(source.attested)
            self.assertEqual(metrics.blocks, 0)
            self.assertTrue(scanner.ready)
            self.assertEqual(scanner.verified_tip, (0, GENESIS))

    def test_scan_account_contains_no_spend_private_key(self):
        with Keyring(bytes.fromhex("02" * 32)) as ring:
            account = ring.accounts()[0]
            self.assertTrue(hasattr(account, "scan_secret"))
            self.assertTrue(hasattr(account, "spend_public"))
            self.assertFalse(hasattr(account, "spend_secret"))
            identity = account.identity()
            self.assertIn("scan_public", identity)
            self.assertIn("spend_public", identity)
            self.assertNotIn("scan_secret", identity)
            self.assertNotIn("spend_secret", identity)

    def test_scanner_has_no_spend_secret_or_signer_dependency(self):
        source = inspect.getsource(Scanner)
        self.assertNotIn("spend_secret", source)
        self.assertNotIn("Signer(", source)
        self.assertNotIn("Keyring(", source)

    def test_wallet_coordinator_holds_scanner_not_keyring(self):
        with Keyring(bytes.fromhex("03" * 32)) as ring:
            scanner = Scanner(self.private_dir() / "wallet.db", ring.accounts())
            self.addCleanup(scanner.close)
            wallet = Wallet(scanner)
            self.assertIs(wallet.scanner, scanner)
            self.assertFalse(hasattr(wallet, "_keyring"))
            signer = Signer(ring)
            self.assertIs(signer._keyring, ring)


if __name__ == "__main__":
    unittest.main()
