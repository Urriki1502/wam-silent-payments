import copy
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wam_sp.block_source import BlockSource
from wam_sp.core import Input, pub, send
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.wallet import Wallet
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


class OneBlockSource:
    def __init__(self, txs):
        digest = sha256((GENESIS + "1").encode()).hexdigest()
        self.block = {
            "height": 1,
            "hash": digest,
            "previousblockhash": GENESIS,
            "tx": list(txs),
        }
        self.attested = False

    def attest(self):
        self.attested = True

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.block["hash"]
        if method == "getblockcount":
            return 1
        if method == "getblockhash":
            if params == [0]:
                return GENESIS
            if params == [1]:
                return self.block["hash"]
        if method == "getblock" and params == [self.block["hash"], 3]:
            return copy.deepcopy(self.block)
        raise AssertionError((method, params))


def payment(account):
    key = 32
    txin = Input("01" * 32, 0, p2wpkh(key), witness=(bytes(72), pub(key)), secret=key)
    output = send([txin], [account.payment_code()])[0]
    return {
        "txid": "02" * 32,
        "vin": [
            {
                "txid": txin.txid,
                "vout": 0,
                "scriptSig": {"hex": ""},
                "txinwitness": [item.hex() for item in txin.witness],
                "prevout": {"scriptPubKey": {"hex": txin.script.hex()}},
            }
        ],
        "vout": [
            {
                "n": 0,
                "value": 0.001,
                "scriptPubKey": {"hex": (b"\x51\x20" + output).hex()},
            }
        ],
    }


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

    def test_full_scan_and_coordinator_never_touch_spend_secret(self):
        with Keyring(bytes.fromhex("03" * 32)) as ring:
            accounts = ring.accounts()
            source = OneBlockSource([payment(accounts[0])])
            scanner = Scanner(self.private_dir() / "wallet.db", accounts)
            self.addCleanup(scanner.close)

            with patch.object(
                Keyring,
                "spend_secret",
                side_effect=AssertionError("SPEND_SECRET_TOUCHED"),
            ):
                metrics = scanner.sync(source)
                balance = Wallet(scanner).balance()

            self.assertTrue(source.attested)
            self.assertEqual(metrics.blocks, 1)
            self.assertEqual(metrics.transactions, 1)
            self.assertEqual(balance["confirmed_atoms"], 100_000)


if __name__ == "__main__":
    unittest.main()
