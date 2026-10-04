import copy
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wam_sp.core import Input, pub, send
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.transaction import p2wpkh
from wam_sp.wallet import Wallet
from wam_sp.watcher import GENESIS


class LifecycleSource:
    def __init__(self):
        self.blocks = []
        self.mempool = {}
        self.nonce = 0

    def attest(self):
        return None

    def append(self, txs=()):
        previous = self.blocks[-1]["hash"] if self.blocks else GENESIS
        self.nonce += 1
        height = len(self.blocks) + 1
        digest = sha256((previous + str(height) + str(self.nonce)).encode()).hexdigest()
        self.blocks.append(
            {
                "height": height,
                "hash": digest,
                "previousblockhash": previous,
                "tx": list(txs),
            }
        )

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.blocks[-1]["hash"] if self.blocks else GENESIS
        if method == "getblockcount":
            return len(self.blocks)
        if method == "getblockhash":
            return self.blocks[params[0] - 1]["hash"] if params[0] else GENESIS
        if method == "getblock":
            return copy.deepcopy(next(b for b in self.blocks if b["hash"] == params[0]))
        if method == "getrawmempool":
            return list(self.mempool)
        if method == "getrawtransaction":
            return copy.deepcopy(self.mempool[params[0]])
        raise AssertionError((method, params))


def payment(account, number, label=None, value=0.001):
    key = 31 + number
    txin = Input(
        format(number, "064x"),
        0,
        p2wpkh(key),
        witness=(bytes(72), pub(key)),
        secret=key,
    )
    output = send([txin], [account.payment_code(label)])[0]
    return {
        "txid": format(1000 + number, "064x"),
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
                "value": value,
                "scriptPubKey": {"hex": (b"\x51\x20" + output).hex()},
            }
        ],
    }


class RuntimeBoundaryV2(unittest.TestCase):
    def test_scanner_lifecycle_never_crosses_spend_key_boundary(self):
        ring = Keyring(bytes(range(32)))
        base_accounts = ring.accounts()
        confirmed = payment(base_accounts[0], 1)
        mempool_payment = payment(base_accounts[0], 2)

        ring.add_label(0, 7)
        expanded_accounts = ring.accounts()
        labeled = payment(expanded_accounts[0], 3, label=7)

        ring.rotate(2)
        rotated_accounts = ring.accounts()
        rotated = payment(rotated_accounts[1], 4)

        source = LifecycleSource()
        source.append([confirmed])

        with tempfile.TemporaryDirectory() as directory:
            scanner = Scanner(Path(directory) / "wallet.db", base_accounts)
            self.addCleanup(scanner.close)

            with patch.object(
                Keyring,
                "spend_secret",
                side_effect=AssertionError("SPEND_SECRET_TOUCHED"),
            ):
                first = scanner.sync(source)
                self.assertEqual(first.blocks, 1)
                self.assertEqual(Wallet(scanner).balance()["confirmed_atoms"], 100_000)

                source.mempool[mempool_payment["txid"]] = mempool_payment
                self.assertEqual(scanner.sync_mempool(source), 1)
                self.assertTrue(scanner.mempool_ready)

                source.mempool.clear()
                source.blocks = []
                source.append([labeled])
                reorg = scanner.sync(source)
                self.assertEqual(reorg.rollback, 1)

                scanner.rescan()
                scanner.sync(source)
                self.assertEqual(scanner.store.tip()[0], 1)

                scanner.reconfigure(expanded_accounts)
                scanner.sync(source)
                self.assertEqual(Wallet(scanner).balance()["confirmed_atoms"], 100_000)

                scanner.reconfigure(rotated_accounts)
                source.append([rotated])
                scanner.sync(source)
                self.assertEqual(Wallet(scanner).balance()["confirmed_atoms"], 200_000)

        ring.close()


if __name__ == "__main__":
    unittest.main()
