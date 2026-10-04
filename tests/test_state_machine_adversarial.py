import copy
from pathlib import Path
import random
import tempfile
import unittest

from test_scanner_wallet import Chain, payment
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet


class StatefulChain(Chain):
    def __init__(self):
        super().__init__()
        self.mempool = {}

    def call(self, method, params=None):
        if method == "getrawmempool":
            return sorted(self.mempool)
        if method == "getrawtransaction":
            return copy.deepcopy(self.mempool[params[0]])
        return super().call(method, params)


class ScannerStateMachine(unittest.TestCase):
    def test_adversarial_lifecycle_matches_clean_rescan_oracle(self):
        rng = random.Random(352_2026)
        ring = Keyring(bytes(range(32)))
        account = ring.accounts()[0]
        chain = StatefulChain()
        counter = 1

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_path = root / "live.db"
            live = Scanner(live_path, (account,))
            self.addCleanup(lambda: live.close())

            for step in range(32):
                operation = rng.randrange(5)

                if operation == 0 or not chain.blocks:
                    txs = []
                    if rng.randrange(3):
                        txs.append(payment(account, counter))
                        counter += 1
                    chain.append(txs)

                elif operation == 1:
                    depth = 1 + rng.randrange(min(3, len(chain.blocks)))
                    chain.blocks = chain.blocks[:-depth]
                    for _ in range(depth + rng.randrange(2)):
                        txs = []
                        if rng.randrange(2):
                            txs.append(payment(account, counter))
                            counter += 1
                        chain.append(txs)

                elif operation == 2:
                    live.rescan()

                elif operation == 3:
                    live.close()
                    live = Scanner(live_path, (account,))

                else:
                    chain.mempool.clear()
                    for _ in range(rng.randrange(3)):
                        tx = payment(account, counter)
                        counter += 1
                        chain.mempool[tx["txid"]] = tx

                with self.subTest(step=step, operation=operation):
                    live.sync(chain)
                    live.sync_mempool(chain)

                    oracle = Scanner(root / f"oracle-{step}.db", (account,))
                    try:
                        oracle.sync(chain)
                        oracle.sync_mempool(chain)

                        self.assertEqual(live.store.tip(), oracle.store.tip())
                        self.assertEqual(live.coins(), oracle.coins())
                        self.assertEqual(Wallet(live).history(), Wallet(oracle).history())
                        self.assertEqual(Wallet(live).balance(), Wallet(oracle).balance())
                    finally:
                        oracle.close()

            ring.close()


if __name__ == "__main__":
    unittest.main()
