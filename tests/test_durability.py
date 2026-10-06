import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet, Intent
from test_scanner_wallet import Chain, payment


def crash_writer(path, accounts, connection):
    scanner = Scanner(path, accounts)
    with scanner.store.transaction():
        scanner.store.db.execute(
            "INSERT INTO contacts VALUES('uncommitted','private','never-commit')"
        )
        connection.send(True)
        signal.pause()


def reserve_worker(path, accounts, chain, destination, connection):
    s = Scanner(path, accounts)
    try:
        s.sync(chain)
        proposal = Wallet(s).propose([Intent(destination, 90000)], 1000)
        connection.send(("reserved", len(proposal.coins)))
    except ValueError:
        connection.send(("rejected", 0))
    finally:
        s.close()


class Durability(unittest.TestCase):
    def test_sigkill_mid_transaction_recovers(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring(bytes(range(32)))
            path = Path(d) / "wallet.db"
            s = Scanner(path, ring.accounts())
            chain = Chain()
            chain.append([payment(ring.accounts()[0])])
            s.sync(chain)
            before = s.coins()
            s.close()
            parent, child = multiprocessing.Pipe(duplex=False)
            p = multiprocessing.Process(target=crash_writer, args=(path, ring.accounts(), child))
            p.start()
            try:
                self.assertTrue(parent.poll(10))
                self.assertTrue(parent.recv())
                os.kill(p.pid, signal.SIGKILL)
                p.join(10)
                self.assertEqual(p.exitcode, -signal.SIGKILL)
                restored = Scanner(path, ring.accounts())
                self.addCleanup(restored.close)
                self.assertEqual(restored.sync(chain).blocks, 0)
                self.assertEqual(restored.coins(), before)
                self.assertEqual(
                    restored.store.db.execute("SELECT count(*) FROM contacts").fetchone()[0], 0
                )
                self.assertEqual(
                    restored.store.db.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
            finally:
                if p.is_alive():
                    p.kill()
                    p.join(5)
                parent.close()
                child.close()

    def test_reorg_depths_and_repeated_restart(self):
        for depth in (1, 12, 100, 300):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as d:
                ring = Keyring(bytes(range(32)))
                path = Path(d) / "wallet.db"
                chain = Chain()
                chain.append()
                chain.append([payment(ring.accounts()[0])])
                for _ in range(depth - 1):
                    chain.append()
                for _ in range(4):
                    s = Scanner(path, ring.accounts())
                    s.sync(chain)
                    self.assertEqual(Wallet(s).balance()["confirmed_atoms"], 100000)
                    s.close()
                chain.blocks = chain.blocks[:1]
                for _ in range(depth + 1):
                    chain.append()
                s = Scanner(path, ring.accounts())
                self.assertEqual(s.sync(chain).rollback, depth)
                self.assertEqual(s.coins(), [])
                self.assertEqual(Wallet(s).history(), [])
                self.assertEqual(s.sync(chain).blocks, 0)
                s.close()

    def test_two_process_coin_reservations_never_double_credit(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring(bytes(range(32)))
            path = Path(d) / "wallet.db"
            chain = Chain()
            chain.append([payment(ring.accounts()[0])])
            dest = Keyring(b"d" * 32).accounts()[0].payment_code()
            s = Scanner(path, ring.accounts())
            s.sync(chain)
            s.close()
            jobs = []
            pipes = []
            for _ in range(2):
                parent, child = multiprocessing.Pipe(duplex=False)
                p = multiprocessing.Process(
                    target=reserve_worker, args=(path, ring.accounts(), chain, dest, child)
                )
                jobs.append(p)
                pipes.append(parent)
                p.start()
                child.close()
            results = []
            try:
                for pipe in pipes:
                    self.assertTrue(pipe.poll(15))
                    results.append(pipe.recv())
                for p in jobs:
                    p.join(10)
                    self.assertEqual(p.exitcode, 0)
                self.assertEqual(sum(result[0] == "reserved" for result in results), 1)
            finally:
                for p in jobs:
                    if p.is_alive():
                        p.kill()
                        p.join(5)
                for pipe in pipes:
                    pipe.close()

    def test_corrupt_database_and_future_schema_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.db"
            path.write_bytes(b"hostile-not-a-database")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "CORRUPTION"):
                Scanner(path, Keyring().accounts())
            path.unlink()
            ring = Keyring()
            s = Scanner(path, ring.accounts())
            s.store.db.execute("PRAGMA user_version=999")
            s.close()
            with self.assertRaisesRegex(ValueError, "INCOMPATIBLE_SCHEMA"):
                Scanner(path, ring.accounts())

    def test_v02_schema_migration_and_metadata_retention(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring()
            path = Path(d) / "old.db"
            s = Scanner(path, ring.accounts())
            chain = Chain()
            chain.append([payment(ring.accounts()[0])])
            s.sync(chain)
            wallet = Wallet(s)
            wallet.add_contact("Contact", Keyring(b"d" * 32).accounts()[0].payment_code())
            before = s.coins()
            for name in (
                "history",
                "mempool_coins",
                "mempool_spends",
                "labels",
                "intents",
                "outbox",
            ):
                s.store.db.execute("DROP TABLE " + name)
            s.store.db.execute("PRAGMA user_version=0")
            s.close()
            upgraded = Scanner(path, ring.accounts())
            self.addCleanup(upgraded.close)
            self.assertEqual(upgraded.store.tip()[0], 0)
            upgraded.sync(chain)
            self.assertEqual(upgraded.coins(), before)
            self.assertEqual(len(Wallet(upgraded).contacts()), 1)
            self.assertEqual(len(Wallet(upgraded).history()), 1)

    def test_duplicate_missing_block_and_rpc_reconnect(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring()
            chain = Chain()
            chain.append([payment(ring.accounts()[0])])
            s = Scanner(Path(d) / "wallet.db", ring.accounts())
            self.addCleanup(s.close)
            original = chain.call

            def offline(method, params=None):
                raise ConnectionError("offline")

            chain.call = offline
            with self.assertRaises(ConnectionError):
                s.sync(chain)
            with self.assertRaises(ValueError):
                s.coins()
            chain.call = original
            s.sync(chain)
            self.assertEqual(len(s.coins()), 1)
            with self.assertRaisesRegex(ValueError, "CONCURRENT_CHAIN_CHANGE"):
                s._block(chain.blocks[0], 1)
            chain.append()
            bad = dict(chain.blocks[1])
            bad["height"] = 3

            def malformed(method, params=None):
                return bad if method == "getblock" else original(method, params)

            chain.call = malformed
            with self.assertRaisesRegex(ValueError, "CHAIN_CHANGED"):
                s.sync(chain)
            self.assertEqual(s.store.tip()[0], 1)
            chain.call = original
            s.sync(chain)
            self.assertEqual(s.store.tip()[0], 2)

    def test_manual_locks_coin_control_and_stale_coordinator(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring()
            path = Path(d) / "wallet.db"
            chain = Chain()
            chain.append([payment(ring.accounts()[0])])
            s = Scanner(path, ring.accounts())
            self.addCleanup(s.close)
            s.sync(chain)
            w = Wallet(s)
            coin = s.coins()[0]
            op = (coin["txid"], coin["vout"])
            token = w.lock([op])
            self.assertEqual(w.balance()["available_atoms"], 0)
            w.unlock(token)
            other = Scanner(path, ring.accounts())
            self.addCleanup(other.close)
            chain.append()
            other.sync(chain)
            with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
                w.balance()
            s.sync(chain)
            dest = Keyring(b"d" * 32).accounts()[0].payment_code()
            proposal = w.propose([Intent(dest, 90000)], 1000, coin_control=[op])
            self.assertEqual(len(proposal.coins), 1)
