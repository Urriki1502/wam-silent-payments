import copy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from wam_sp.core import Input, pub, send, Receiver, prepare
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet, Intent
from wam_sp.transaction import p2wpkh
from wam_sp.watcher import GENESIS
from wam_sp.limits import DEFAULT

PASSWORD = b"checkpoint secret for synthetic tests"


class Chain:
    def __init__(self):
        self.blocks = []
        self.fetches = 0
        self.nonce = 0

    def attest(self):
        return None

    def append(self, txs=()):
        previous = self.blocks[-1]["hash"] if self.blocks else GENESIS
        self.nonce += 1
        h = len(self.blocks) + 1
        digest = sha256((previous + str(h) + str(self.nonce)).encode()).hexdigest()
        self.blocks.append(
            {"height": h, "hash": digest, "previousblockhash": previous, "tx": list(txs)}
        )

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.blocks[-1]["hash"] if self.blocks else GENESIS
        if method == "getblockcount":
            return len(self.blocks)
        if method == "getblockhash":
            return self.blocks[params[0] - 1]["hash"] if params[0] else GENESIS
        if method == "getblock":
            self.fetches += 1
            return copy.deepcopy(next(b for b in self.blocks if b["hash"] == params[0]))
        raise ValueError("UNEXPECTED_RPC")


def payment(account, number=1, label=None, value=0.001):
    key = 31 + number
    txin = Input(format(number, "064x"), 0, p2wpkh(key), witness=(bytes(72), pub(key)), secret=key)
    outputs = send([txin], [account.payment_code(label)])
    return {
        "txid": format(1000 + number, "064x"),
        "vin": [
            {
                "txid": txin.txid,
                "vout": 0,
                "scriptSig": {"hex": ""},
                "txinwitness": [x.hex() for x in txin.witness],
                "prevout": {"scriptPubKey": {"hex": txin.script.hex()}},
            }
        ],
        "vout": [
            {"n": 0, "value": value, "scriptPubKey": {"hex": (b"\x51\x20" + outputs[0]).hex()}}
        ],
    }


class ScannerWallet(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.ring = Keyring(bytes(range(32)))
        self.ring.add_label(0, 7)
        self.accounts = self.ring.accounts()
        self.chain = Chain()
        self.scanners = []

    def tearDown(self):
        for s in self.scanners:
            s.close()
        self.tmp.cleanup()

    def scanner(self, name="wallet.db", accounts=None, limits=DEFAULT):
        s = Scanner(self.path / name, accounts or self.accounts, limits)
        self.scanners.append(s)
        return s

    def test_incremental_warm_resume_and_cache(self):
        self.chain.append([payment(self.accounts[0])])
        s = self.scanner()
        m = s.sync(self.chain)
        self.assertEqual((m.blocks, m.prepared, m.ecdh), (1, 1, 1))
        self.assertEqual(len(s.coins()), 1)
        self.chain.fetches = 0
        m = s.sync(self.chain)
        self.assertEqual((m.blocks, self.chain.fetches), (0, 0))
        s.rescan()
        m = s.sync(self.chain)
        self.assertEqual(m.cache_hits, 1)
        self.assertEqual(m.prepared, 0)
        reopened = self.scanner()
        m = reopened.sync(self.chain)
        self.assertEqual(m.blocks, 0)
        self.assertEqual(reopened.coins(), s.coins())

    def test_deep_reorg_300_and_spend_undo(self):
        tx = payment(self.accounts[0])
        self.chain.append([tx])
        s = self.scanner()
        spend = {
            "txid": "ff" * 32,
            "vin": [{"txid": tx["txid"], "vout": 0}],
            "vout": [{"n": 0, "value": 0.0009, "scriptPubKey": {"hex": "51"}}],
        }
        self.chain.append([spend])
        for _ in range(299):
            self.chain.append()
        s.sync(self.chain)
        self.assertEqual(s.coins(), [])
        self.chain.blocks = self.chain.blocks[:1]
        for _ in range(301):
            self.chain.append()
        m = s.sync(self.chain)
        self.assertEqual(m.rollback, 300)
        self.assertEqual(len(s.coins()), 1)
        self.chain.blocks = []
        self.chain.append()
        m = s.sync(self.chain)
        self.assertEqual(s.coins(), [])

    def test_partial_resume_and_cancel_never_serves_balance(self):
        for _ in range(4):
            self.chain.append()
        s = self.scanner()
        s.sync(self.chain, max_blocks=2)
        self.assertEqual(s.store.tip()[0], 2)
        with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
            s.coins()
        with self.assertRaisesRegex(ValueError, "SCAN_CANCELLED"):
            s.sync(self.chain, cancel=lambda: True)
        s.sync(self.chain)
        self.assertEqual(s.store.tip()[0], 4)

    def test_malformed_block_rolls_back_whole_block(self):
        good = payment(self.accounts[0])
        bad = payment(self.accounts[0], 2)
        del bad["vin"][0]["prevout"]
        self.chain.append([good, bad])
        s = self.scanner()
        with self.assertRaisesRegex(ValueError, "PREVOUT_DATA_REQUIRED"):
            s.sync(self.chain)
        self.assertEqual(s.store.tip()[0], 0)
        self.assertEqual(s.store.db.execute("SELECT count(*) FROM coins").fetchone()[0], 0)
        self.chain.blocks[0]["tx"].pop()
        s.sync(self.chain)
        self.assertEqual(len(s.coins()), 1)

    def test_authenticated_checkpoint_and_identity(self):
        self.chain.append([payment(self.accounts[0])])
        s = self.scanner()
        s.sync(self.chain)
        encrypted = s.checkpoint(PASSWORD)
        other = self.scanner("restored.db")
        other.restore(encrypted, PASSWORD)
        with self.assertRaises(ValueError):
            other.coins()
        self.chain.fetches = 0
        other.sync(self.chain)
        self.assertEqual(self.chain.fetches, 0)
        self.assertEqual(other.coins(), s.coins())
        wrong = self.scanner("wrong.db", Keyring(b"x" * 32).accounts())
        with self.assertRaisesRegex(ValueError, "CHECKPOINT_RESTORE"):
            wrong.restore(encrypted, PASSWORD)
        corrupted = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        empty = self.scanner("empty.db")
        with self.assertRaises(ValueError):
            empty.restore(corrupted, PASSWORD)

    def test_checkpoint_reorg_below_checkpoint(self):
        self.chain.append([payment(self.accounts[0])])
        self.chain.append()
        s = self.scanner()
        s.sync(self.chain)
        other = self.scanner("copy.db")
        other.restore(s.checkpoint(PASSWORD), PASSWORD)
        self.chain.blocks = []
        self.chain.append()
        other.sync(self.chain)
        self.assertEqual(other.coins(), [])

    def test_multiple_accounts_precompute_once(self):
        b = Keyring(b"b" * 32).accounts()[0]
        self.chain.append([payment(self.accounts[0])])
        s = self.scanner(accounts=(*self.accounts, b))
        m = s.sync(self.chain)
        self.assertEqual(m.prepared, 1)
        self.assertEqual(m.ecdh, 2)
        self.assertEqual(len(s.coins()), 1)

    def test_label_lookup_bounded_and_large_table(self):
        account = self.accounts[0]
        key = 31
        vin = Input("ab" * 32, 0, p2wpkh(key), witness=(b"x", pub(key)), secret=key)
        from wam_sp.core import address

        outputs = send([vin], [address(account.scan_secret, account.spend_public, 999)])
        r = Receiver(account.scan_secret, account.spend_public, range(1, 1000))
        self.assertEqual(r.scan_prepared(prepare([vin]), outputs)[0].label, 999)
        self.assertLessEqual(r.operations, 4)
        r = Receiver(
            account.scan_secret, account.spend_public, [7], replace(DEFAULT, max_curve_operations=1)
        )
        with self.assertRaisesRegex(ValueError, "SCAN_WORK_LIMIT"):
            r.scan_prepared(prepare([vin]), outputs)

    def test_wallet_contacts_selection_locks_and_cluster_policy(self):
        self.chain.append(
            [payment(self.accounts[0], 1, None, 0.001), payment(self.accounts[0], 2, 7, 0.001)]
        )
        s = self.scanner()
        s.sync(self.chain)
        w = Wallet(s)
        dest = Keyring(b"d" * 32).accounts()[0].payment_code()
        cid = w.add_contact("Local contact", dest)
        self.assertNotIn("code", w.contacts()[0])
        intent = w.contact_intent(cid, 150000)
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_SINGLE_CLUSTER_FUNDS"):
            w.propose([intent], 1000)
        proposal = w.propose([intent], 1000, allow_cluster_merge=True)
        self.assertEqual(len(proposal.coins), 2)
        self.assertEqual(w.balance()["available_atoms"], 0)
        with self.assertRaises(ValueError):
            Wallet(s).propose([Intent(dest, 1000)], 1000)
        w.release_draft(proposal.token)
        self.assertEqual(w.balance()["available_atoms"], 200000)
        proposal = w.propose([intent], 1000, allow_cluster_merge=True)
        w.mark_signed(proposal.token)
        with self.assertRaises(ValueError):
            w.release_draft(proposal.token)

    def test_no_private_keys_in_sqlite_or_repr(self):
        self.chain.append([payment(self.accounts[0])])
        s = self.scanner()
        s.sync(self.chain)
        data = (self.path / "wallet.db").read_bytes()
        for secret in (self.accounts[0].scan_secret, self.ring.spend_secret(0)):
            self.assertNotIn(format(secret, "064x").encode(), data)
            self.assertNotIn(format(secret, "064x"), repr(self.accounts[0]))

    def test_cache_bound_and_context_changes(self):
        for i in range(1, 6):
            self.chain.append([payment(self.accounts[0], i)])
        s = self.scanner(limits=replace(DEFAULT, max_cache=2))
        s.sync(self.chain)
        self.assertEqual(s.store.db.execute("SELECT count(*) FROM cache").fetchone()[0], 2)
        s.rescan()
        m = s.sync(self.chain)
        self.assertGreater(m.prepared, 0)

    def test_rotation_and_label_expansion_rewind(self):
        # Publish a label only after registering it; then recover prior history after importing metadata.
        self.ring.add_label(0, 9)
        self.chain.append([payment(self.ring.accounts()[0], 1, 9)])
        s = self.scanner()
        s.sync(self.chain)
        self.assertEqual(s.coins(), [])
        s.reconfigure(self.ring.accounts())
        self.assertEqual(s.store.tip()[0], 0)
        s.sync(self.chain)
        self.assertEqual(len(s.coins()), 1)
        self.ring.rotate(2)
        s.reconfigure(self.ring.accounts())
        self.assertEqual(s.store.tip()[0], 1)
        self.chain.append([payment(self.ring.accounts()[1], 2)])
        s.sync(self.chain)
        self.assertEqual(len(s.coins()), 2)
        with self.assertRaisesRegex(ValueError, "OLD_ACCOUNTS_REQUIRED"):
            s.reconfigure((self.ring.accounts()[1],))

    def test_tip_changes_during_scan_cannot_serve_stale_coins(self):
        self.chain.append([payment(self.accounts[0])])
        s = self.scanner()
        original = self.chain.call
        calls = 0

        def unstable(method, params=None):
            nonlocal calls
            if method == "getbestblockhash":
                calls += 1
                if calls == 2:
                    self.chain.append()
            return original(method, params)

        self.chain.call = unstable
        with self.assertRaisesRegex(ValueError, "CHAIN_CHANGED_RETRY"):
            s.sync(self.chain)
        with self.assertRaisesRegex(ValueError, "SCAN_NOT_CURRENT"):
            s.coins()
        self.chain.call = original
        s.sync(self.chain)
        self.assertEqual(len(s.coins()), 1)

    def test_reorg_limit_fails_without_partial_rollback(self):
        for _ in range(4):
            self.chain.append()
        s = self.scanner(limits=replace(DEFAULT, max_reorg=2))
        s.sync(self.chain)
        tip = s.store.tip()
        self.chain.blocks = []
        with self.assertRaisesRegex(ValueError, "REORG_LIMIT_RESCAN_REQUIRED"):
            s.sync(self.chain)
        self.assertEqual(s.store.tip(), tip)
        s.rescan()
        s.sync(self.chain)
        self.assertEqual(s.coins(), [])

    def test_cache_binds_witness_across_reorg(self):
        tx = payment(self.accounts[0])
        self.chain.append([tx])
        s = self.scanner()
        s.sync(self.chain)
        self.chain.blocks = []
        changed = copy.deepcopy(tx)
        changed["vin"][0]["txinwitness"][0] = "01" + changed["vin"][0]["txinwitness"][0][2:]
        self.chain.append([changed])
        m = s.sync(self.chain)
        self.assertEqual(m.rollback, 1)
        self.assertEqual(m.cache_hits, 0)
        self.assertEqual(m.prepared, 1)
        self.assertEqual(len(s.coins()), 1)

    def test_ambiguous_broadcast_keeps_reservations(self):
        from wam_sp.wallet import Signer
        from devtools.errors import HarnessError

        self.chain.append([payment(self.accounts[0])])
        s = self.scanner()
        s.sync(self.chain)
        wallet = Wallet(s)
        destination = Keyring(b"d" * 32).accounts()[0].payment_code()
        intent = Intent(destination, 50000)
        proposal = wallet.propose([intent], 1000)
        signer = Signer(self.ring)
        signed = signer.sign(signer.prepare(proposal), [intent], 1000)
        calls = []
        coin = proposal.coins[0]

        class RPC:
            def attest(self):
                pass

            def call(self, method, params=None):
                calls.append(method)
                if method == "gettxout":
                    return {"value": 0.001, "scriptPubKey": {"hex": "5120" + coin["public_key"]}}
                if method == "testmempoolaccept":
                    return [{"allowed": True}]
                if method == "sendrawtransaction":
                    raise HarnessError("RPC_TRANSPORT")
                raise ValueError("UNEXPECTED_RPC")

        with self.assertRaises(HarnessError):
            wallet.broadcast(signed, proposal.token, RPC())
        self.assertEqual(calls.count("sendrawtransaction"), 1)
        self.assertEqual(
            s.store.db.execute("SELECT state FROM reservations").fetchone()[0], "uncertain"
        )
        with self.assertRaises(ValueError):
            wallet.release_draft(proposal.token)
