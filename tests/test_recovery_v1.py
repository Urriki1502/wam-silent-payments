import json
from pathlib import Path
import tempfile
import unittest
from wam_sp.keystore import Keyring, seal, derive
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet, Intent, Signer
from wam_sp import backup
from wam_sp.descriptors import Descriptor
from wam_sp.adapters.descriptor import export, parse, checksum
from wam_sp.hd import ExtendedPrivate, HARDENED
from wam_sp.privacy import RedactedLog
from test_scanner_wallet import Chain, payment

PASSWORD = b"recovery synthetic passphrase"


class RecoveryV1(unittest.TestCase):
    def test_delete_database_restore_history_labels_spendability(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wallet.db"
            ring = Keyring(bytes(range(32)))
            ring.add_label(0, 7)
            scanner = Scanner(path, ring.accounts())
            chain = Chain()
            chain.append([payment(ring.accounts()[0], label=7)])
            scanner.sync(chain)
            wallet = Wallet(scanner)
            destination = Keyring(b"x" * 32).accounts()[0].payment_code()
            wallet.add_contact("Merchant", destination)
            original_coins = scanner.coins()
            original_history = wallet.history()
            original_balance = wallet.balance()
            envelope = backup.create(ring, scanner, PASSWORD)
            scanner.close()
            path.unlink()
            restored, recovered = backup.restore(envelope, PASSWORD, path)
            self.addCleanup(recovered.close)
            recovered.sync(chain)
            rw = Wallet(recovered)
            self.assertEqual(recovered.coins(), original_coins)
            self.assertEqual(rw.history(), original_history)
            self.assertEqual(rw.balance(), original_balance)
            self.assertEqual(restored.accounts(), ring.accounts())
            self.assertEqual(len(rw.contacts()), 1)
            proposal = rw.propose([Intent(destination, 50000)], 1000)
            signer = Signer(restored)
            signed = signer.sign(signer.prepare(proposal), proposal.intents, 1000)
            from wam_sp.psbt import PSBT

            self.assertTrue(PSBT.decode(signed).finalize())

    def test_old_keyring_derivation_migration_preserves_ownership(self):
        from wam_sp.watcher import GENESIS

        seed = bytes(range(32))
        old = {
            "version": 2,
            "network": GENESIS,
            "seed": seed.hex(),
            "epochs": {"0": {"birthday": 1, "labels": [7]}},
        }
        ring = Keyring.restore(seal(json.dumps(old).encode(), PASSWORD, b"keys"), PASSWORD)
        self.assertEqual(ring.algorithm, "legacy-v2")
        self.assertEqual(ring.spend_secret(0), derive(seed, 0, "spend"))
        self.assertEqual(
            Keyring.restore(ring.backup(PASSWORD), PASSWORD).accounts(), ring.accounts()
        )

    def test_descriptor_draft_and_checksum(self):
        ring = Keyring(bytes(range(32)))
        ring.add_label(0, 7)
        a = ring.accounts()[0]
        descriptor = Descriptor(a, origin="deadbeef/352h/1h/0h")
        raw = export(descriptor)
        result = parse(raw)
        self.assertEqual(result.descriptor.account.spend_public, a.spend_public)
        self.assertEqual(result.descriptor.account.labels, tuple(range(1, 8)))
        self.assertIsNone(result.spend_secret)
        full = parse(export(descriptor, ring.spend_secret(0)))
        self.assertEqual(full.spend_secret, ring.spend_secret(0))
        base = raw.split("#")[0] + "&other=9"
        self.assertEqual(parse(base + "#" + checksum(base)).annotations["other"], 9)
        for suffix in ("?bh=01", "?bh=1&bh=2", "?Bh=1", "?ml=4294967295"):
            text = raw.split("?")[0] + suffix
            with self.assertRaises(ValueError):
                parse(text + "#" + checksum(text))
        text = "wpkh(0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)?bh=150000"
        self.assertEqual(checksum(text), "8kehtsrj")

    def test_bip32_vector_one(self):
        root = ExtendedPrivate.master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(
            root.secret.hex(), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        )
        self.assertEqual(
            root.chain_code.hex(),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        )
        self.assertEqual(
            root.child(HARDENED).secret.hex(),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        )

    def test_logging_refuses_sensitive_fields(self):
        import io

        stream = io.StringIO()
        logger = RedactedLog(stream, debug=True)
        for key in (
            "seed",
            "private_key",
            "scan_secret",
            "spend_secret",
            "shared_secret",
            "backup",
            "address",
            "txid",
            "error",
        ):
            with self.assertRaises(ValueError):
                logger.emit("scan_complete", **{key: "secret"})
        logger.emit("scan_complete", height=1, blocks=1)
        self.assertNotIn("secret", stream.getvalue())

    def test_wrong_password_no_database_created(self):
        with tempfile.TemporaryDirectory() as d:
            ring = Keyring()
            s = Scanner(Path(d) / "one.db", ring.accounts())
            self.addCleanup(s.close)
            encrypted = backup.create(ring, s, PASSWORD)
            target = Path(d) / "two.db"
            with self.assertRaises(ValueError):
                backup.restore(encrypted, b"wrong password sufficiently long", target)
            self.assertFalse(target.exists())
