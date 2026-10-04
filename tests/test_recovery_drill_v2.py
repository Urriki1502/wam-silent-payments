import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from test_scanner_wallet import Chain, payment
from wam_sp import backup
from wam_sp.adapters.pay import Merchant
from wam_sp.api import SilentWallet
from wam_sp.keystore import Keyring, seal, unseal
from wam_sp.psbt import PSBT
from wam_sp.wallet import Signer


PASSWORD = b"recovery drill v2 synthetic password"


def private_directory(path):
    path.mkdir()
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


class RecoveryDrillV2(unittest.TestCase):
    def test_new_machine_restore_recovers_multi_epoch_metadata_locks_and_spendability(
        self,
    ):
        ring = Keyring(bytes(range(32)))
        chain = Chain()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = private_directory(root / "old-host")
            new = private_directory(root / "new-host")

            wallet = SilentWallet(old / "wallet.db", ring.accounts())
            merchant = Merchant(wallet)

            merchant.create_intent(100_000, confirmations=1)
            first_label = wallet.scanner.accounts[0].labels[-1]
            ring.add_label(0, first_label)

            first_account = wallet.scanner.accounts[0]
            chain.append([payment(first_account, 1, label=first_label)])
            wallet.scan(chain)
            merchant.refresh()

            ring.rotate(2)
            wallet.scanner.reconfigure(ring.accounts())
            allocated = wallet.create_labeled_address("Rotated epoch", epoch=1, label=9)
            self.assertEqual(allocated["label"], 9)
            ring.add_label(1, 9)

            second_account = next(a for a in wallet.scanner.accounts if a.epoch == 1)
            chain.append([payment(second_account, 2, label=9)])
            wallet.scan(chain)

            contact_code = Keyring(b"c" * 32).accounts()[0].payment_code()
            wallet.wallet.add_contact("Recovery contact", contact_code)

            coins = wallet.scanner.coins()
            self.assertEqual(len(coins), 2)
            manual_token = wallet.wallet.lock([(coins[0]["txid"], coins[0]["vout"])])

            expected = {
                "accounts": ring.accounts(),
                "payments": wallet.list_payments(),
                "history": wallet.history(),
                "balance": wallet.get_balance(),
                "events": merchant.events(),
                "local": {
                    table: [
                        tuple(row)
                        for row in wallet.scanner.store.db.execute(
                            "SELECT * FROM " + table + " ORDER BY rowid"
                        )
                    ]
                    for table in (
                        "contacts",
                        "reservations",
                        "labels",
                        "intents",
                        "outbox",
                    )
                },
            }
            self.assertEqual(expected["balance"]["reserved_atoms"], 100_000)
            self.assertEqual(expected["balance"]["available_atoms"], 100_000)
            self.assertTrue(expected["events"])

            envelope = wallet.backup(ring, PASSWORD)
            wallet.close()
            (old / "wallet.db").unlink()

            restored_ring, restored_wallet = SilentWallet.restore(
                envelope,
                PASSWORD,
                new / "wallet.db",
            )
            self.addCleanup(restored_ring.close)
            self.addCleanup(restored_wallet.close)

            restored_wallet.scan(chain)

            self.assertEqual(restored_ring.accounts(), expected["accounts"])
            self.assertEqual(restored_wallet.list_payments(), expected["payments"])
            self.assertEqual(restored_wallet.history(), expected["history"])
            self.assertEqual(restored_wallet.get_balance(), expected["balance"])
            self.assertEqual(Merchant(restored_wallet).events(), expected["events"])

            for table, rows in expected["local"].items():
                recovered = [
                    tuple(row)
                    for row in restored_wallet.scanner.store.db.execute(
                        "SELECT * FROM " + table + " ORDER BY rowid"
                    )
                ]
                self.assertEqual(recovered, rows)

            with self.assertRaisesRegex(ValueError, "LOCK_NOT_MANUAL"):
                restored_wallet.wallet.unlock("not-" + manual_token)

            destination = Keyring(b"d" * 32).accounts()[0].payment_code()
            proposal = restored_wallet.construct_spend([(destination, 50_000)], 1_000)
            signer = Signer(restored_ring)
            signed = signer.sign(signer.prepare(proposal), proposal.intents, 1_000)
            self.assertTrue(PSBT.decode(signed).finalize())

        ring.close()

    def test_invalid_local_state_restore_removes_partial_database(self):
        ring = Keyring(bytes(range(32)))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = private_directory(root / "source")
            target_dir = private_directory(root / "target")
            wallet = SilentWallet(source_dir / "wallet.db", ring.accounts())
            self.addCleanup(wallet.close)

            envelope = wallet.backup(ring, PASSWORD)
            document = json.loads(unseal(envelope, PASSWORD, b"recovery"))
            payload = document["payload"]
            payload["local"]["reservations"].append(["00" * 32, 0, "synthetic", "invalid-state", 1])
            document["checksum"] = hashlib.sha256(backup.canonical(payload)).hexdigest()
            malformed = seal(backup.canonical(document), PASSWORD, b"recovery")

            target = target_dir / "wallet.db"
            with self.assertRaisesRegex(ValueError, "RECOVERY_STATE_INVALID"):
                SilentWallet.restore(malformed, PASSWORD, target)
            self.assertFalse(target.exists())

        ring.close()


if __name__ == "__main__":
    unittest.main()
