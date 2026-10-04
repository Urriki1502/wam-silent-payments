import base64
import io
from pathlib import Path
import tempfile
import unittest

from test_scanner_wallet import Chain, payment
from wam_sp import backup
from wam_sp.keystore import Keyring, export_scan
from wam_sp.privacy import RedactedLog
from wam_sp.scanner import Scanner
from wam_sp.wallet import Wallet


PASSWORD = b"privacy at rest synthetic password"


def encodings(secret):
    value = bytes(secret)
    return (
        value,
        value.hex().encode(),
        base64.b64encode(value),
        str(int.from_bytes(value, "big")).encode(),
    )


class PrivacyAtRestContract(unittest.TestCase):
    def test_database_and_encrypted_exports_do_not_expose_private_key_material(self):
        seed = bytes(range(32))
        ring = Keyring(seed)
        accounts = ring.accounts()
        scan_secret = accounts[0].scan_secret.to_bytes(32, "big")
        spend_secret = ring.spend_secret(0).to_bytes(32, "big")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.db"
            scanner = Scanner(path, accounts)
            self.addCleanup(scanner.close)

            chain = Chain()
            chain.append([payment(accounts[0])])
            scanner.sync(chain)

            destination = Keyring(b"d" * 32).accounts()[0].payment_code()
            Wallet(scanner).add_contact("Synthetic merchant", destination)

            database = path.read_bytes()
            key_backup = ring.backup(PASSWORD)
            scan_backup = export_scan(accounts, PASSWORD)
            recovery = backup.create(ring, scanner, PASSWORD)

            for secret in (seed, scan_secret, spend_secret):
                for encoded in encodings(secret):
                    self.assertNotIn(encoded, database)
                    self.assertNotIn(encoded, key_backup)
                    self.assertNotIn(encoded, scan_backup)
                    self.assertNotIn(encoded, recovery)

        ring.close()

    def test_operational_logger_rejects_wallet_identifiers_and_secrets(self):
        stream = io.StringIO()
        logger = RedactedLog(stream, debug=True)

        for field in (
            "txid",
            "address",
            "balance",
            "seed",
            "scan_secret",
            "spend_secret",
            "shared_secret",
            "psbt",
            "backup",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "LOG_FIELD_DENIED"):
                    logger.emit("scan_complete", **{field: 1})

        logger.emit("scan_complete", height=1, blocks=1, transactions=1)
        self.assertEqual(
            stream.getvalue(),
            '{"blocks":1,"event":"scan_complete","height":1,"transactions":1}\n',
        )


if __name__ == "__main__":
    unittest.main()
