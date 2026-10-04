import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from wam_sp.core import N, pub
from wam_sp.keystore import Keyring, save_private
from wam_sp.offline_signer import run
from wam_sp.psbt import PSBT
from wam_sp.wallet import Intent, Proposal, encode_request

PASSWORD = b"offline signer v2 synthetic password"


def fixture(directory):
    directory = Path(directory)
    if os.name == "posix":
        os.chmod(directory, 0o700)

    ring = Keyring(bytes(range(32)))
    account = ring.accounts()[0]
    tweak = 17
    spend = (ring.spend_secret(0) + tweak) % N
    coin = {
        "txid": "ab" * 32,
        "vout": 0,
        "account": account.account_id,
        "epoch": 0,
        "atoms": 150000,
        "public_key": pub(spend)[1:].hex(),
        "tweak": format(tweak, "064x"),
        "label": None,
        "k": 0,
    }
    recipient = Keyring(b"\x99" * 32).accounts()[0].payment_code()
    proposal = Proposal(
        (coin,),
        (Intent(recipient, 50000),),
        1000,
        0,
        "offline-v2-synthetic",
    )

    keys = directory / "keys.enc"
    request = directory / "request.enc"
    output = directory / "signed.psbt"
    save_private(keys, ring.backup(PASSWORD))
    save_private(request, encode_request(proposal, PASSWORD))
    ring.close()
    return keys, request, output


class OfflineSignerV2(unittest.TestCase):
    def test_request_rejection_never_unlocks_spend_key(self):
        with tempfile.TemporaryDirectory() as d:
            keys, request, output = fixture(d)
            with patch("wam_sp.offline_signer.Keyring.restore") as restore:
                result = run(
                    keys,
                    request,
                    output,
                    getpass_fn=lambda _: PASSWORD.decode(),
                    input_fn=lambda _: "CANCEL",
                    print_fn=lambda *_: None,
                )
            self.assertEqual(result, 1)
            restore.assert_not_called()
            self.assertFalse(output.exists())

    def test_keyring_is_closed_during_exact_transaction_review_and_after_sign(self):
        with tempfile.TemporaryDirectory() as d:
            keys, request, output = fixture(d)
            restored = []

            def restore_keyring(*_):
                ring = Keyring(bytes(range(32)))
                restored.append(ring)
                return ring

            def approve(prompt):
                if prompt.startswith("Type REVIEW"):
                    self.assertEqual(restored, [])
                    return "REVIEW"
                match = re.fullmatch(
                    r"Type SIGN ([0-9a-f]{64}) to approve this exact prepared transaction: ",
                    prompt,
                )
                self.assertIsNotNone(match)
                self.assertEqual(len(restored), 1)
                self.assertTrue(restored[0]._closed)
                return "SIGN " + match.group(1)

            with patch(
                "wam_sp.offline_signer.Keyring.restore",
                side_effect=restore_keyring,
            ):
                result = run(
                    keys,
                    request,
                    output,
                    getpass_fn=lambda _: PASSWORD.decode(),
                    input_fn=approve,
                    print_fn=lambda *_: None,
                )

            self.assertEqual(result, 0)
            self.assertEqual(len(restored), 2)
            self.assertTrue(all(ring._closed for ring in restored))
            signed = PSBT.from_base64(output.read_text())
            self.assertTrue(signed.finalize())

    def test_wrong_fingerprint_never_reopens_keyring_for_signing(self):
        with tempfile.TemporaryDirectory() as d:
            keys, request, output = fixture(d)
            restored = []

            def restore_keyring(*_):
                ring = Keyring(bytes(range(32)))
                restored.append(ring)
                return ring

            approvals = iter(("REVIEW", "SIGN " + "00" * 32))
            with patch(
                "wam_sp.offline_signer.Keyring.restore",
                side_effect=restore_keyring,
            ):
                result = run(
                    keys,
                    request,
                    output,
                    getpass_fn=lambda _: PASSWORD.decode(),
                    input_fn=lambda _: next(approvals),
                    print_fn=lambda *_: None,
                )

            self.assertEqual(result, 1)
            self.assertEqual(len(restored), 1)
            self.assertTrue(restored[0]._closed)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
