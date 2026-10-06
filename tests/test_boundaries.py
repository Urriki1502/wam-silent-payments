import dataclasses
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from wam_sp import Input, address, pub, send, scan, spending_key
from wam_sp.core import N, label_scalar
from wam_sp.transaction import p2wpkh, signed_single_input
from wam_sp.watcher import Watcher, private_json, read_private
from devtools.errors import HarnessError, RPCError
from devtools.rpc import RPC, Cookie, endpoint


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.bs, self.bd, self.sender = 11, 29, 31
        self.vin = Input(
            "ab" * 32, 0, p2wpkh(self.sender), witness=(b"", pub(self.sender)), secret=self.sender
        )
        self.code = address(self.bs, pub(self.bd))

    def test_network_and_checksum(self):
        from wam_sp import decode_address

        with self.assertRaises(ValueError):
            decode_address(address(self.bs, pub(self.bd), hrp="sp"))
        with self.assertRaises(ValueError):
            decode_address(self.code[:-1] + ("q" if self.code[-1] != "q" else "p"))
        with self.assertRaises(ValueError):
            decode_address(self.code[:3].upper() + self.code[3:])
        self.assertEqual(decode_address(self.code.upper())[0].format(), pub(self.bs))

    def test_input_change_requires_new_outputs(self):
        before = send([self.vin], [self.code])
        after = send([dataclasses.replace(self.vin, vout=1)], [self.code])
        self.assertNotEqual(before, after)
        self.assertEqual(
            scan([dataclasses.replace(self.vin, vout=1)], before, self.bs, pub(self.bd)), []
        )

    def test_wrong_sender_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "INPUT_KEY_MISMATCH"):
            send([dataclasses.replace(self.vin, secret=37)], [self.code])

    def test_change_label_zero_always_scanned(self):
        output = send([self.vin], [address(self.bs, pub(self.bd), 0)])
        (match,) = scan([self.vin], output, self.bs, pub(self.bd))
        self.assertEqual(match.label, 0)
        self.assertEqual(spending_key(self.bd, match).public_key.format()[1:], output[0])

    def test_future_witness_skips_whole_transaction(self):
        future = Input("cd" * 32, 1, b"\x52\x20" + bytes(32))
        output = send([self.vin], [self.code])
        self.assertEqual(scan([self.vin, future], output, self.bs, pub(self.bd)), [])
        with self.assertRaisesRegex(ValueError, "INELIGIBLE_TRANSACTION"):
            send([self.vin, future], [self.code])

    def test_unknown_and_unspendable_outputs_ignored(self):
        own = send([self.vin], [self.code])[0]
        matches = scan([self.vin], [b"\xff" * 32, pub(97)[1:], own], self.bs, pub(self.bd))
        self.assertEqual([m.output_index for m in matches], [2])

    def test_duplicate_outputs_and_sequence(self):
        a, b = send([self.vin], [self.code, self.code])
        matches = scan([self.vin], [a, b, a], self.bs, pub(self.bd))
        self.assertEqual({m.output_index for m in matches}, {0, 1, 2})
        self.assertEqual([m.k for m in matches], [0, 0, 1])

    def test_scan_does_not_need_spend_secret(self):
        output = send([self.vin], [self.code])
        (match,) = scan([dataclasses.replace(self.vin, secret=None)], output, self.bs, pub(self.bd))
        with self.assertRaisesRegex(ValueError, "SPEND_KEY_MISMATCH"):
            spending_key(self.bd + 1, match)
        self.assertEqual(scan([self.vin], output, self.bs + 1, pub(self.bd)), [])

    def test_missing_first_output_stops_scan(self):
        first, second = send([self.vin], [self.code, self.code])
        self.assertEqual(scan([self.vin], [second], self.bs, pub(self.bd)), [])
        # Match before value filtering: a dust/zero-valued first output must not hide k=1.
        self.assertEqual(len(scan([self.vin], [first, second], self.bs, pub(self.bd))), 2)

    def test_wrong_key_signing_rejected(self):
        with self.assertRaisesRegex(ValueError, "INPUT_KEY_MISMATCH"):
            signed_single_input(self.vin, 10000, [(9000, p2wpkh(2))], self.sender + 1)
        with self.assertRaisesRegex(ValueError, "INVALID_FEE"):
            signed_single_input(self.vin, 10000, [(10000, p2wpkh(2))], self.sender)

    def test_scalar_and_label_bounds(self):
        for value in (0, -1, N, True, "1"):
            with self.assertRaises(ValueError):
                pub(value)
        for value in (-1, 2**32, True):
            with self.assertRaises(ValueError):
                label_scalar(self.bs, value)

    def test_private_state_and_wallet_binding(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            watcher = Watcher(path, self.bs, pub(self.bd))
            watcher.save()
            self.assertNotIn("secret", path.read_text())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "STATE_WALLET_MISMATCH"):
                Watcher(path, self.bs + 1, pub(self.bd))
            target = Path(d) / "target.json"
            private_json(target, {"sentinel": True})
            link = Path(d) / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "UNSAFE_PATH"):
                private_json(link, {})
            self.assertEqual(read_private(target), {"sentinel": True})

    def test_endpoint_and_mutation_chain_guard(self):
        for url in (
            "http://localhost:8332",
            "https://127.0.0.1:8332",
            "http://192.168.1.1:8332",
            "http://127.0.0.1:8332@evil.invalid",
            "http://127.0.0.1:8332/path",
        ):
            with self.assertRaises(HarnessError):
                endpoint(url)
        rpc = RPC("http://127.0.0.1:12345", Cookie(Path("/nonexistent")))
        with (
            patch.object(rpc, "attest", side_effect=HarnessError("CHAIN_MISMATCH")),
            patch.object(rpc, "_request") as request,
        ):
            with self.assertRaises(HarnessError):
                rpc.call("sendrawtransaction", ["secret"])
            request.assert_not_called()
        self.assertEqual(str(RPCError(-26)), "RPC_REMOTE")

    def test_report_exception_redaction(self):
        from devtools.regtest import run

        secret_text = "cookie:never-export-wallet-keys"
        with patch("devtools.regtest.Node.start", side_effect=ValueError(secret_text)):
            report = run("/unused", "0" * 64)
        self.assertNotIn(secret_text, json.dumps(report))
        self.assertEqual(report["failed"], ["SPREG-001"])
