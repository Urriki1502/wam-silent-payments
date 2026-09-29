import dataclasses
import random
import unittest
from wam_sp.core import Input, NUMS, pub, send, prepare, Receiver
from wam_sp.transaction import p2wpkh
from wam_sp.scanner import transaction_inputs


class Adversarial(unittest.TestCase):
    def setUp(self):
        self.vin = Input("ab" * 32, 0, p2wpkh(31), witness=(b"x", pub(31)), secret=31)

    def test_duplicate_inputs_and_nonminimal_nested_script(self):
        with self.assertRaisesRegex(ValueError, "DUPLICATE_INPUT"):
            prepare([self.vin, self.vin])
        from wam_sp.core import hash160

        redeem = p2wpkh(31)
        spk = b"\xa9\x14" + hash160(redeem) + b"\x87"
        i = dataclasses.replace(self.vin, script=spk, script_sig=b"\x4c\x16" + redeem)
        self.assertIsNone(i.public_key())
        self.assertIsNone(dataclasses.replace(self.vin, witness=(b"x", pub(32))).public_key())

    def test_nums_control_block_and_annex_edges(self):
        base = Input("ab" * 32, 0, b"\x51\x20" + pub(31)[1:])
        self.assertIsNone(dataclasses.replace(base, witness=(b"\x51", b"\xc0" + NUMS)).public_key())
        self.assertIsNone(
            dataclasses.replace(base, witness=(b"\x51", b"\xc0" + NUMS, b"\x50")).public_key()
        )
        self.assertIsNone(
            dataclasses.replace(base, witness=(b"\x51", b"\xc0" + pub(47)[1:] + b"x")).public_key()
        )
        self.assertIsNotNone(
            dataclasses.replace(base, witness=(bytes(64), b"\x50annex")).public_key()
        )
        self.assertIsNotNone(
            dataclasses.replace(base, witness=(b"\x51", b"\xc0" + pub(47)[1:])).public_key()
        )

    def test_parser_and_work_exhaustion(self):
        i = dataclasses.replace(self.vin, script_sig=b"x" * 10001)
        with self.assertRaisesRegex(ValueError, "SCRIPT_LIMIT"):
            prepare([i])
        with self.assertRaisesRegex(ValueError, "INPUT_LIMIT"):
            prepare([self.vin] * 2049)
        with self.assertRaisesRegex(ValueError, "OUTPUT_LIMIT"):
            Receiver(11, pub(29)).scan_prepared(prepare([self.vin]), [pub(31)[1:]] * 4097)
        with self.assertRaisesRegex(ValueError, "LABEL_LIMIT"):
            Receiver(11, pub(29), range(1001))
        with self.assertRaisesRegex(ValueError, "INPUT_LIMIT"):
            transaction_inputs({"vin": [{}] * 2049})

    def test_witness_extraction_mutational_fuzz_2000(self):
        rng = random.Random(352)
        for _ in range(2000):
            script = rng.randbytes(rng.randrange(0, 90))
            ss = rng.randbytes(rng.randrange(0, 120))
            witness = tuple(rng.randbytes(rng.randrange(0, 80)) for _ in range(rng.randrange(0, 6)))
            candidate = dataclasses.replace(self.vin, script=script, script_sig=ss, witness=witness)
            key = candidate.public_key()
            self.assertTrue(key is None or len(key) == 33)

    def test_address_mutational_fuzz_1000(self):
        from wam_sp.core import address, decode_address

        good = address(11, pub(29))
        rng = random.Random(350)
        for _ in range(1000):
            bad = list(good)
            index = rng.randrange(len(bad))
            bad[index] = chr(rng.randrange(32, 127))
            value = "".join(bad)
            try:
                scan, spend = decode_address(value)
                self.assertEqual(scan.format(), pub(11))
                self.assertEqual(spend.format(), pub(29))
            except ValueError:
                pass

    def test_unsupported_witness_never_silently_changes_input_set(self):
        for version in range(2, 17):
            future = Input("cd" * 32, 1, bytes([0x50 + version, 32]) + bytes(32))
            with self.assertRaisesRegex(ValueError, "INELIGIBLE_TRANSACTION"):
                prepare([self.vin, future])

    def test_all_outpoints_include_unsupported_inputs(self):
        from wam_sp.core import address

        code = address(11, pub(29))
        ineligible = Input("00" * 32, 0, b"\x00\x20" + bytes(32))
        self.assertNotEqual(send([self.vin], [code]), send([self.vin, ineligible], [code]))
