"""Deterministic randomized differential checks against pinned upstream Python oracle."""

import random
import sys
from pathlib import Path
import unittest
from wam_sp import core
from wam_sp.transaction import p2wpkh

sys.path.insert(0, str(Path(__file__).parent / "reference"))
import reference as ref
from bitcoin_utils import COutPoint, CTxInWitness, VinInfo
from secp256k1lab.secp256k1 import GE, Scalar


def oracle_input(i):
    w = CTxInWitness()
    w.scriptWitness.stack = list(i.witness)
    return VinInfo(COutPoint(bytes.fromhex(i.txid)[::-1], i.vout), i.script_sig, w, i.script)


class Differential(unittest.TestCase):
    def test_64_generated_cases(self):
        rng = random.Random(getattr(self, "seed", 35220260929))
        for case in range(getattr(self, "case_count", 64)):
            inputs = []
            for index in range(1 + case % 4):
                secret = rng.randrange(1, core.N)
                pk = core.pub(secret)
                kind = (case + index) % 4
                if kind == 0:
                    script = p2wpkh(secret)
                    ss = b""
                    w = (b"sig", pk)
                elif kind == 1:
                    script = b"\x76\xa9\x14" + core.hash160(pk) + b"\x88\xac"
                    ss = b"\x03sig\x21" + pk + b"\x61"
                    w = ()
                elif kind == 2:
                    redeem = p2wpkh(secret)
                    script = b"\xa9\x14" + core.hash160(redeem) + b"\x87"
                    ss = b"\x16" + redeem
                    w = (b"sig", pk)
                else:
                    script = b"\x51\x20" + pk[1:]
                    ss = b""
                    w = (bytes(64),)
                inputs.append(
                    core.Input(
                        format(rng.getrandbits(256), "064x"),
                        rng.randrange(65536),
                        script,
                        ss,
                        w,
                        secret,
                    )
                )
            if case % 3 == 0:
                inputs.append(
                    core.Input("00" * 32, case, b"\x00\x20" + b"\x11" * 32, witness=(b"x",))
                )
            vin = [oracle_input(i) for i in inputs]
            eligible = [ref.get_pubkey_from_input(v) for v in vin]
            self.assertEqual(
                [p.to_bytes_compressed() for p in eligible if not p.infinity],
                [k for i in inputs if (k := i.public_key())],
            )
            wallets = [(rng.randrange(1, core.N), rng.randrange(1, core.N)) for _ in range(2)]
            recipients = []
            codes = []
            for j in range(1 + case % 6):
                bs, bd = wallets[j % 2]
                label = [None, 1, 3, 2**32 - 1][(case + j) % 4]
                code = core.address(bs, core.pub(bd), label, "sp")
                a, b = core.decode_address(code, "sp")
                self.assertEqual(
                    tuple(p.format() for p in (a, b)),
                    tuple(
                        p.to_bytes_compressed()
                        for p in ref.decode_silent_payment_address(code, "sp")
                    ),
                )
                codes.append(code)
                recipients.append(
                    {
                        "address": code,
                        "scan_pub_key": a.format().hex(),
                        "spend_pub_key": b.format().hex(),
                    }
                )
            keys = [
                (Scalar(i.secret), i.script[:2] == b"\x51\x20") for i in inputs if i.public_key()
            ]
            expected = ref.create_outputs(keys, [v.outpoint for v in vin], recipients, hrp="sp")
            actual = core.send(inputs, codes, "sp")
            self.assertEqual(set(expected), {x.hex() for x in actual})
            A = GE.sum(*(p for p in eligible if not p.infinity))
            h = ref.get_input_hash([v.outpoint for v in vin], A)
            total, actual_h = core.input_context(inputs)
            self.assertEqual(total.format(), A.to_bytes_compressed())
            self.assertEqual(actual_h, int.from_bytes(h, "big"))
            shuffled = actual + [core.pub(rng.randrange(1, core.N))[1:]]
            rng.shuffle(shuffled)
            for bs, bd in wallets:
                from wam_sp.crypto import shared_point

                self.assertEqual(
                    shared_point(core.ser(bs), core.prepare(inputs)),
                    (Scalar(bs) * Scalar.from_bytes_checked(h) * A).to_bytes_compressed(),
                )
                labels = [0, 1, 3, 2**32 - 1]
                table = {
                    (ref.generate_label(Scalar(bs), m) * ref.G)
                    .to_bytes_compressed()
                    .hex(): ref.generate_label(Scalar(bs), m).to_bytes().hex()
                    for m in labels
                }
                expected = ref.scanning(
                    Scalar(bs), GE.from_bytes_compressed(core.pub(bd)), A, h, list(shuffled), table
                )
                found = core.scan(inputs, shuffled, bs, core.pub(bd), labels)
                self.assertEqual(
                    {(x["pub_key"], x["priv_key_tweak"]) for x in expected},
                    {(x.public_key.hex(), format(x.tweak, "064x")) for x in found},
                )

    def test_nums_annex_and_scriptpath(self):
        key = core.pub(31)
        for internal in (core.NUMS, core.pub(47)[1:]):
            for annex in ((), (b"\x50annex",)):
                i = core.Input(
                    "aa" * 32,
                    1,
                    b"\x51\x20" + key[1:],
                    witness=(b"\x51", b"\xc0" + internal, *annex),
                )
                oracle = ref.get_pubkey_from_input(oracle_input(i))
                self.assertEqual(
                    i.public_key(), None if oracle.infinity else oracle.to_bytes_compressed()
                )
