import csv
from dataclasses import replace
from pathlib import Path
import unittest
from coincurve import PrivateKey
from wam_sp.core import pub, ser
from wam_sp.psbt import PSBT, Tx, _map
from wam_sp.adapters import dleq, sp_psbt
from test_keys_psbt import fixture
from wam_sp.wallet import Signer


class PSBTV2(unittest.TestCase):
    def test_dleq_official_generation(self):
        for row in csv.DictReader(
            (Path(__file__).parent / "vectors/bip374-generate.csv").read_text().splitlines()
        ):
            with self.subTest(index=row["index"]):
                args = (
                    int(row["scalar_a"], 16),
                    bytes.fromhex(row["point_B"]) if row["point_B"] != "INFINITY" else b"",
                    bytes.fromhex(row["auxrand_r"]),
                    bytes.fromhex(row["message"]) if row["message"] else None,
                    bytes.fromhex(row["point_G"]),
                )
                if row["result_proof"] == "INVALID":
                    with self.assertRaises(ValueError):
                        dleq.prove(*args)
                else:
                    self.assertEqual(dleq.prove(*args)[1].hex(), row["result_proof"])

    def test_dleq_official_verification(self):
        for row in csv.DictReader(
            (Path(__file__).parent / "vectors/bip374-verify.csv").read_text().splitlines()
        ):
            with self.subTest(index=row["index"]):

                def point(k):
                    return bytes.fromhex(row[k]) if row[k] != "INFINITY" else b""

                self.assertEqual(
                    dleq.verify(
                        point("point_A"),
                        point("point_B"),
                        point("point_C"),
                        bytes.fromhex(row["proof"]),
                        bytes.fromhex(row["message"]) if row["message"] else None,
                        point("point_G"),
                    ),
                    row["result_success"] == "TRUE",
                )

    def test_partial_combine_unknown_preservation(self):
        keys = [PrivateKey(ser(11)), PrivateKey(ser(17))]
        tx = Tx((("ab" * 32, 0), ("cd" * 32, 1)), ((19000, b"\x51\x20" + pub(29)[1:]),))
        p = PSBT(
            tx,
            tuple((10000, b"\x51\x20" + k.public_key.format()[1:]) for k in keys),
            global_extra={b"\x70x": b"unknown"},
            input_extra=({b"\x70i": b"a"}, {}),
            output_extra=({b"\x70o": b"b"},),
        )
        a = p.sign([keys[0], None])
        b = p.sign([None, keys[1]])
        with self.assertRaises(ValueError):
            a.finalize()
        combined = a.combine(b)
        self.assertTrue(combined.finalize())
        self.assertEqual(combined.global_extra, p.global_extra)
        final = combined.finalized()
        self.assertEqual(final.finalize(), combined.finalize())
        self.assertEqual(final.input_extra[0][b"\x70i"], b"a")
        self.assertEqual(PSBT.decode(final.encode()).output_extra, p.output_extra)
        bad = replace(b, global_extra={b"\x70x": b"changed"})
        with self.assertRaisesRegex(ValueError, "CONFLICT"):
            a.combine(bad)

    def test_v0_v2_duplicate_conflicts(self):
        ring, proposal = fixture()
        p = PSBT.decode(Signer(ring).prepare(proposal).psbt)
        self.assertEqual(p.version, 2)
        self.assertEqual(PSBT.decode(PSBT(p.tx, p.utxos).to_v0().encode()).tx, p.tx)
        g, ins, outs = p.maps()
        g[b"\x00"] = p.tx.serialize()
        raw = b"psbt\xff" + _map(g) + b"".join(_map(m) for m in ins + outs)
        with self.assertRaisesRegex(ValueError, "V2_UNSIGNED_TX"):
            PSBT.decode(raw)

    def test_sender_proofs_spend_tweak(self):
        ring, proposal = fixture()
        signer = Signer(ring)
        p, keys = signer._build(proposal)
        from wam_sp.core import address

        a = ring.accounts()[0]
        codes = [proposal.intents[0].code, address(a.scan_secret, a.spend_public, 0)]
        p = sp_psbt.add_sender(p, keys, codes)
        p = sp_psbt.add_spend(p, proposal.coins, ring.accounts())
        sp_psbt.verify_sender(p)
        signed = sp_psbt.sign_spend(p, {a.spend_public: ring.spend_secret(0)})
        self.assertTrue(signed.finalize())
        self.assertEqual(len(signed.signatures[0]), 65)
        final = signed.finalized()
        self.assertTrue(final.finalize())
        self.assertNotIn(b"\x20", final.input_extra[0])
        self.assertNotIn(b"\x1f" + a.spend_public, final.input_extra[0])
        extra = dict(p.input_extra[0])
        proofkey = next(k for k in extra if k[0] == 0x1E)
        extra[proofkey] = bytes(64)
        with self.assertRaisesRegex(ValueError, "DLEQ_INVALID"):
            replace(p, input_extra=(extra,)).sign(keys)

    def test_locktime_constraints(self):
        ring, proposal = fixture()
        p = PSBT.decode(Signer(ring).prepare(proposal).psbt)
        g, ins, outs = p.maps()
        ins[0][b"\x12"] = (500).to_bytes(4, "little")
        raw = b"psbt\xff" + _map(g) + b"".join(_map(m) for m in ins + outs)
        q = PSBT.decode(raw)
        self.assertEqual(q.tx.locktime, 500)
        self.assertEqual(PSBT.decode(q.encode()).tx.locktime, 500)
