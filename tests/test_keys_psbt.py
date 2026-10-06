from pathlib import Path
import random
import tempfile
import unittest
from wam_sp.keystore import Keyring, export_scan, import_scan, unseal
from wam_sp.core import pub
from wam_sp.psbt import PSBT, Tx
from wam_sp.wallet import Intent, Proposal, Prepared, Signer

PASSWORD = b"correct horse regtest battery"


def fixture():
    ring = Keyring(bytes(range(32)))
    a = ring.accounts()[0]
    tweak = 17
    d = ring.spend_secret(0) + tweak
    from wam_sp.core import N

    c = {
        "txid": "ab" * 32,
        "vout": 0,
        "account": a.account_id,
        "epoch": 0,
        "atoms": 150000,
        "public_key": pub(d % N)[1:].hex(),
        "tweak": format(tweak, "064x"),
        "label": None,
        "k": 0,
    }
    recipient = Keyring(b"\x99" * 32).accounts()[0].payment_code()
    proposal = Proposal((c,), (Intent(recipient, 50000),), 1000, 0, "synthetic")
    return ring, proposal


class KeysAndPSBT(unittest.TestCase):
    def test_encrypted_deterministic_restore_rotation(self):
        ring = Keyring(bytes(range(32)))
        first = ring.accounts()[0].payment_code()
        ring.add_label(0, 7)
        ring.rotate(100)
        backup = ring.backup(PASSWORD)
        copy = Keyring.restore(backup, PASSWORD)
        self.assertEqual(
            [a.identity() for a in ring.accounts()], [a.identity() for a in copy.accounts()]
        )
        self.assertNotEqual(first, copy.accounts()[1].payment_code())
        self.assertNotIn(bytes(range(32)).hex().encode(), backup)
        self.assertNotEqual(backup, ring.backup(PASSWORD))
        accounts = import_scan(export_scan(ring.accounts(), PASSWORD), PASSWORD)
        self.assertEqual(accounts, ring.accounts())
        self.assertFalse(hasattr(accounts[0], "spend_secret"))

    def test_backup_tamper_wrong_password_purpose(self):
        ring = Keyring()
        raw = ring.backup(PASSWORD)
        for bad in (raw[:-1] + bytes([raw[-1] ^ 1]), raw[:8], b"x" * len(raw)):
            with self.assertRaises(ValueError):
                Keyring.restore(bad, PASSWORD)
        with self.assertRaises(ValueError):
            Keyring.restore(raw, b"wrong password long enough")
        with self.assertRaises(ValueError):
            unseal(raw, PASSWORD, b"scan")
        with self.assertRaises(ValueError):
            ring.backup(b"short")

    def test_change_label_not_publishable(self):
        ring = Keyring()
        with self.assertRaises(ValueError):
            ring.accounts()[0].payment_code(0)
        with self.assertRaises(ValueError):
            ring.accounts()[0].payment_code(7)
        ring.add_label(0, 7)
        self.assertTrue(ring.accounts()[0].payment_code(7).startswith("wamrtsp"))

    def test_psbt_roundtrip_sign_finalize(self):
        ring, proposal = fixture()
        signer = Signer(ring)
        prepared = signer.prepare(proposal)
        p = PSBT.decode(prepared.psbt)
        self.assertEqual(p.encode(), prepared.psbt)
        self.assertEqual(PSBT.from_base64(p.base64()).encode(), prepared.psbt)
        signed = signer.sign(prepared, proposal.intents, 1000)
        raw = PSBT.decode(signed).finalize()
        self.assertTrue(raw.startswith(b"\x02\x00\x00\x00\x00\x01"))
        self.assertNotIn(proposal.intents[0].code.encode(), prepared.psbt)

    def test_signer_rejects_destination_fee_input_changes(self):
        ring, p = fixture()
        signer = Signer(ring)
        prepared = signer.prepare(p)
        psbt = PSBT.decode(prepared.psbt)
        wrong = PSBT(
            Tx(psbt.tx.inputs, ((49000, psbt.tx.outputs[0][1]), *psbt.tx.outputs[1:])), psbt.utxos
        )
        with self.assertRaisesRegex(ValueError, "PSBT_INTENT_MISMATCH"):
            signer.sign(Prepared(p, wrong.encode()), p.intents, 1000)
        with self.assertRaisesRegex(ValueError, "INTENT_NOT_APPROVED"):
            signer.sign(prepared, (Intent(p.intents[0].code, 49000),), 1000)
        with self.assertRaisesRegex(ValueError, "FEE_NOT_APPROVED"):
            signer.sign(prepared, p.intents, 999)
        wrong = PSBT(psbt.tx, ((150001, psbt.utxos[0][1]),))
        with self.assertRaisesRegex(ValueError, "PSBT_INTENT_MISMATCH"):
            signer.sign(Prepared(p, wrong.encode()), p.intents, 1000)

    def test_signature_mutation(self):
        ring, p = fixture()
        s = Signer(ring)
        psbt = PSBT.decode(s.sign(s.prepare(p), p.intents, 1000))
        changed = bytes([psbt.signatures[0][0] ^ 1]) + psbt.signatures[0][1:]
        with self.assertRaises(ValueError):
            PSBT(psbt.tx, psbt.utxos, (changed,)).finalize()

    def test_duplicate_and_unknown_psbt_fields(self):
        ring, p = fixture()
        raw = Signer(ring).prepare(p).psbt
        for bad in (raw + b"\x00", b"psbt\xff\xfd\x01\x00\x00", b"psbt\xff\x01\xfc\x00\x00"):
            with self.assertRaises(ValueError):
                PSBT.decode(bad)
        with self.assertRaises(ValueError):
            Tx((("ab" * 32, 0), ("ab" * 32, 0)), ((1000, b"\x51"),)).serialize()

    def test_bounded_psbt_mutational_fuzz_1000(self):
        ring, p = fixture()
        raw = Signer(ring).prepare(p).psbt
        rng = random.Random(371)
        for _ in range(1000):
            bad = bytearray(raw)
            for _ in range(1 + rng.randrange(4)):
                bad[rng.randrange(len(bad))] ^= rng.randrange(1, 256)
            if rng.randrange(3) == 0:
                bad = bad[: rng.randrange(len(bad))]
            try:
                parsed = PSBT.decode(bytes(bad))
                reparsed = PSBT.decode(parsed.encode())
                self.assertEqual(parsed, reparsed)
            except ValueError:
                pass
        with self.assertRaisesRegex(ValueError, "PSBT_LIMIT"):
            PSBT.decode(b"x" * 1_000_001)

    def test_backup_file_permissions_and_overwrite(self):
        from wam_sp.keystore import save_private, load_private
        import os

        ring = Keyring()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "keys.enc"
            data = ring.backup(PASSWORD)
            save_private(path, data)
            self.assertEqual(load_private(path), data)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                save_private(path, data)

    def test_encrypted_offline_request_roundtrip(self):
        from wam_sp.wallet import encode_request, decode_request

        ring, proposal = fixture()
        envelope = encode_request(proposal, PASSWORD)
        restored = decode_request(envelope, PASSWORD)
        self.assertEqual(restored, proposal)
        self.assertNotIn(proposal.intents[0].code.encode(), envelope)
        signer = Signer(ring)
        signed = signer.sign(signer.prepare(restored), restored.intents, restored.fee)
        self.assertTrue(PSBT.decode(signed).finalize())
        with self.assertRaises(ValueError):
            decode_request(envelope[:-1] + bytes([envelope[-1] ^ 1]), PASSWORD)
