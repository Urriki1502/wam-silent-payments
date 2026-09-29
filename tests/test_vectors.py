import io
import json
from hashlib import sha256
from pathlib import Path
import unittest
from coincurve import PublicKeyXOnly
from wam_sp import core

VECTORS = json.loads((Path(__file__).parent / "vectors/bip352.json").read_text())


def compact(f):
    b = f.read(1)
    if not b:
        return 0
    n = b[0]
    return n if n < 253 else int.from_bytes(f.read({253: 2, 254: 4, 255: 8}[n]), "little")


def vin(item):
    f = io.BytesIO(bytes.fromhex(item["txinwitness"]))
    witness = tuple(f.read(compact(f)) for _ in range(compact(f)))
    return core.Input(
        item["txid"],
        item["vout"],
        bytes.fromhex(item["prevout"]["scriptPubKey"]["hex"]),
        bytes.fromhex(item["scriptSig"]),
        witness,
        int(item["private_key"], 16) if "private_key" in item else None,
    )


def vector_check(self, case):
    for test in case["sending"]:
        g, e = test["given"], test["expected"]
        inputs = list(map(vin, g["vin"]))
        self.assertEqual([p.hex() for i in inputs if (p := i.public_key())], e["input_pub_keys"])
        recipients = [r["address"] for r in g["recipients"] for _ in range(r.get("count", 1))]
        for r in g["recipients"]:
            a, b = core.decode_address(r["address"], "sp")
            self.assertEqual(a.format().hex(), r["scan_pub_key"])
            self.assertEqual(b.format().hex(), r["spend_pub_key"])
        try:
            outputs = [p.hex() for p in core.send(inputs, recipients, "sp")]
        except ValueError as error:
            self.assertIn(str(error), {"INPUT_SUM_ZERO", "NO_ELIGIBLE_INPUTS", "RECIPIENT_LIMIT"})
            outputs = []
        self.assertTrue(any(set(outputs) == set(expected) for expected in e["outputs"]))
        if outputs:
            total, h = core.input_context(inputs)
            a = int(e["input_private_key_sum"], 16)
            self.assertEqual(core.pub(a), total.format())
            for index, r in enumerate(g["recipients"]):
                key, _ = core.decode_address(r["address"], "sp")
                self.assertEqual(
                    key.multiply(core.ser(h * a % core.N)).format().hex(),
                    e["shared_secrets"][index],
                )
    for test in case["receiving"]:
        g, e = test["given"], test["expected"]
        inputs = list(map(vin, g["vin"]))
        bs = int(g["key_material"]["scan_priv_key"], 16)
        bd = int(g["key_material"]["spend_priv_key"], 16)
        addresses = [core.address(bs, core.pub(bd), hrp="sp")]
        addresses += [core.address(bs, core.pub(bd), m, "sp") for m in g["labels"]]
        self.assertEqual(addresses, e["addresses"])
        found = core.scan(
            inputs, [bytes.fromhex(x) for x in g["outputs"]], bs, core.pub(bd), g["labels"]
        )
        if found:
            total, h = core.input_context(inputs)
            self.assertEqual(total.format().hex(), e["input_pub_key_sum"])
            self.assertEqual(total.multiply(core.ser(h)).format().hex(), e["tweak"])
            self.assertEqual(
                total.multiply(core.ser(h * bs % core.N)).format().hex(), e["shared_secret"]
            )
        actual = []
        for match in found:
            key = core.spending_key(bd, match)
            msg, aux = sha256(b"message").digest(), sha256(b"random auxiliary data").digest()
            sig = key.sign_schnorr(msg, aux)
            self.assertTrue(PublicKeyXOnly(match.public_key).verify(sig, msg))
            actual.append(
                {
                    "pub_key": match.public_key.hex(),
                    "priv_key_tweak": match.tweak.to_bytes(32, "big").hex(),
                    "signature": sig.hex(),
                }
            )
        if "outputs" in e:
            self.assertEqual(
                {frozenset(x.items()) for x in actual}, {frozenset(x.items()) for x in e["outputs"]}
            )
        else:
            self.assertEqual(len(actual), e["n_outputs"])


class Vectors(unittest.TestCase):
    pass


for index, case in enumerate(VECTORS):
    setattr(Vectors, f"test_bip352_{index + 1:03}", lambda self, c=case: vector_check(self, c))
