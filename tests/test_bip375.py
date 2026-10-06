import base64
import json
from pathlib import Path
import unittest
from wam_sp.adapters.psbt_document import Document

VECTORS = json.loads((Path(__file__).parent / "vectors/bip375.json").read_text())


class BIP375(unittest.TestCase):
    pass


def check_valid(self, case):
    raw = base64.b64decode(case["psbt"])
    doc = Document.decode(raw)
    doc.validate(case.get("checks"), strict_inputs=False)
    # Upstream vectors 2..14,17..19 use public keys whose HASH160 does
    # not match the supplied witness UTXO. Reference field checks are not
    # consensus/ownership checks: our signing boundary must reject these.
    if VECTORS["valid"].index(case) in (*range(2, 15), 17, 18, 19):
        code = (
            "TAPROOT_ORIGIN"
            if VECTORS["valid"].index(case) == 12
            else "SP_INPUT_PUBLIC_KEY_REQUIRED"
        )
        with self.assertRaisesRegex(ValueError, code):
            doc.validate()
    self.assertEqual(Document.decode(doc.encode()).global_map, doc.global_map)


def check_invalid(self, case):
    with self.assertRaises(ValueError):
        Document.decode(base64.b64decode(case["psbt"])).validate(
            case.get("checks"), strict_inputs=False
        )


for kind, function in (("valid", check_valid), ("invalid", check_invalid)):
    for index, case in enumerate(VECTORS[kind]):
        setattr(BIP375, f"test_{kind}_{index:03}", lambda self, c=case, f=function: f(self, c))
