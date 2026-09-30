"""Nine coverage-guided targets. Synthetic fixtures only, never real wallet data."""

import json
from wam_sp.core import Input, decode_address, label_scalar, pub
from wam_sp.chain import RawTransaction
from wam_sp.scanner import validate_transaction_shape, transaction_inputs
from wam_sp.adapters.descriptor import parse, checksum
from wam_sp.psbt import PSBT
from wam_sp.adapters.psbt_document import Document
from wam_sp.backup import parse_document
from wam_sp.state import decode_checkpoint

NAMES = (
    "address",
    "transaction",
    "eligible_input",
    "scanner",
    "descriptor",
    "psbt",
    "backup",
    "label",
    "database_decoder",
)
COUNTS = [0] * 9


def one(data):
    if not data:
        return
    target = data[0] % len(NAMES)
    body = data[1:]
    COUNTS[target] += 1
    try:
        if target == 0:
            code = body.decode("ascii")
            decode_address(code)
        elif target == 1:
            tx = RawTransaction.parse(body)
            assert RawTransaction.parse(tx.serialize()) == tx
        elif target == 2:
            split = body[:1]
            kind = split[0] % 3 if split else 0
            script = (
                body[1:35]
                if kind == 0
                else b"\x51\x20" + body[1:33]
                if kind == 1
                else b"\x00\x14" + body[1:21]
            )
            witness = tuple(body[i : i + 33] for i in range(35, len(body), 33))
            key = Input("ab" * 32, 0, script, body[1:100], witness).public_key()
            assert key is None or len(key) == 33
        elif target == 3:
            tx = json.loads(body)
            validate_transaction_shape(tx)
            if "coinbase" not in tx["vin"][0]:
                transaction_inputs(tx)
        elif target == 4:
            text = body.decode("ascii")
            # Both literal checksum boundary and deeper grammar are exercised.
            if body[:1] == b"!":
                text = text[1:] + "#" + checksum(text[1:])
            parse(text)
        elif target == 5:
            try:
                p = PSBT.decode(body)
                assert PSBT.decode(p.encode()) == p
            except ValueError:
                pass  # The independent document adapter also accepts unresolved outputs.
            document = Document.decode(body)
            document.validate()
            assert Document.decode(document.encode()).encode() == document.encode()
        elif target == 6:
            parse_document(body)
        elif target == 7:
            if len(body) > 64:
                raise ValueError("LABEL_LIMIT")
            label = int.from_bytes(body, "big")
            value = label_scalar(11, label)
            assert 0 < value and len(pub(value)) == 33
        else:
            decode_checkpoint(body, "synthetic")
    except (ValueError, UnicodeError, RecursionError):
        return
