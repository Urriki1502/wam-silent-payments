from pathlib import Path
import json
from wam_sp.core import address, pub
from wam_sp.psbt import PSBT, Tx
from wam_sp.descriptors import Descriptor
from wam_sp.keystore import Keyring
from wam_sp.adapters.descriptor import export
from wam_sp.store import TABLES
from wam_sp.backup import canonical
import hashlib

root = Path("fuzz/corpus")
root.mkdir(exist_ok=True)
ring = Keyring(bytes(range(32)))
p = PSBT(
    Tx((("ab" * 32, 0),), ((1000, b"\x51\x20" + pub(17)[1:]),)),
    ((2000, b"\x51\x20" + pub(11)[1:]),),
)
tx = {
    "txid": "ab" * 32,
    "vin": [
        {"txid": "cd" * 32, "vout": 0, "prevout": {"scriptPubKey": {"hex": "0014" + "ab" * 20}}}
    ],
    "vout": [{"n": 0, "value": "0.001", "scriptPubKey": {"hex": "5120" + pub(11)[1:].hex()}}],
}
seeds = {
    0: address(11, pub(29)).encode(),
    1: p.tx.serialize(),
    2: b"\x01" + pub(11)[1:] + bytes(64),
    3: json.dumps(tx).encode(),
    4: b"!" + export(Descriptor(ring.accounts()[0])).split("#")[0].encode(),
    5: p.encode(),
    6: canonical({"payload": {}, "checksum": hashlib.sha256(b"{}").hexdigest()}),
    7: bytes(4),
    8: json.dumps(
        {"schema": 3, "identity": "synthetic", "tables": {t: [] for t in TABLES}}
    ).encode(),
}
for index, data in seeds.items():
    (root / str(index)).write_bytes(bytes([index]) + data)
