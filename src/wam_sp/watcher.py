"""Regtest-only full-node scanner. Atomic local journal; no spend secret persisted."""

import json
import os
from pathlib import Path
import tempfile
from decimal import Decimal
from .core import Input, HRP, pub, scan, scalar

GENESIS = "b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d"
MAX_JOURNAL = 16 * 1024 * 1024


def private_json(path, value):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("UNSAFE_PATH")
    if os.name == "posix" and path.parent.stat().st_mode & 0o077:
        raise ValueError("PRIVATE_DIRECTORY_REQUIRED")
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_private(path):
    path = Path(path)
    if (
        path.is_symlink()
        or (os.name == "posix" and path.stat().st_mode & 0o077)
        or path.stat().st_size > MAX_JOURNAL
    ):
        raise ValueError("UNSAFE_STATE")
    return json.loads(path.read_text())


class Watcher:
    """Keep this object and its file private: scan keys reveal incoming payment history."""

    def __init__(self, path, scan_secret, spend_public, labels=()):
        self.path, self.scan_secret, self.spend_public = (
            Path(path),
            scalar(scan_secret),
            spend_public,
        )
        self.labels = list(dict.fromkeys(labels))
        self.identity = {
            "version": 1,
            "network": GENESIS,
            "hrp": HRP,
            "scan_public": pub(scan_secret).hex(),
            "spend_public": spend_public.hex(),
            "labels": self.labels,
        }
        self.blocks = []
        if self.path.exists():
            data = read_private(self.path)
            if data["identity"] != self.identity:
                raise ValueError("STATE_WALLET_MISMATCH")
            self.blocks = data["blocks"]

    def save(self):
        value = {"identity": self.identity, "blocks": self.blocks}
        if len(json.dumps(value)) > MAX_JOURNAL:
            raise ValueError("JOURNAL_LIMIT")
        private_json(self.path, value)

    def coins(self):
        received, spent = {}, set()
        for block in self.blocks:
            for record in block["received"]:
                received[(record["txid"], record["vout"])] = record
            spent.update(tuple(p) for p in block["spent"])
        return [v for k, v in received.items() if k not in spent]

    def sync(self, rpc):
        rpc.attest()
        target = rpc.call("getbestblockhash")
        height = rpc.call("getblockcount")
        while self.blocks and (
            self.blocks[-1]["height"] > height
            or rpc.call("getblockhash", [self.blocks[-1]["height"]]) != self.blocks[-1]["hash"]
        ):
            self.blocks.pop()
        self.save()
        start = self.blocks[-1]["height"] + 1 if self.blocks else 1
        for h in range(start, height + 1):
            blockhash = rpc.call("getblockhash", [h])
            block = rpc.call("getblock", [blockhash, 3])
            previous = self.blocks[-1]["hash"] if self.blocks else GENESIS
            if block["previousblockhash"] != previous:
                raise ValueError("CHAIN_CHANGED_RETRY")
            received, spent = [], []
            for tx in block["tx"]:
                if "coinbase" in tx["vin"][0]:
                    continue
                spent.extend([i["txid"], i["vout"]] for i in tx["vin"])
                candidates = [
                    o
                    for o in tx["vout"]
                    if o["scriptPubKey"]["hex"].startswith("5120")
                    and len(o["scriptPubKey"]["hex"]) == 68
                ]
                if not candidates:
                    continue
                if any("prevout" not in i for i in tx["vin"]):
                    raise ValueError("PREVOUT_DATA_REQUIRED")
                inputs = [
                    Input(
                        i["txid"],
                        i["vout"],
                        bytes.fromhex(i["prevout"]["scriptPubKey"]["hex"]),
                        bytes.fromhex(i.get("scriptSig", {}).get("hex", "")),
                        tuple(bytes.fromhex(w) for w in i.get("txinwitness", [])),
                    )
                    for i in tx["vin"]
                ]
                found = scan(
                    inputs,
                    [bytes.fromhex(o["scriptPubKey"]["hex"][4:]) for o in candidates],
                    self.scan_secret,
                    self.spend_public,
                    self.labels,
                )
                for match in found:
                    o = candidates[match.output_index]
                    atoms = Decimal(str(o["value"])) * 100_000_000
                    if atoms != atoms.to_integral_value():
                        raise ValueError("INVALID_AMOUNT")
                    received.append(
                        {
                            "txid": tx["txid"],
                            "vout": o["n"],
                            "atoms": int(atoms),
                            "public_key": match.public_key.hex(),
                            "tweak": format(match.tweak, "064x"),
                            "label": match.label,
                            "k": match.k,
                        }
                    )
            self.blocks.append(
                {"height": h, "hash": blockhash, "received": received, "spent": spent}
            )
            self.save()
        if rpc.call("getbestblockhash") != target:
            raise ValueError("CHAIN_CHANGED_RETRY")
        return self.coins()
