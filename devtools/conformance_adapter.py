"""JSONL test adapter. Only synthetic fixture keys enter this test-only process."""

import io
import json
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
from wam_sp import core
from wam_sp.psbt import Reader, PSBT
from wam_sp.api import SilentWallet
from wam_sp.keystore import Keyring
from wam_sp.privacy import RedactedLog
from wam_sp.wallet import Signer
from wam_sp.watcher import GENESIS


def vin(item):
    r = Reader(bytes.fromhex(item["txinwitness"]))
    witness = tuple(r.blob() for _ in range(r.size(1000))) if r.data else ()
    r.finish()
    return core.Input(
        item["txid"],
        item["vout"],
        bytes.fromhex(item["prevout"]["scriptPubKey"]["hex"]),
        bytes.fromhex(item["scriptSig"]),
        witness,
        int(item["private_key"], 16) if "private_key" in item else None,
    )


class FixtureChain:
    def __init__(self):
        self.blocks = []

    def attest(self):
        return None

    def call(self, method, params=None):
        if method == "getbestblockhash":
            return self.blocks[-1]["hash"] if self.blocks else GENESIS
        if method == "getblockcount":
            return len(self.blocks)
        if method == "getblockhash":
            return self.blocks[params[0] - 1]["hash"] if params[0] else GENESIS
        if method == "getblock":
            return next(b for b in self.blocks if b["hash"] == params[0])
        raise ValueError("CONTRACT_METHOD")


class Adapter:
    def __init__(self, path):
        self.path = path
        self.wallet = None
        self.chain = FixtureChain()

    def close(self):
        if self.wallet:
            self.wallet.close()

    def call(self, r):
        op = r["op"]
        g = r.get("given", {})
        if op == "address":
            a, b = core.decode_address(g["address"], g.get("hrp", "wamrtsp"))
            return {"scan_public": a.format().hex(), "spend_public": b.format().hex()}
        if op == "sending":
            inputs = list(map(vin, g["vin"]))
            keys = [p.hex() for i in inputs if (p := i.public_key())]
            recipients = [r["address"] for r in g["recipients"] for _ in range(r.get("count", 1))]
            try:
                outputs = [x.hex() for x in core.send(inputs, recipients, g.get("hrp", "sp"))]
            except ValueError as e:
                if str(e) not in ("INPUT_SUM_ZERO", "NO_ELIGIBLE_INPUTS", "RECIPIENT_LIMIT"):
                    raise
                outputs = []
            return {"input_pub_keys": keys, "outputs": outputs}
        if op == "receiving":
            inputs = list(map(vin, g["vin"]))
            bs = int(g["key_material"]["scan_priv_key"], 16)
            bd = int(g["key_material"]["spend_priv_key"], 16)
            addresses = [core.address(bs, core.pub(bd), hrp="sp")] + [
                core.address(bs, core.pub(bd), m, "sp") for m in g["labels"]
            ]
            found = core.scan(
                inputs, [bytes.fromhex(x) for x in g["outputs"]], bs, core.pub(bd), g["labels"]
            )
            actual = []
            for m in found:
                key = core.spending_key(bd, m)
                sig = key.sign_schnorr(
                    sha256(b"message").digest(), sha256(b"random auxiliary data").digest()
                )
                actual.append(
                    {
                        "pub_key": m.public_key.hex(),
                        "priv_key_tweak": m.tweak.to_bytes(32, "big").hex(),
                        "signature": sig.hex(),
                    }
                )
            return {"addresses": addresses, "outputs": actual, "n_outputs": len(actual)}
        if op == "create":
            self.close()
            self.ring = Keyring(bytes.fromhex(g["seed"]))
            for label in g.get("labels", []):
                self.ring.add_label(0, label)
            self.wallet = SilentWallet(self.path / "wallet.db", self.ring.accounts())
            return {"api_version": self.wallet.api_version, "profile": self.wallet.profile}
        if op == "chain":
            self.chain.blocks = g["blocks"]
            return {"height": len(self.chain.blocks)}
        if op == "scan":
            return asdict(self.wallet.scan(self.chain))
        if op == "balance":
            return self.wallet.get_balance()
        if op == "history":
            return {"history": self.wallet.history()}
        if op == "restart":
            self.wallet.close()
            self.wallet = SilentWallet(self.path / "wallet.db", self.ring.accounts())
            return {"reopened": True}
        if op == "recover":
            encrypted = self.wallet.backup(self.ring, b"synthetic conformance password")
            self.wallet.close()
            (self.path / "wallet.db").unlink()
            self.ring, self.wallet = SilentWallet.restore(
                encrypted, b"synthetic conformance password", self.path / "wallet.db"
            )
            self.wallet.scan(self.chain)
            return self.wallet.get_balance()
        if op == "spend":
            proposal = self.wallet.construct_spend([(g["destination"], g["atoms"])], g["fee"])
            signer = Signer(self.ring)
            signed = PSBT.decode(signer.sign(signer.prepare(proposal), proposal.intents, g["fee"]))
            result = {
                "version": signed.version,
                "inputs": len(signed.tx.inputs),
                "outputs": len(signed.tx.outputs),
                "fee": sum(v for v, _ in signed.utxos) - sum(v for v, _ in signed.tx.outputs),
                "finalized": bool(signed.finalize()),
            }
            self.wallet.wallet.release_draft(proposal.token)
            return result
        if op == "psbt_reject":
            PSBT.decode(bytes.fromhex(g["hex"]))
            return {"accepted": True}
        if op == "privacy":
            stream = io.StringIO()
            log = RedactedLog(stream, debug=True)
            denied = []
            for name in g["fields"]:
                try:
                    log.emit("scan_complete", **{name: 42})
                except ValueError:
                    denied.append(name)
            return {"denied": denied, "log": stream.getvalue()}
        raise ValueError("CONTRACT_OPERATION")


def main():
    with tempfile.TemporaryDirectory(prefix="wsp-conformance-") as d:
        adapter = Adapter(Path(d))
        try:
            while True:
                line = sys.stdin.buffer.readline(4 * 1024 * 1024 + 1)
                if not line:
                    break
                if len(line) > 4 * 1024 * 1024:
                    raise ValueError("CONTRACT_LIMIT")
                try:
                    request = json.loads(line)
                    answer = {"ok": True, "result": adapter.call(request)}
                except (ValueError, TypeError, KeyError):
                    answer = {"ok": False, "error": "REJECTED"}
                print(json.dumps(answer, separators=(",", ":")), flush=True)
        finally:
            adapter.close()


if __name__ == "__main__":
    main()
