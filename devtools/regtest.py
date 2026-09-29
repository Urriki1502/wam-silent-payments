"""Executable local demo; public output is restricted to fixed test IDs and status."""

import argparse
import json
import secrets
from decimal import Decimal
from wam_sp import Input, Match, address, pub, send, spending_key
from wam_sp.core import N
from wam_sp.codec import encode
from wam_sp.transaction import p2wpkh, signed_single_input
from wam_sp.watcher import Watcher, private_json, read_private
from .node import Node
from .privacy import PrivateWorkspace


def require(condition):
    if not condition:
        raise AssertionError("CHECK_FAILED")


def run(binary, digest):
    passed = []
    active = "SPREG-001"
    with PrivateWorkspace() as workspace:
        node = Node(binary, digest, workspace.path, 0)
        try:
            node.start()
            rpc = node.rpc
            require(rpc.call("getconnectioncount") == 0)
            passed.append(active)
            active = "SPREG-002"
            sender, bs, bd = [secrets.randbelow(N - 1) + 1 for _ in range(3)]
            script = p2wpkh(sender)
            mining = encode("wamrt", script[2:], 0, bech32m=False)
            blocks = rpc.call("generatetoaddress", [110, mining])
            coinbase = rpc.call("getblock", [blocks[0], 2])["tx"][0]
            output = next(o for o in coinbase["vout"] if o["scriptPubKey"]["hex"] == script.hex())
            amount = int(Decimal(str(output["value"])) * 100_000_000)
            txin = Input(
                coinbase["txid"], output["n"], script, witness=(b"", pub(sender)), secret=sender
            )
            codes = [address(bs, pub(bd)), address(bs, pub(bd), 7)]
            outputs = send([txin], codes)
            require(outputs[0] != outputs[1])
            raw = signed_single_input(
                txin,
                amount,
                [
                    (100_000, b"\x51\x20" + outputs[0]),
                    (120_000, b"\x51\x20" + outputs[1]),
                    (amount - 221_000, script),
                ],
                sender,
            )
            require(rpc.call("testmempoolaccept", [[raw]])[0]["allowed"])
            rpc.call("sendrawtransaction", [raw])
            payment_block = rpc.call("generatetoaddress", [1, mining])[0]
            passed.append(active)
            active = "SPREG-003"
            watch = Watcher(workspace.path / "watch.json", bs, pub(bd), [7])
            coins = watch.sync(rpc)
            require(len(coins) == 2 and sum(c["atoms"] for c in coins) == 220_000)
            require({c["label"] for c in coins} == {None, 7})
            passed.append(active)
            active = "SPREG-004"
            node.stop()
            node.start()
            restarted = Watcher(workspace.path / "watch.json", bs, pub(bd), [7])
            require(restarted.sync(rpc) == coins)
            state = (workspace.path / "watch.json").read_text()
            require(format(bs, "064x") not in state and format(bd, "064x") not in state)
            require((workspace.path / "watch.json").stat().st_mode & 0o077 == 0)
            passed.append(active)
            active = "SPREG-005"
            # Disposable, synthetic plaintext backup ONLY, erased at demo exit.
            backup = {
                "version": 1,
                "network": "wam-regtest",
                "scan": format(bs, "064x"),
                "spend": format(bd, "064x"),
                "labels": [7],
            }
            private_json(workspace.path / "backup.json", backup)
            restored = read_private(workspace.path / "backup.json")
            recovery = Watcher(
                workspace.path / "recovery.json",
                int(restored["scan"], 16),
                pub(int(restored["spend"], 16)),
                restored["labels"],
            )
            require(recovery.sync(rpc) == coins)
            passed.append(active)
            active = "SPREG-006"
            c = coins[0]
            match = Match(
                c["vout"], bytes.fromhex(c["public_key"]), int(c["tweak"], 16), c["label"], c["k"]
            )
            key = spending_key(int(restored["spend"], 16), match)
            spendin = Input(c["txid"], c["vout"], b"\x51\x20" + match.public_key)
            spendraw = signed_single_input(
                spendin,
                c["atoms"],
                [(c["atoms"] - 1000, script)],
                int.from_bytes(key.secret, "big"),
                taproot=True,
            )
            damaged = bytearray.fromhex(spendraw)
            damaged[-5] ^= 1  # Last Schnorr signature byte, before locktime.
            require(not rpc.call("testmempoolaccept", [[damaged.hex()]])[0]["allowed"])
            require(rpc.call("testmempoolaccept", [[spendraw]])[0]["allowed"])
            rpc.call("sendrawtransaction", [spendraw])
            spendblock = rpc.call("generatetoaddress", [1, mining])[0]
            require(len(watch.sync(rpc)) == 1)
            passed.append(active)
            active = "SPREG-007"
            rpc.call("invalidateblock", [spendblock])
            require(len(watch.sync(rpc)) == 2)
            rpc.call("invalidateblock", [payment_block])
            require(watch.sync(rpc) == [])
            require(Watcher(workspace.path / "watch.json", bs, pub(bd), [7]).sync(rpc) == [])
            passed.append(active)
            active = "SPREG-008"
            branch = rpc.call("generatetoaddress", [2, mining])
            require(branch[0] != payment_block)
            require(len(watch.sync(rpc)) == 1)
            require(watch.blocks[-1]["hash"] == rpc.call("getbestblockhash"))
            passed.append(active)
            active = "SPREG-009"
            require(rpc.call("getconnectioncount") == 0)
            require(not (node.path / "regtest" / "debug.log").exists())
            passed.append(active)
        except Exception:
            return {"suite": "wam-sp-regtest", "passed": passed, "failed": [active]}
        finally:
            node.stop()
    return {"suite": "wam-sp-regtest", "passed": passed, "failed": []}


def main():
    parser = argparse.ArgumentParser(description="Disposable WAM regtest Silent Payments demo")
    parser.add_argument("--wamd", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        report = run(args.wamd, args.sha256)
    except Exception:
        report = {"suite": "wam-sp-regtest", "passed": [], "failed": ["SPREG-000"]}
    print(json.dumps(report, separators=(",", ":")))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
