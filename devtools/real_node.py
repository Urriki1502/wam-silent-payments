"""Mandatory WSP-1 two-node E2E: restore, offline spend, fork and reconfirm."""

import argparse
import json
from pathlib import Path
import secrets
import time
from wam_sp.core import N, Input, pub, send
from wam_sp.codec import encode
from wam_sp.transaction import p2wpkh, signed_single_input
from wam_sp.keystore import Keyring
from wam_sp.api import SilentWallet
from wam_sp.psbt import PSBT
from wam_sp.adapters.sp_psbt import core_v0_export
from wam_sp.scanner import atoms
from .node import Node, wait_until
from .privacy import PrivateWorkspace
from .offline_process import sign_in_process
from .regtest import require


def run(binary, digest):
    passed = []
    active = "WSP-E2E-001"
    wallets = []
    nodes = []
    started = time.monotonic()
    with PrivateWorkspace() as ws:
        try:
            a, b = [Node(binary, digest, ws.path, i) for i in range(2)]
            nodes = [a, b]
            a.start()
            b.start()
            miner = secrets.randbelow(N - 1) + 1
            script = p2wpkh(miner)
            mining = encode("wamrt", script[2:], 0, False)
            blocks = a.rpc.call("generatetoaddress", [110, mining])
            a.connect(b)
            a.sync_with(b)
            ring = Keyring()
            ring.add_label(0, 7)
            recipient = ring.accounts()[0]
            destination = Keyring()
            wallet = SilentWallet(ws.path / "wallet.db", ring.accounts())
            other = SilentWallet(ws.path / "other.db", destination.accounts())
            wallets.extend([wallet, other])
            cb = a.rpc.call("getblock", [blocks[0], 2])["tx"][0]
            coin = next(o for o in cb["vout"] if o["scriptPubKey"]["hex"] == script.hex())
            amount = atoms(coin["value"])
            vin = Input(
                cb["txid"], coin["n"], script, witness=(bytes(72), pub(miner)), secret=miner
            )
            outputs = send([vin], [recipient.payment_code(), recipient.payment_code(7)])
            raw = signed_single_input(
                vin,
                amount,
                [(150000, b"\x51\x20" + o) for o in outputs] + [(amount - 302000, script)],
                miner,
            )
            txid = a.rpc.call("sendrawtransaction", [raw])
            wait_until(lambda: txid in b.rpc.call("getrawmempool"))
            wallet.scan(a.rpc, mempool=True)
            require(wallet.get_balance()["unconfirmed_atoms"] == 300000)
            a.rpc.call("generatetoaddress", [1, mining])
            a.sync_with(b)
            wallet.scan(a.rpc, mempool=True)
            require(
                wallet.get_balance()["confirmed_atoms"] == 300000
                and wallet.get_balance()["unconfirmed_atoms"] == 0
            )
            passed.append(active)
            active = "WSP-E2E-002"
            password = b"synthetic v1 recovery test passphrase"
            history = wallet.history()
            old = wallet.list_payments()
            envelope = wallet.backup(ring, password)
            wallet.close()
            wallets.remove(wallet)
            (ws.path / "wallet.db").unlink()
            ring, wallet = SilentWallet.restore(envelope, password, ws.path / "wallet.db")
            wallets.append(wallet)
            wallet.scan(b.rpc)
            require(wallet.history() == history and wallet.list_payments() == old)
            wallet.close()
            wallets.remove(wallet)
            wallet = SilentWallet(ws.path / "wallet.db", ring.accounts())
            wallets.append(wallet)
            require(wallet.scan(a.rpc).blocks == 0)
            passed.append(active)
            active = "WSP-E2E-003"
            # B stays at the pre-spend tip and cannot receive the pending spend.
            b.rpc.call("setnetworkactive", [False])
            proposal = wallet.construct_spend(
                [(destination.accounts()[0].payment_code(), 50000)], 1000
            )
            request = wallet.export_signing_request(proposal, password)
            signed = PSBT.decode(sign_in_process(ws.path, ring, request, password))
            require(signed.version == 2)
            core = core_v0_export(signed)
            decoded = a.rpc.call("decodepsbt", [core.base64()])
            require(decoded["tx"]["txid"] == signed.txid())
            finalized = a.rpc.call("finalizepsbt", [core.base64(), True])
            require(finalized["complete"] and finalized["hex"] == signed.finalize().hex())
            spend = wallet.broadcast(signed.encode(), proposal.token, a.rpc)
            wallet.scan(a.rpc, mempool=True)
            require(
                wallet.get_balance()["pending_spent_atoms"] == 150000
                and wallet.get_balance()["unconfirmed_atoms"] == 99000
            )
            a.rpc.call("generatetoaddress", [1, mining])
            wallet.scan(a.rpc)
            other.scan(a.rpc)
            require(
                wallet.get_balance()["confirmed_atoms"] == 249000
                and other.get_balance()["confirmed_atoms"] == 50000
            )
            passed.append(active)
            active = "WSP-E2E-004"
            b.rpc.call("generatetoaddress", [2, mining])
            b.rpc.call("setnetworkactive", [True])
            a.connect(b)
            a.sync_with(b)
            metrics = wallet.scan(a.rpc, mempool=True)
            other.scan(b.rpc)
            require(
                metrics.rollback == 1
                and wallet.get_balance()["confirmed_atoms"] == 300000
                and other.get_balance()["confirmed_atoms"] == 0
            )
            wait_until(lambda: spend in a.rpc.call("getrawmempool"))
            a.rpc.call("generatetoaddress", [1, mining])
            a.sync_with(b)
            wallet.scan(a.rpc)
            other.scan(b.rpc)
            require(
                wallet.get_balance()["confirmed_atoms"] == 249000
                and other.get_balance()["confirmed_atoms"] == 50000
            )
            require(len(wallet.history()) == 2)
            passed.append(active)
            active = "WSP-E2E-005"
            # Actual disconnect/reconnect plus replacement chains at each required depth.
            depths = {}
            branch_mining = encode("wamrt", p2wpkh(secrets.randbelow(N - 1) + 1)[2:], 0, False)
            for depth in (1, 12, 100, 300):
                a.sync_with(b)
                a.rpc.call("getblockcount")
                b.rpc.call("setnetworkactive", [False])
                a.rpc.call("generatetoaddress", [depth, mining])
                wallet.scan(a.rpc)
                b.rpc.call("generatetoaddress", [depth + 1, branch_mining])
                b.rpc.call("setnetworkactive", [True])
                a.connect(b)
                a.sync_with(b)
                metrics = wallet.scan(a.rpc)
                if metrics.rollback != depth or wallet.get_balance()["confirmed_atoms"] != 249000:
                    raise AssertionError(
                        "DEEP_REORG_" + str(depth) + "_ACTUAL_" + str(metrics.rollback)
                    )
                depths[str(depth)] = metrics.rollback
            passed.append(active)
            active = "WSP-E2E-006"
            before = wallet.list_payments()
            a.stop()
            a.start()
            a.connect(b)
            a.sync_with(b)
            require(wallet.scan(a.rpc).blocks == 0 and wallet.list_payments() == before)
            passed.append(active)
            active = "WSP-E2E-007"
            # Exercise production transport and the actual separately packaged SDK.
            from wam_sp.rpc import RPC, Cookie
            from wam_sp.adapters.sdk import SDKChain
            from wam_sdk.client import WamClient
            from wam_sdk.config import Config, Network, CookieAuth

            local = RPC(a.rpc.url, Cookie(a.cookie_path))
            require(wallet.scan(local).blocks == 0)
            sdk = SDKChain(WamClient(Config(a.rpc.url, Network.REGTEST, CookieAuth(a.cookie_path))))
            require(
                wallet.scan(sdk).blocks == 0 and wallet.get_balance()["confirmed_atoms"] == 249000
            )
            passed.append(active)
        except Exception as exc:
            # Only exception type and fixed stage; never secrets or RPC messages.
            return {
                "suite": "wsp-real-node",
                "passed": passed,
                "failed": [active],
                "error_type": type(exc).__name__,
                "check": str(exc)
                if isinstance(exc, AssertionError) and str(exc).startswith("DEEP_REORG_")
                else "FAILED",
            }
        finally:
            for wallet in wallets:
                wallet.close()
            for node in nodes:
                node.stop()
    return {
        "suite": "wsp-real-node",
        "passed": passed,
        "failed": [],
        "real_reorg_depths": depths,
        "seconds": round(time.monotonic() - started, 3),
        "core_version": "0.1.11",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--wamd", required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--output", default="reports/real-node.json")
    args = p.parse_args()
    report = run(args.wamd, args.sha256)
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
