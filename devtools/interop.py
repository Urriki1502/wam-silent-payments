"""Two real WAM nodes, two independent keyrings, PSBT roundtrip and branch replacement."""

import argparse
from dataclasses import asdict
import json
import secrets
from wam_sp import Input, pub, send
from wam_sp.codec import encode
from wam_sp.core import N
from wam_sp.transaction import p2wpkh, signed_single_input
from wam_sp.keystore import Keyring
from wam_sp.scanner import Scanner, atoms
from wam_sp.wallet import Wallet, Intent, Signer
from wam_sp.psbt import PSBT
from wam_sp.adapters.sp_psbt import core_v0_export
from .node import Node, wait_until
from .privacy import PrivateWorkspace
from .regtest import require
from .offline_process import sign_in_process


def run(binary, digest):
    passed = []
    active = "SP2-001"
    scanners = []
    nodes = []
    metrics = {}
    with PrivateWorkspace() as ws:
        try:
            nodes = [Node(binary, digest, ws.path, n) for n in range(2)]
            a, b = nodes
            a.start()
            b.start()
            sender = secrets.randbelow(N - 1) + 1
            script = p2wpkh(sender)
            mining = encode("wamrt", script[2:], 0, bech32m=False)
            blocks = a.rpc.call("generatetoaddress", [110, mining])
            a.connect(b)
            a.sync_with(b)
            require(a.rpc.call("getblockcount") == b.rpc.call("getblockcount") == 110)
            passed.append(active)
            active = "SP2-002"
            alice = Keyring()
            alice.add_label(0, 7)
            bob = Keyring()
            aa, bb = alice.accounts()[0], bob.accounts()[0]
            coinbase = a.rpc.call("getblock", [blocks[0], 2])["tx"][0]
            coin = next(o for o in coinbase["vout"] if o["scriptPubKey"]["hex"] == script.hex())
            amount = atoms(coin["value"])
            vin = Input(
                coinbase["txid"], coin["n"], script, witness=(bytes(72), pub(sender)), secret=sender
            )
            codes = [aa.payment_code(), aa.payment_code(), aa.payment_code(7), bb.payment_code()]
            values = [250000, 250000, 100000, 350000]
            outputs = send([vin], codes)
            funding = signed_single_input(
                vin,
                amount,
                [(v, b"\x51\x20" + p) for v, p in zip(values, outputs)]
                + [(amount - sum(values) - 2000, script)],
                sender,
            )
            a.rpc.call("sendrawtransaction", [funding])
            funding_block = a.rpc.call("generatetoaddress", [1, mining])[0]
            a.sync_with(b)
            sa = Scanner(ws.path / "alice.db", alice.accounts())
            sb = Scanner(ws.path / "bob.db", bob.accounts())
            scanners.extend([sa, sb])
            metrics["cold_alice"] = asdict(sa.sync(a.rpc))
            sb.sync(b.rpc)
            wa, wb = Wallet(sa), Wallet(sb)
            require(
                wa.balance()["confirmed_atoms"] == 600000
                and wb.balance()["confirmed_atoms"] == 350000
            )
            passed.append(active)
            active = "SP2-003"
            contact = wa.add_contact("Bob", bb.payment_code())
            intent = wa.contact_intent(contact, 350000)
            proposal = wa.propose([intent], 2000)
            require(len(proposal.coins) == 2)
            signer = Signer(alice)
            prepared = signer.prepare(proposal)
            password = b"synthetic offline request password"
            request = wa.export_request(proposal, password)
            decoded = b.rpc.call(
                "decodepsbt",
                [
                    PSBT(
                        PSBT.decode(prepared.psbt).tx, PSBT.decode(prepared.psbt).utxos, version=0
                    ).base64()
                ],
            )
            require(len(decoded["tx"]["vin"]) == 2)
            signed = sign_in_process(ws.path, alice, request, password)
            psbt = PSBT.decode(signed)
            require(psbt.tx == PSBT.decode(prepared.psbt).tx)
            finalized = b.rpc.call("finalizepsbt", [core_v0_export(psbt).base64(), True])
            require(finalized["complete"] and finalized["hex"] == psbt.finalize().hex())
            require(a.rpc.call("testmempoolaccept", [[finalized["hex"]]])[0]["allowed"])
            txid = wa.broadcast(signed, proposal.token, a.rpc)
            wait_until(lambda: txid in b.rpc.call("getrawmempool"))
            b.rpc.call("generatetoaddress", [1, mining])
            b.sync_with(a)
            sa.sync(a.rpc)
            sb.sync(b.rpc)
            require(
                wa.balance()["confirmed_atoms"] == 248000
                and wb.balance()["confirmed_atoms"] == 700000
            )
            passed.append(active)
            active = "SP2-004"
            intent = Intent(aa.payment_code(7), 100000)
            proposal = wb.propose([intent], 2000)
            signer_b = Signer(bob)
            prepared = signer_b.prepare(proposal)
            wb.mark_signed(proposal.token)
            signed = signer_b.sign(prepared, [intent], 2000)
            txid = wb.broadcast(signed, proposal.token, b.rpc)
            wait_until(lambda: txid in a.rpc.call("getrawmempool"))
            a.rpc.call("generatetoaddress", [1, mining])
            a.sync_with(b)
            sa.sync(a.rpc)
            sb.sync(b.rpc)
            require(
                wa.balance()["confirmed_atoms"] == 348000
                and wb.balance()["confirmed_atoms"] == 598000
            )
            passed.append(active)
            active = "SP2-005"
            # Native wallet receives a standard Taproot spend; it does NOT understand silent codes.
            native = b.wallet("native-receiver")
            native_address = native.call("getnewaddress", ["", "bech32m"])
            native_script = bytes.fromhex(
                native.call("getaddressinfo", [native_address])["scriptPubKey"]
            )
            c = sb.coins()[0]
            from wam_sp.core import Match, spending_key

            m = Match(
                c["vout"], bytes.fromhex(c["public_key"]), int(c["tweak"], 16), c["label"], c["k"]
            )
            key = spending_key(bob.spend_secret(c["epoch"]), m)
            from wam_sp.psbt import Tx

            native_psbt = PSBT(
                Tx(((c["txid"], c["vout"]),), ((c["atoms"] - 1000, native_script),)),
                ((c["atoms"], b"\x51\x20" + m.public_key),),
            ).sign([key])
            final = a.rpc.call("finalizepsbt", [core_v0_export(native_psbt).base64(), True])
            require(final["complete"])
            txid = b.rpc.call("sendrawtransaction", [final["hex"]])
            wait_until(lambda: txid in a.rpc.call("getrawmempool"))
            a.rpc.call("generatetoaddress", [1, mining])
            a.sync_with(b)
            require(atoms(native.call("getbalance")) == c["atoms"] - 1000)
            sa.sync(a.rpc)
            sb.sync(b.rpc)
            passed.append(active)
            active = "SP2-006"
            password = b"synthetic demo backup passphrase"
            encrypted = alice.backup(password)
            restored = Keyring.restore(encrypted, password)
            require(
                [x.identity() for x in restored.accounts()]
                == [x.identity() for x in alice.accounts()]
            )
            checkpoint = sa.checkpoint(password)
            sc = Scanner(ws.path / "checkpoint.db", restored.accounts())
            scanners.append(sc)
            sc.restore(checkpoint, password)
            require(sc.sync(b.rpc).blocks == 0 and sc.coins() == sa.coins())
            sr = Scanner(ws.path / "genesis.db", restored.accounts())
            scanners.append(sr)
            sr.sync(b.rpc)
            require(sr.coins() == sa.coins())
            passed.append(active)
            active = "SP2-007"
            before = sa.coins()
            sa.close()
            scanners.remove(sa)
            a.stop()
            a.start()
            a.connect(b)
            a.sync_with(b)
            sa = Scanner(ws.path / "alice.db", alice.accounts())
            scanners.append(sa)
            metrics["warm_restart"] = asdict(sa.sync(a.rpc))
            require(sa.coins() == before and sa.metrics.blocks == 0)
            passed.append(active)
            active = "SP2-008"
            a.rpc.call("generatetoaddress", [8, mining])
            a.sync_with(b)
            sa.sync(a.rpc)
            sb.sync(b.rpc)  # Original chain height 122: twelve blocks after fork point.
            b.rpc.call("setnetworkactive", [False])
            a.rpc.call("invalidateblock", [funding_block])
            replacement_output = send([vin], [aa.payment_code()])[0]
            replacement = signed_single_input(
                vin,
                amount,
                [(100000, b"\x51\x20" + replacement_output), (amount - 150000, script)],
                sender,
            )
            require(a.rpc.call("testmempoolaccept", [[replacement]])[0]["allowed"])
            a.rpc.call("sendrawtransaction", [replacement])
            a.rpc.call("generatetoaddress", [14, mining])
            ma = sa.sync(a.rpc)
            require(ma.rollback == 12)
            require(Wallet(sa).balance()["confirmed_atoms"] == 100000)
            b.rpc.call("setnetworkactive", [True])
            a.connect(b)
            a.sync_with(b)
            mb = sb.sync(b.rpc)
            require(mb.rollback == 12 and Wallet(sb).balance()["confirmed_atoms"] == 0)
            metrics["branch_reorg"] = {"alice_rollback": ma.rollback, "bob_rollback": mb.rollback}
            sc.sync(b.rpc)
            require(sc.coins() == sa.coins())
            passed.append(active)
            active = "SP2-009"
            expected = sa.coins()
            sa.rescan()
            metrics["rescan"] = asdict(sa.sync(a.rpc))
            require(sa.coins() == expected)
            passed.append(active)
            active = "SP2-010"
            for s, ring in ((sa, alice), (sb, bob)):
                data = s.store.path.read_bytes()
                for ac in ring.accounts():
                    require(format(ac.scan_secret, "064x").encode() not in data)
                    require(format(ring.spend_secret(ac.epoch), "064x").encode() not in data)
            require(all(not (n.path / "regtest" / "debug.log").exists() for n in nodes))
            passed.append(active)
        except Exception:
            return {"suite": "wam-sp-v2-interop", "passed": passed, "failed": [active]}
        finally:
            for s in scanners:
                s.close()
            for n in nodes:
                n.stop()
    return {"suite": "wam-sp-v2-interop", "passed": passed, "failed": [], "metrics": metrics}


def main():
    p = argparse.ArgumentParser(description="Two-node disposable WAM regtest interop")
    p.add_argument("--wamd", required=True)
    p.add_argument("--sha256", required=True)
    args = p.parse_args()
    try:
        report = run(args.wamd, args.sha256)
    except Exception:
        report = {"suite": "wam-sp-v2-interop", "passed": [], "failed": ["SP2-000"]}
    print(json.dumps(report, separators=(",", ":")))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
