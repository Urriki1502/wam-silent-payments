"""Black-box contract: external implementations need no imports from wam_sp."""

import json
import os
from pathlib import Path
import selectors
import subprocess
import sys

GROUPS = (
    "Protocol",
    "Address",
    "Labels",
    "Scanner",
    "Reorg",
    "Recovery",
    "PSBT",
    "Wallet",
    "Privacy",
    "Integration",
)


class Client:
    def __init__(self, command, root):
        self.process = subprocess.Popen(
            command,
            cwd=root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.pending = b""

    def call(self, request):
        raw = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        while b"\n" not in self.pending:
            if not self.selector.select(30):
                raise ValueError("ADAPTER_TIMEOUT")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise ValueError("ADAPTER_EXIT")
            self.pending += chunk
            if len(self.pending) > 4 * 1024 * 1024:
                raise ValueError("ADAPTER_OUTPUT_LIMIT")
        line, self.pending = self.pending.split(b"\n", 1)
        answer = json.loads(line)
        if not isinstance(answer, dict) or type(answer.get("ok")) is not bool:
            raise ValueError("ADAPTER_FORMAT")
        return answer

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(3)
        self.process.stdout.close()
        self.selector.close()


def run(root, command=None):
    root = Path(root)
    counts = {g: {"passed": 0, "failed": 0} for g in GROUPS}
    failures = []
    command = command or [sys.executable, "-m", "devtools.conformance_adapter"]
    client = Client(command, root)

    def check(group, name, request, verify):
        try:
            ok = verify(client.call(request))
        except (ValueError, KeyError, TypeError, OSError):
            ok = False
        counts[group]["passed" if ok else "failed"] += 1
        if not ok:
            failures.append(name)

    try:
        vectors = json.loads((root / "tests/vectors/bip352.json").read_text())
        for n, case in enumerate(vectors):
            for i, t in enumerate(case["sending"]):
                e = t["expected"]
                check(
                    "Protocol",
                    f"BIP352-S-{n}-{i}",
                    {"op": "sending", "given": t["given"]},
                    lambda a, e=e: (
                        a["ok"]
                        and a["result"]["input_pub_keys"] == e["input_pub_keys"]
                        and any(sorted(a["result"]["outputs"]) == sorted(x) for x in e["outputs"])
                    ),
                )
                for j, r in enumerate(t["given"]["recipients"]):
                    check(
                        "Address",
                        f"BIP352-A-{n}-{i}-{j}",
                        {"op": "address", "given": {"address": r["address"], "hrp": "sp"}},
                        lambda a, r=r: (
                            a["ok"]
                            and a["result"]
                            == {
                                "scan_public": r["scan_pub_key"],
                                "spend_public": r["spend_pub_key"],
                            }
                        ),
                    )
            for i, t in enumerate(case["receiving"]):
                e = t["expected"]
                group = "Labels" if t["given"]["labels"] else "Protocol"

                def receiving(a, e=e):
                    if not a["ok"] or a["result"]["addresses"] != e["addresses"]:
                        return False
                    actual = a["result"]
                    return (
                        sorted(actual["outputs"], key=lambda x: x["pub_key"])
                        == sorted(e["outputs"], key=lambda x: x["pub_key"])
                        if "outputs" in e
                        else actual["n_outputs"] == e["n_outputs"]
                    )

                check(
                    group, f"BIP352-R-{n}-{i}", {"op": "receiving", "given": t["given"]}, receiving
                )
        for case in json.loads((root / "tests/conformance/cases.json").read_text()):

            def compare(answer, case=case):
                if case.get("reject"):
                    return answer["ok"] is False
                return answer["ok"] and all(
                    answer["result"].get(k) == v for k, v in case["expect"].items()
                )

            check(case["group"], case["id"], case["request"], compare)
    finally:
        client.close()
    conformant = not failures and all(v["passed"] and not v["failed"] for v in counts.values())
    return {
        "profile": "WSP-1",
        "contract_version": 1,
        "result": "WSP-1 CONFORMANT" if conformant else "WSP-1 NON-CONFORMANT",
        "scope": "black-box contract; full release requires additional qualification evidence",
        "groups": counts,
        "failures": failures,
        "passed": sum(v["passed"] for v in counts.values()),
        "failed": sum(v["failed"] for v in counts.values()),
    }
