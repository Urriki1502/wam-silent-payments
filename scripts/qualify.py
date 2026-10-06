#!/usr/bin/env python3
"""Run all internal gates on trusted local hardware, never GitHub-hosted mining."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from devtools.qualification import source_digest, release_gate

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    python = sys.executable
    binary = env.get("WAMD")
    digest = env.get("WAMD_SHA256")
    if not binary or not digest:
        raise SystemExit("WAMD_AND_WAMD_SHA256_REQUIRED")
    node_args = ["--wamd", binary, "--sha256", digest]
    paths = ["src", "devtools", "tests", "fuzz", "benchmarks", "examples", "scripts"]
    commands = {
        "format": ([python, "-m", "ruff", "format", "--check", *paths], []),
        "lint": ([python, "-m", "ruff", "check", *paths], []),
        "unit": ([python, "-m", "devtools.selftest"], []),
        "conformance": (
            [
                python,
                "-m",
                "wam_sp.conformance",
                "test",
                "--contract-only",
                "--output",
                "reports/conformance.json",
            ],
            ["conformance.json"],
        ),
        "differential": (
            [python, "-m", "devtools.differential", "--cases", "10000"],
            ["differential.json"],
        ),
        "fuzz": (
            [
                python,
                "fuzz/run.py",
                "fuzz/corpus",
                "-artifact_prefix=fuzz/regressions/",
                "-runs=1010000",
                "-max_len=4096",
                "-rss_limit_mb=1024",
            ],
            ["fuzz-counts.json"],
        ),
        "real_node": ([python, "-m", "devtools.real_node", *node_args], ["real-node.json"]),
        "interop": ([python, "-m", "devtools.interop", *node_args], []),
        "regtest": ([python, "-m", "devtools.regtest", *node_args], []),
        "benchmark": ([python, "benchmarks/scanner.py"], ["benchmark.json"]),
        "dependencies": (
            [
                python,
                "-m",
                "pip_audit",
                "-r",
                "requirements-lock.txt",
                "--format",
                "json",
                "--output",
                "reports/dependency-audit.json",
            ],
            ["dependency-audit.json"],
        ),
        "build": ([python, "-m", "devtools.build_check"], ["build.json"]),
    }
    report = {
        "profile": "WSP-1",
        "source_sha256": source_digest(ROOT),
        "gates": {},
        "started_unix": int(time.time()),
    }
    output = ROOT / "reports/qualification.json"
    output.parent.mkdir(exist_ok=True)
    for name, (command, artifacts) in commands.items():
        log = "qualification-" + name + ".log"
        start = time.monotonic()
        with (ROOT / "reports" / log).open("wb") as stream:
            try:
                code = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=env,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=1200,
                ).returncode
            except subprocess.TimeoutExpired:
                code = 124
        if name == "fuzz" and code == 0:
            counts = json.loads((ROOT / "reports/fuzz-counts.json").read_text())
            if counts["executions"] < 1000000 or any(n <= 0 for n in counts["targets"].values()):
                code = 1
        if name == "differential" and code == 0:
            counts = json.loads((ROOT / "reports/differential.json").read_text())
            if counts["passed"] < 10000 or counts["failed"]:
                code = 1
        hashes = {
            str(Path("reports") / f): hashlib.sha256(
                (ROOT / "reports" / f).read_bytes()
            ).hexdigest()
            for f in [log, *artifacts]
            if (ROOT / "reports" / f).exists()
        }
        report["gates"][name] = {
            "exit_code": code,
            "seconds": round(time.monotonic() - start, 3),
            "reports": hashes,
        }
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"gate": name, "exit_code": code}), flush=True)
        if code:
            return code
    if source_digest(ROOT) != report["source_sha256"]:
        raise SystemExit("SOURCE_CHANGED_DURING_QUALIFICATION")
    report["finished_unix"] = int(time.time())
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(release_gate(ROOT)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
