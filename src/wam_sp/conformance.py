"""Forge entry point. Run from a source checkout with independently executable tests."""

import argparse
import json
from pathlib import Path
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["test"])
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--release", action="store_true", help="explicit full release gate (default)")
    p.add_argument("--contract-only", action="store_true")
    p.add_argument("--output", type=Path)
    p.add_argument("--adapter", nargs=argparse.REMAINDER)
    args = p.parse_args()
    sys.path.insert(0, str(args.root.resolve()))
    try:
        from devtools.conformance import run

        report = run(args.root, args.adapter)
        if not args.contract_only:
            from devtools.qualification import release_gate

            report["qualification"] = release_gate(args.root)
            if report["qualification"]["result"] != "PASS":
                report["result"] = "WSP-1 NON-CONFORMANT"
        else:
            report["result"] = (
                "CONTRACT PASS" if report["result"] == "WSP-1 CONFORMANT" else "CONTRACT FAIL"
            )
    except (ImportError, ValueError, OSError):
        report = {
            "profile": "WSP-1",
            "result": "WSP-1 NON-CONFORMANT",
            "error": "CONFORMANCE_INFRASTRUCTURE",
        }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, separators=(",", ":")))
    return int(report["result"] not in ("WSP-1 CONFORMANT", "CONTRACT PASS"))


if __name__ == "__main__":
    raise SystemExit(main())
