"""Independent, unchanged BIP352 oracle; deterministic parallel campaign."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
from pathlib import Path
import sys
import time


def batch(args):
    index, count, seed = args
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from test_differential import Differential

    test = Differential("test_64_generated_cases")
    test.seed = seed + index
    test.case_count = count
    test.test_64_generated_cases()
    return count


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cases", type=int, default=10000)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--output", default="reports/differential.json")
    args = p.parse_args()
    if not 1 <= args.cases <= 1_000_000 or not 1 <= args.workers <= 16:
        raise ValueError("CAMPAIGN_LIMIT")
    start = time.monotonic()
    done = 0
    seed = 35220260930
    report = {
        "suite": "independent-bip352-differential",
        "seed": seed,
        "oracle_revision": "3a10b5b5f0a7586df8928d580a3009744ebb2079",
        "target": args.cases,
        "passed": 0,
        "failed": 0,
    }
    try:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            jobs = [
                pool.submit(batch, (i, min(64, args.cases - i * 64), seed))
                for i in range((args.cases + 63) // 64)
            ]
            for future in as_completed(jobs):
                done += future.result()
                if done % 1024 == 0:
                    print(json.dumps({"completed": done}), flush=True)
        report["passed"] = done
    except Exception:
        report["passed"] = done
        report["failed"] = 1
        raise
    finally:
        report["seconds"] = round(time.monotonic() - start, 3)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
