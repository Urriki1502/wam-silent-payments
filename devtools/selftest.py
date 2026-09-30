"""No raw test exceptions, paths, keys, addresses or transaction IDs in reports."""

import contextlib
import io
import json
from pathlib import Path
import unittest


def main():
    root = Path(__file__).resolve().parent.parent
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite = unittest.defaultTestLoader.discover(str(root / "tests"))
        result = unittest.TestResult()
        suite.run(result)
    report = {
        "suite": "wam-sp-selftest",
        "tests": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "failed": len(result.failures) + len(result.errors),
        "skipped": len(result.skipped),
    }
    print(json.dumps(report, separators=(",", ":")))

    # CI-safe diagnostics: print test identifiers only.
    # Never expose exception messages, paths, keys, addresses or transaction data.
    if not result.wasSuccessful():
        failed_ids = sorted(
            {test.id() for test, _ in [*result.failures, *result.errors]}
        )
        print(json.dumps(
            {"failed_test_ids": failed_ids},
            separators=(",", ":"),
        ))

    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == "__main__":
    raise SystemExit(main())
