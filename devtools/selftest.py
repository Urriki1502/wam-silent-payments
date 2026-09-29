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
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == "__main__":
    raise SystemExit(main())
