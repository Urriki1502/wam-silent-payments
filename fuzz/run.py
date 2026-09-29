"""Atheris/libFuzzer campaign. Crashes are saved by libFuzzer, never ignored."""

import atheris
import atexit
import json
from pathlib import Path
import sys
import time

with atheris.instrument_imports():
    import targets

START = time.monotonic()


def finish():
    report = {
        "engine": "atheris-3.0.0/libFuzzer",
        "executions": sum(targets.COUNTS),
        "targets": dict(zip(targets.NAMES, targets.COUNTS)),
        "seconds": round(time.monotonic() - START, 3),
    }
    Path("reports/fuzz-counts.json").write_text(json.dumps(report, indent=2) + "\n")


atexit.register(finish)


def instrumented(data):
    targets.one(data)
    if sum(targets.COUNTS) % 1000 == 0:
        finish()


atheris.Setup(sys.argv, instrumented)
atheris.Fuzz()
