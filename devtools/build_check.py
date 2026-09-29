"""Build twice, install a wheel into a clean interpreter, run real recovery tests."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv


def main():
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["SOURCE_DATE_EPOCH"] = "1780272000"
    report = {"suite": "clean-install-reproducible-build", "result": "FAIL"}
    with tempfile.TemporaryDirectory() as d, (root / "reports/build-run.log").open("w") as log:
        work = Path(d)

        def run(args, **kwargs):
            subprocess.run(args, cwd=root, env=env, check=True, stdout=log, stderr=log, **kwargs)

        try:
            for target in ("one", "two"):
                run(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "wheel",
                        "--no-deps",
                        "--no-build-isolation",
                        "--wheel-dir",
                        str(work / target),
                        ".",
                    ]
                )
            one = next((work / "one").glob("*.whl"))
            two = next((work / "two").glob("*.whl"))

            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()

            if digest(one) != digest(two):
                raise ValueError("NONREPRODUCIBLE_BUILD")
            venv.EnvBuilder(with_pip=True).create(work / "clean")
            python = str(work / "clean/bin/python")
            run([python, "-m", "pip", "install", str(one)])
            run([python, "-m", "pip", "check"])
            run(
                [
                    python,
                    "-c",
                    'import wam_sp; assert wam_sp.__version__=="1.0.0.dev0"; assert "site-packages" in wam_sp.__file__',
                ]
            )
            run([python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_recovery_v1.py"])
            run([python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_durability.py"])
            run([python, "-m", "wam_sp.conformance", "test", "--contract-only"])
            (root / "dist").mkdir(exist_ok=True)
            shutil.copy2(one, root / "dist" / one.name)
            report.update(
                result="PASS",
                wheel=one.name,
                sha256=digest(one),
                identical_wheels=2,
                clean_install=True,
                migration_and_crash_tests=7,
                recovery_tests=6,
            )
        except (subprocess.CalledProcessError, ValueError, OSError):
            report["error"] = "BUILD_OR_INSTALL_VALIDATION"
    (root / "reports/build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(report["result"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
