"""Fail-closed release evidence. Reports are reproducible records, not audit attestations."""

import hashlib
import json
from pathlib import Path

SUFFIXES = {".py", ".json", ".csv", ".toml", ".sh", ".yml", ".yaml", ".txt"}
DIRECTORIES = (
    "src",
    "devtools",
    "tests",
    "fuzz",
    "benchmarks",
    "scripts",
    ".github",
    "integration-deps",
)
REQUIRED = (
    "format",
    "lint",
    "unit",
    "conformance",
    "differential",
    "fuzz",
    "real_node",
    "interop",
    "regtest",
    "benchmark",
    "dependencies",
    "build",
)


def source_digest(root):
    root = Path(root)
    files = [root / "pyproject.toml", root / "requirements-lock.txt", root / "requirements-dev.txt"]
    for directory in DIRECTORIES:
        files.extend(
            p
            for p in (root / directory).rglob("*")
            if p.is_file()
            and p.suffix in SUFFIXES
            and "__pycache__" not in p.parts
            and not any(x.endswith(".egg-info") for x in p.parts)
            and not ("fuzz" in p.parts and "corpus" in p.parts)
        )
    digest = hashlib.sha256()
    for p in sorted(set(files)):
        digest.update(
            p.relative_to(root).as_posix().encode()
            + b"\0"
            + hashlib.sha256(p.read_bytes()).digest()
        )
    return digest.hexdigest()


def release_gate(root):
    root = Path(root)
    checks = {}
    evidence = None
    try:
        evidence = json.loads((root / "reports/qualification.json").read_text())
        checks["source_bound"] = evidence["source_sha256"] == source_digest(root)
        for name in REQUIRED:
            item = evidence["gates"][name]
            checks[name] = item["exit_code"] == 0
            for filename, digest in item["reports"].items():
                path = Path(filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != "reports"
                ):
                    raise ValueError("EVIDENCE_PATH")
                checks[name] = (
                    checks[name]
                    and hashlib.sha256((root / path).read_bytes()).hexdigest() == digest
                )
    except (OSError, ValueError, TypeError, KeyError):
        checks["evidence_complete"] = False
    try:
        decisions = json.loads((root / "audit/release-decisions.json").read_text())
        checks["wam_profile_adoption"] = decisions["wam_profile_adoption"] == "approved"
        checks["independent_security_review"] = (
            decisions["independent_security_review"] == "approved"
        )
    except (OSError, ValueError, TypeError, KeyError):
        checks["release_decisions"] = False
    engineering = all(checks.get(k, False) for k in ("source_bound", *REQUIRED))
    return {
        "result": "PASS" if engineering and all(checks.values()) else "FAIL",
        "engineering": "PASS" if engineering else "FAIL",
        "checks": checks,
        "external_audit_status": "pending"
        if not checks.get("independent_security_review")
        else "reviewed",
        "blockers": [k for k, v in checks.items() if not v],
    }
