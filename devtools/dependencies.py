"""Inventory installed runtime distributions without importing cryptographic code."""

from importlib.metadata import distribution
import json
from pathlib import Path


def main():
    result = []
    for name in ("coincurve", "cryptography", "cffi", "pycparser"):
        d = distribution(name)
        m = d.metadata
        license_name = (
            m.get("License-Expression")
            or m.get("License")
            or "; ".join(x for x in m.get_all("Classifier", []) if x.startswith("License ::"))
        )
        result.append(
            {
                "name": m["Name"],
                "version": d.version,
                "license": license_name,
                "requires": d.requires or [],
                "project_urls": m.get_all("Project-URL", []),
            }
        )
    Path("audit/dependencies.json").write_text(
        json.dumps(
            {
                "runtime": result,
                "python": ">=3.11; verified CPython 3.12/Linux x86_64",
                "crypto_backend": "coincurve bundled libsecp256k1; cryptography bundled OpenSSL",
                "update_policy": "pin reviewed releases; pip-audit each qualification; rerun vectors, differential, fuzz, restore and real-node suites after crypto upgrades",
            },
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
