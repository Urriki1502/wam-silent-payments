# Contributing

Use synthetic fixtures and disposable regtest datadirs only. Never attach test
code to another person's node/wallet or include real secrets in an issue/report.

Install the pinned development requirements, run ruff format/check and
`python -m devtools.selftest`. Protocol changes must pass all official vectors and
`python -m devtools.differential --cases 10000`. Retain upstream reference source
unchanged. Regressions go in fuzz/regressions and a focused test.

Run `scripts/qualify.py` on trusted hardware before proposing a release. No skip,
missing report, reduced campaign or unexpected exception is release success.
After edits, old source-bound qualification evidence is invalid. Do not suppress
legitimate failing tests or loosen parsing/signing to fit malformed fixtures.

Security reports follow SECURITY.md. No v1.0.0 tag should be created until the full
conformance command exits zero, maintainer profile decisions are recorded, and
independent security review has resolved release-blocking findings. Protected
branch/release settings must enforce this policy externally to the source code.
