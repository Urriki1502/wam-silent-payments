# WSP-1 conformance and release

Profile ID: WSP-1. API major: 1. Internal descriptor: 1. Recovery bundle: 1.
SQLite schema: 3. Package remains 1.0.0.dev0 until release requirements are met.

`wsp-conformance test` emits machine-readable JSON and a nonzero exit status for
any failed/missing mandatory evidence, changed source/report, unresolved network
adoption or pending independent security review. Full success is exactly
`WSP-1 CONFORMANT`; otherwise `WSP-1 NON-CONFORMANT`.

`--contract-only` deliberately reports `CONTRACT PASS`/`CONTRACT FAIL`, never full
WSP conformance. The contract covers Protocol, Address, Labels, Scanner, Reorg,
Recovery, PSBT, Wallet, Privacy and Integration. It executes a separate process;
an external implementation supplies `--adapter executable arg...`. See
[docs/CONFORMANCE.md](docs/CONFORMANCE.md). Official expected results are imported,
not calculated by the implementation under test.

Full qualification additionally requires: all unit/adversarial/migration/recovery
checks; >=10,000 independent differential cases; >=1,000,000 coverage-guided fuzz
executions over all nine targets; actual two-node E2E; all four deep-reorg depths;
legacy interop/regtest checks; dependency scan; formatting/lint; measured benchmarks;
clean wheel installation; and byte-identical repeated wheel builds.

`reports/qualification.json` records every command exit code, output hash, source
hash and timing. Evidence is local reproducible evidence, not a cryptographic audit
attestation. Branch protection and release permissions remain repository-owner
controls. CI provides no automatic tag/release operation.
