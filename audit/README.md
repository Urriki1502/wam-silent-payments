# Independent review package

External audit status: **pending**. No external reviewer has been contacted and no
review approval is claimed. This directory is an entry point, not an audit report.

Read ARCHITECTURE.md, SPEC.md, WSP-1.md, THREAT_MODEL.md, RECOVERY.md, PSBT.md and
SCANNER.md at repository root. Detailed lifecycle/timing/integration/contract docs
are under docs/. FINDINGS.md records internally found issues and fixture mismatches.
INVARIANTS.md and REVIEW_CHECKLIST.md describe the intended properties to attack.
`baseline-inventory.json` preserves the v0.2 inventory; `dependencies.json` records
runtime versions/licenses. Exact evidence is under reports/ and bound by the
qualification source SHA256 and per-report digests.

## Trust boundaries and sensitive files

| Boundary | Sensitive modules / data | Reviewer focus |
| --- | --- | --- |
| Consensus → scanner | rpc.py, chain.py, scanner.py | Trusted node identity, malformed/missing prevouts, bounded failure, reorg races |
| Protocol → native crypto | core.py, crypto.py, hd.py | Parity, zero/infinity, raw ECDH serialization, native API/CFFI usage |
| Coordinator → offline signer | wallet.py, psbt.py, offline_signer.py | Approved intent, fee, change, ownership, DLEQ, unknown/conflicting fields |
| Encrypted bundle → state | keystore.py, backup.py, descriptors.py, store.py | Authentication, migration, exact labels, atomic restore, secret lifetime |
| Database → applications | store.py, api.py, adapters/pay.py | Double-credit, rollback, locks, late payments/outbox idempotence |
| Operations → public reports | privacy.py, devtools/privacy.py, watchtower.py | Fixed-code redaction, no address/output maps or secret-bearing exceptions |

Test vectors contain known private values and must never be funded. The independent
reference implementation is test-only and not shipped inside the runtime wheel.
The WAM SDK snapshot is a test/integration dependency, not cryptographic authority.
