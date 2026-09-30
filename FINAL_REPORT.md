# WAM Silent Payments / WSP-1 — implementation report

Delivered version: **1.0.0.dev0**, upgraded from the existing v0.2 codebase.
Target v1.0.0 is not tagged. Internal engineering qualification: **PASS**.
Full release gate: **WSP-1 NON-CONFORMANT** pending two external decisions below.

## Implementation

32 production source files added/modified. The retained core now includes native
compressed-point ECDH, BIP32 with legacy key migration, SQLite schema 3 scanning,
crash/reorg/history/mempool accounting, coin selection/control/locks, encrypted
recovery, draft descriptor adapter, PSBTv2, DLEQ, offline signing and stable API v1.
Implemented WAM SDK, merchant payment intent/outbox, Watchtower and Forge adapters.
Existing v0.2 code/reference was read and retained where correct; no rewrite from
scratch. File-by-file hashes: audit/changes-from-v0.2.json.

Complete source, tests, fixtures, fuzz corpus/regression, benchmarks, scripts,
GitHub Actions, required documentation, upstream pins/licenses, audit package,
source-bound test reports and installable wheel are included.

## Verification

| Verification | PASS | FAIL |
| --- | ---: | ---: |
| Unit/adversarial/integration/migration tests | 150 | 0 |
| Official BIP-352 vector groups, included above | 28 | 0 |
| Official BIP-375 field cases, included above | 43 | 0 |
| Official DLEQ rows, included above | 28 | 0 |
| Independent differential cases | 10,000 | 0 |
| Real-node test stages: mandatory E2E + interop + regtest | 26 | 0 |
| Black-box conformance contract cases | 126 | 0 |
| Internal qualification gates | 12 | 0 |

Fuzz: 1,009,000 recorded executions across nine targets; no known remaining corpus
crash. Actual-node and synthetic reorg depths: 1/12/100/300 blocks. SIGKILL during a
SQLite write transaction recovers correctly. Full database deletion/restoration
recovers labels, balances/history and signing ability. Clean installation passes
recovery/migration/crash tests and the contract. Two independently built wheels are
byte-identical. Dependency scan: 0 advisories across four pinned runtime packages.

Benchmark: 1000 synthetic blocks at 1206.55 tx/s; peak RSS 66,308 KiB; restart
0.0596 s; 300-block rollback/replacement 0.1973 s; full restore/rescan 0.9335 s.
Details/limits: docs/VERIFICATION.md. These are not mainnet throughput claims.

## Security

Fixed malformed-prevout parser crash, wrong WAM money limit, missing signature
sighash binding, insufficient stored-schema/profile validation, whole-mempool
retention and non-atomic compound accounting reads. Preserved strict UTXO/origin
binding despite inconsistent official BIP-375 field fixtures; discrepancy is
investigated/documented rather than ignored. Updated cryptography to 50.0.0.

External audit status: **pending**. No independent review or zero-unknown-findings
claim. Python key lifetime/timing, plaintext metadata and node trust limits are
explicit in THREAT_MODEL.md and audit/. The review package is ready for inspection.

## Compatibility

WAM Core v0.1.11, commit 8a3f4fe4f1d804c378f795d4cc281ec5125f75f3; actual regtest
nodes and supplied WAM SDK 0.1.0. BIP-340/341/350/352 and PSBTv2/BIP-370;
374/375/376/392/393 draft adapters pinned at
3a10b5b5f0a7586df8928d580a3009744ebb2079. WSP-1/API 1/schema 3/recovery 1;
authenticated v0.2 key/database upgrades retain ownership. Supported subsets and
fail-closed limitations are explicit in COMPATIBILITY.md.

## Remaining blockers

1. WAM maintainers must adopt the production Silent Payment namespace/HD network
   profile. Current implementation is intentionally pinned to regtest; no invented
   official mainnet compatibility is claimed.
2. Independent security/custody review has not occurred. Internal tests cannot
   provide that independent assurance or approve findings on a reviewer's behalf.

No v1.0.0 tag, mainnet deployment, repository push or external message was made.
