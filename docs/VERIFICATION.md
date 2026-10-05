# Executed verification

This records executed tests for the 1.0.0.dev0 qualification source. Source/report
hashes and per-command exits are in reports/qualification.json. These are internal
results, not an external audit. Counts below are not additive coverage percentages.

| Suite | Actual result |
| --- | --- |
| Unit/adversarial/integration/migration tests | 163 PASS, 0 FAIL, 0 SKIP |
| Official BIP-352 vectors | All 28 groups PASS, included in the 163 tests |
| Official BIP-375 field corpus | 20 valid + 23 invalid cases PASS; strict rejections separately asserted |
| Official BIP-374 DLEQ | 11 generation + 17 verification rows PASS, inside two unit tests |
| Independent BIP-352 differential | 10,000 PASS, 0 mismatch; deterministic seed 35220260930 |
| Coverage-guided fuzz | 1,009,000 recorded nonempty executions, nine targets, exit 0 |
| Two-node mandatory E2E | 7 PASS, 0 FAIL |
| Retained two-node interop | 10 PASS, 0 FAIL |
| Retained regtest checks | 9 PASS, 0 FAIL |
| Black-box conformance contract | 126 PASS, 0 FAIL across ten groups |
| Clean-install tests | 6 recovery + 7 durability/migration tests PASS, plus 126 contract checks |
| Reproducible wheel | Two independently built wheels have identical SHA256 |
| Runtime dependency scan | 4 pinned packages, 0 known reported vulnerabilities |
| Formatting / lint | PASS |
| Full release command | NON-CONFORMANT; engineering PASS, two external decisions pending |

## Unit group coverage

Adversarial 7; BIP375 43; boundaries 14; differential 2; durability 7; application
integrations 8; keys/PSBT 10; PSBTv2 6; recovery 6; release gate 3; scanner/wallet 16; architecture/capability boundary 13; BIP352 vector groups 28. No statement of 100% line/branch coverage is made.

## Actual E2E and durability

Node A/B use separate private datadirs and a verified v0.1.11 daemon. Tests send,
detect unconfirmed/confirmed payments, delete/restore the database, restart without
rescan, construct SP change, sign in a separate offline terminal process, verify
Core finalization, broadcast/spend, fork away the spend, roll back, reconfirm and
check final accounting. Additional actual competing branches measure rollback at
1, 12, 100 and 300 blocks. Stage 007 exercises production RPC and real WamClient.
Unit durability kills a writer with SIGKILL mid-transaction, tests simultaneous
reservations, repeated restarts, corrupt/future databases and schema-0/2 migration.

## Independent differential and fuzz

The BIP-352 oracle is the unchanged upstream reference at
3a10b5b5f0a7586df8928d580a3009744ebb2079. Randomized deterministic cases compare
address decoding, eligible inputs, aggregate/input hash, exact shared point,
output derivation, labels and receiver ownership across four eligible input types.
A 10,000-case run is 157.087 seconds on this environment; it is not an SLA.

Atheris 3.0.0/libFuzzer instruments Python paths. Final recorded target counts:
address 100,613; transaction 119,061; eligible input 43,083; scanner 65,142;
descriptor 223,095; PSBT/document 353,880; recovery payload 54,710; label 15,674;
state decoder 33,742. Counts are checkpointed every 1000 nonempty cases; the engine
was requested to execute 1,010,000 inputs. No known crash remains in this corpus.
The earlier missing-prevout crash is retained and replayed as a regression.
Native crypto wheels are not ASAN-instrumented; the backup fuzz target exercises
the bounded payload parser, while AEAD/password tampering is covered by unit tests.

## Measured synthetic performance

1000 blocks / 1000 payment transactions with synchronous FULL SQLite:
1206.55 blocks/transactions per second; database 1,208,320 bytes; peak RSS 66,308 KiB;
restart 0.0596 seconds with zero blocks rescanned; 300-block rollback plus replacement
scan 0.1973 seconds; authenticated restore plus full rescan 0.9335 seconds.
These synthetic local fixtures exclude real network latency and do not establish
mainnet throughput or constant-time behavior. Raw measures: reports/benchmark.json.

Full release remains blocked by production WAM profile adoption and independent
security/custody review. The command exits nonzero and no v1.0.0 tag is created.
