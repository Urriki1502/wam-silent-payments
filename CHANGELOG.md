# Changelog

## 1.0.0.dev0 — WSP-1 qualification

Upgrades v0.2 while retaining its BIP-352 implementation and independent oracle.
Adds native compressed-point ECDH, BIP32 keys with legacy recovery, SQLite schema 3,
atomic history/mempool accounting, process-level scan serialization, strict state
validation, complete recovery bundles, PSBTv2 and pinned DLEQ/SP/descriptor adapters,
merchant outbox, SDK/Watchtower contracts, black-box conformance, release evidence,
coverage-guided fuzzing, actual two-node offline/recovery/deep-reorg E2E, measured
benchmarks, clean install and reproducible wheels.

Fixes malformed prevout parser crashes, Bitcoin-vs-WAM maximum money mismatch,
wallet stale-state checks, strict prevout/origin binding and signature sighash
binding. Preserves unknown PSBT fields. Upgrades cryptography to 50.0.0 after
runtime dependency audit findings. External audit and WAM production profile
adoption remain pending. No mainnet release or v1.0.0 tag.

## 0.2 — retained baseline

77 baseline tests, incremental scanning, labels, encrypted keys/checkpoints,
coin reservations, isolated signing and two-node integration harness.
