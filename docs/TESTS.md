# Test catalog

Current executed counts and limitations: [VERIFICATION.md](VERIFICATION.md).

`tests/test_vectors.py` imports all pinned BIP-352 vectors. `test_bip375.py` retains
all field-level PSBT fixtures and additionally enforces strict prevout/origin
rejection. `test_psbt_v2.py` includes DLEQ vectors, unknown-field preservation and
partial signing. `test_differential.py` imports an unchanged independent oracle.
`test_scanner_wallet.py` and `test_durability.py` cover rollback, bounds, crash,
restart, database upgrades and concurrent reservations. `test_recovery_v1.py`
deletes the database and reconstructs spendability. `test_integrations_v1.py`
exercises merchant/outbox/expiry/reorg, health, logging, RPC and key disposal.
`test_release_gate.py` verifies nonconforming external adapters fail.

Tests are flat Python unittest modules to retain v0.2 discovery/import compatibility.
The requested unit/integration/adversarial categories are represented by these
modules rather than duplicated test directories. Real-node drivers are under
devtools/, black-box fixtures under tests/conformance/, and machine-readable
vectors under tests/vectors/. No mandatory tests are skipped for absent daemons;
full qualification requires the explicitly supplied node binary and digest.
