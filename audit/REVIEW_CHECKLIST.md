# External reviewer checklist

- Record reviewer identity, exact source/wheel digest, platform and native versions.
- Independently derive BIP-352 parity/outpoint/NUMS/labels/repeated-recipient cases.
- Review raw-point ECDH callback and Python secret arithmetic/lifetime assumptions.
- Cross-check PSBTv2 locktime/unknown-field/duplicate rules, partial signing, final
  sighash, DLEQ statements and proof binding; inspect the BIP-375 fixture discrepancy.
- Attack coordinator intent substitution, amount/fee/change confusion and imported
  origin/tweak mismatches using a clean offline signer.
- Interrupt per-block commit, migration, label allocation, backup write and restore;
  inspect rollback/locks after repeated restart/reorg and multiple processes.
- Verify full database-loss recovery of ownership, labels, history and spendability.
- Examine SQLite trust, corruption handling and what malicious deletion cannot detect.
- Audit RPC response caps, malicious shapes, timeout/chain-tip races and resource limits.
- Inspect all representations, logs, errors, CLI arguments, file permissions and
  webhook metadata; evaluate deployment-specific timing/network leakage.
- Independently build/compare wheels, review dependencies/licenses and supply chain.
- Reproduce 10k differential, 1M fuzz and two-node E2E on separate trusted hardware.
- Record severity, exploit preconditions, affected properties and testable fixes.
- Explicitly accept/reject production network adoption and custody assumptions.

Only a real independent reviewer can complete this checklist. Internal test output
must not be substituted for reviewer identity or approval.
