# Critical invariants

1. `(txid,vout)` is unique; replay cannot credit twice. One atomic block commit
   includes receipts, spends, history and checkpoint.
2. Rollback reverses precisely orphaned receipts/spends/history. Reservations of
   externally signable transactions remain conservative across forks.
3. Selected outputs/fee never exceed verified inputs. Amounts are integer atoms;
   negative values, non-integral RPC decimals and WAM money-range violations fail.
4. Checkpoint height/hash must match a verified coherent node tip before balances
   or selection. Partial scan, malformed block, disconnect or cancellation cannot
   expose a current balance.
5. Scanner-only context contains scan secret/public spend key, no base spend key
   or seed. Output tweak alone is insufficient to spend.
6. Recovery is deterministic for the recorded network/algorithm/epochs/labels.
   Wrong password, corruption, duplicate JSON keys or identity mismatch fails.
7. A frozen signing request binds recipients, amounts, fee, change and owned inputs.
   A malformed PSBT, invalid proof, conflicting field, false origin or mismatched
   sighash does not reach a usable signature/finalization path.
8. Unknown PSBT fields are preserved except explicit completed-draft Core export;
   generic conversion never silently drops standard SP metadata.
9. Resource limits fail closed. Exceeding a limit does not skip a transaction and
   call a wallet synced. Mempool snapshots are all-or-nothing and marked unknown
   until a complete verified snapshot commits.
10. Structured logs accept only fixed events and integer counters; debug cannot
    override this rule. Backups, private keys and deterministic receipt maps stay
    out of logs and public release reports.
11. Duplicate signing reservations cannot succeed concurrently. Reconfiguration
    rejects stale metadata identities and cannot remove historical accounts/labels.
12. Missing, failed, skipped or stale mandatory release evidence is not success.

Assertions/tests enforce these boundaries, but structural validation is not a
second consensus engine or authenticated database. Independent review should
challenge assumptions and design fresh adversarial fixtures, not only rerun ours.
