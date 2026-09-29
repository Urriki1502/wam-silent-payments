# Test evidence and known limits

The executed counts, differential comparison scope, fuzz target coverage and actual
node/recovery workflow are in [docs/VERIFICATION.md](../docs/VERIFICATION.md).
`reports/qualification.json` binds command/report digests to the exact source tree.
`reports/release-gate.json` distinguishes engineering PASS from release failure.
The initial upstream/v0.2 inventory and changed-file hashes are retained in this
folder; no old failing test was deleted to make the upgraded suite pass.

Known limits requiring review: local full-node consensus trust; plaintext SQLite
metadata; Python timing/lifetime and native wheels outside ASAN coverage; POSIX-only
scanner locks; bounded script/PSBT/label policies; no general multisig/hardware
transport; supported descriptor subset; stale-backup metadata cannot be recovered
from an absent record. These limitations are explicit API/operational boundaries,
not implied guarantees. MAINNET_ENABLED remains false pending WAM profile adoption.

External audit status: pending. Current internal evidence cannot prove absence of
unknown HIGH/CRITICAL findings. Reviewer acceptance must identify actual reviewer,
exact source, test reproduction and resolved findings. No such record is invented.
