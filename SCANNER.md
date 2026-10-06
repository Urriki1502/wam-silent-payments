# Scanner and durable state

Sync attests the regtest genesis, pins a coherent height/hash pair, compares local
history to node hashes, binary-searches the common ancestor and rolls back to it.
It commits each new block atomically, rechecks its hash and verifies the pinned tip
before marking the wallet current. Failure, cancellation, partial progress or tip
movement cannot serve a current balance. Restart at the same tip fetches no blocks.

Rollback deletes orphan receipts/history, reverses spend heights, removes orphan
headers and clears the mempool snapshot. Conservative signing reservations survive
reorgs: a previously exported signature may still be broadcast. Public transaction
tweak caching includes prevout/script/witness content in its key, preventing a
malformed transaction from bypassing validation through a txid cache collision.

The database uses SQLite DELETE journaling, synchronous FULL, private files,
quick_check, expected schema/column validation and ownership/accounting checks.
Crash rollback is exercised by SIGKILL during a real SQLite write transaction.
Logical schema 0/2 upgrades to 3 rebuild chain-derived data and preserve local
metadata/reservations. Future schemas/profiles fail closed. Database corruption
recovery means restoring an authenticated recovery bundle into a new database,
not repairing arbitrary rows in place. SQLite checks cannot detect an attacker
who deletes a valid row and repairs database structure; rescan is the remedy.

## Bounds and failures

Defaults: 2048 inputs, 4096 outputs, 1 MiB transaction parser, 10 KiB scripts,
1000 witness items, 1000 labels/account, 16 accounts, 100,000 curve operations per
receiver scan, 2048 cached public tweaks, 10,000-block automatic rollback, 1 GiB
SQLite limit. PSBT policy is 128 inputs/256 outputs/1 MiB. RPC response cap defaults
to 4 MiB, configurable up to 16 MiB. A block beyond local limits aborts; it is not
silently skipped. RPC and transaction consensus validity are trusted to a local
validating node. The scanner does not reimplement proof-of-work or script consensus.

Mempool scanning is optional, atomic and ephemeral. It streams one transaction
at a time, validates at most 10,000 txids and checks both mempool and chain snapshots.
Failed snapshots remain explicitly unknown. Confirmed balance is separate from
unconfirmed change/incoming amounts and pending spent amounts; selection excludes
mempool spends. `txindex=1` is needed when the node must resolve a missing prevout.

A reorg beyond the configured undo limit returns REORG_LIMIT_RESCAN_REQUIRED.
Stop applications from spending, retain the recovery bundle, invoke `scanner.rescan`,
then sync from genesis. Birthdays suppress ownership work before each account's
birthday while retaining verified block linkage. No balance is available mid-rescan.
