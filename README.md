# WAM Silent Payments — WSP-1 qualification build

Version: **1.0.0.dev0**. Target: **v1.0.0 / WSP-1 Production Baseline**.
External audit status: **pending**. No v1.0.0 tag has been created.

This repository upgrades the existing v0.2 implementation. It implements BIP-352
payment derivation, durable scanning, wallet accounting, authenticated recovery,
PSBTv2 offline signing and adapters for WAM SDK, Pay, Watchtower and Forge.
Cryptographic curve operations use coincurve/libsecp256k1, not a custom curve.

The verified node profile is **WAM Core v0.1.11, regtest only**. `wamrtsp` is an
unregistered regtest address namespace. Mainnet/testnet SP namespace and HD
profile adoption require a WAM maintainer decision; this code does not guess them.
The full release gate remains NON-CONFORMANT while adoption/review are pending.
Do not interpret passing local tests as an independent audit or a mainnet release.

## Build and verify

Linux, CPython 3.11+; verified on CPython 3.12, x86_64. Scanning uses POSIX file
locks. Build from this checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install --no-build-isolation . ./integration-deps/wam-sdk
python -m devtools.selftest
wsp-conformance test --contract-only
python examples/wallet_api.py
```

Full internal qualification uses a locally supplied, digest-pinned WAM daemon:

```sh
export WAMD=/absolute/path/to/wamd
export WAMD_SHA256=625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4
python scripts/qualify.py
wsp-conformance test --release --output reports/release-gate.json
```

The harness creates its own private datadirs, binds to loopback, disables public
peers and uses regtest. It never attaches to existing wallets. Install any system
libraries required by the chosen daemon. The supplied digest identifies the
Linux x86_64 v0.1.11 binary used for the recorded tests; other builds require their
own verified digest. Mining tests must run on trusted local/self-hosted hardware.
`reports/qualification.json` binds commands and report hashes to the tested source.

## Use and recovery

Applications use `wam_sp.api.SilentWallet`; the separate `Keyring`/`Signer` live
in the offline signing role. `create_silent_wallet`, `get_silent_address`,
`create_labeled_address`, `scan`, `get_balance`, `list_payments`,
`construct_payment`, `construct_spend`, `backup` and `restore` expose API v1.
A scan account contains the scan secret and public spend key only.

Use a private directory (0700) for databases and encrypted bundles. Save recovery
bundles with `keystore.save_private`; it creates 0600 files without overwriting.
Back up after adding an epoch, label, contact, invoice or irreversible reservation.
Restore into a new database, then rescan a validating node before serving balances.
See [RECOVERY.md](RECOVERY.md) for the complete procedure and legacy migration.

## Scope and assumptions

* BIP-352 v0 address payload/output derivation; all applicable pinned official
  vectors, including multi-input/output, labels, NUMS and repeated recipients.
* SQLite schema 3, atomic per-block commits, crash recovery, deterministic rollback,
  restart and real two-node reorg tests at depths 1/12/100/300.
* Confirmed SP coins, explicit mempool snapshots, coin control/locks, address book,
  transaction history, SP change and native P2TR signing through PSBTv2.
* Draft BIP-374/375/376/392/393 adapters are pinned and isolated. See
  [COMPATIBILITY.md](COMPATIBILITY.md) for exact limitations.
* A validating local node is trusted for consensus/prevouts. This is not an
  Electrum proof verifier, an anonymity network or protection against a hostile OS.
* Python cannot guarantee constant-time scalar bookkeeping, zeroization, or a
  secure enclave. Encrypted backups do not encrypt the live SQLite metadata.
* Unsupported script/signing policies or work limits stop scanning/signing; they
  never silently skip a block and report a complete balance.

Read [THREAT_MODEL.md](THREAT_MODEL.md), [PSBT.md](PSBT.md), [SCANNER.md](SCANNER.md),
[WSP-1.md](WSP-1.md), [audit/README.md](audit/README.md) and
[docs/VERIFICATION.md](docs/VERIFICATION.md). Public reports contain only synthetic
fixtures, counts and fixed error codes. Never paste real key material into tests.
