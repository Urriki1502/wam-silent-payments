# WAM Silent Payments architecture boundary

## Status

This document defines the smallest reviewable WSP-1 integration boundary before
further production integration work. It does not enable mainnet and it does not
change WAM Core consensus or wallet code.

The current implementation already contains the required primitives. This change
makes their ownership and interfaces explicit rather than spreading Silent Payments
logic through WAM Core.

## Ownership model

```text
validating WAM node / block source
        |
        v
Silent Payments scanner
        |
        v
minimal scan/index database
        |
        v
matched output metadata
        |
        v
core/coordinator wallet
        |
        v
offline Signer(Keyring)
```

### Node / block source owns chain truth

The block source is authoritative for consensus-valid blocks, the active tip,
prevout state and mempool policy. The scanner verifies continuity, stable tip
observations, reorg handling, transaction shape and bounded work, but it does not
attempt to become a second consensus implementation.

The scanner consumes the existing WAM SDK/Core RPC adapter through a minimal
capability interface: `attest()` plus bounded `call(method, params)`. This keeps the
protocol engine independent of a specific node transport.

### Scanner owns only scan/index state

The scanner receives `ScanAccount` values. A scan account contains:

- scan secret;
- spend **public** key;
- epoch/birthday;
- label metadata.

It does not contain the wallet seed or spend private key.

### Scan secret privacy boundary

The scan secret is intentionally available to the scanner. Anyone who obtains it,
together with the account's public data, can identify incoming payments to that
account. This does **not** grant spending authority and does not reveal the spend
private key, so compromise of the scan secret is a privacy loss rather than a loss
of funds.

Treat the scan secret and exported scan backups as privacy-sensitive secrets even
though they are not spending keys. This is the intended BIP-352 trade-off: online
scanning can be separated from offline spending authority, but the scanner still
holds material that protects payment privacy.

The scanner database stores chain/index data needed to recover matched outputs:
block linkage, matched outpoints, amount, account/epoch, matched public key, tweak,
label, receive/spend height, bounded public preparation cache, mempool snapshot,
reservations, labels and history. The database is not a seed backup and is not a
spending keystore.

### Wallet owns spend coordination, not spend secrets

`Wallet` consumes scanner state to calculate balances, select/reserve coins, build
payment intents and verify broadcast state. The coordinator does not receive a spend
private key.

### Keyring / signer own spend authority

One seed produces both scan and spend material. Recovery uses one authenticated
backup. `Keyring.accounts()` exports only scanning capability to the scanner.
`Keyring.spend_secret(epoch)` remains on the signer side.

Signing remains inside `Signer(Keyring)` or the standalone offline signer. The
scanner never receives the spend private key and the node/block-source interface
never receives any private key.

## BIP-352 responsibility split

BIP-352 address and output derivation remain in the WSP protocol engine. The node is
not made Silent-Payments-aware. For receive scanning, the scanner obtains ordinary
blocks/transactions with prevout data from the validating node and applies BIP-352
receiver derivation locally.

For spending, the coordinator exports an authenticated signing request containing
intent/UTXO metadata but no spend secret. The signer re-derives required spend keys
from the wallet seed, reconstructs the expected transaction and signs only after the
approved intent/fee matches.

## WAM Core integration policy

WAM Core currently materializes upstream Bitcoin Core through
`scripts/patch_upstream.py`. Silent Payments should therefore remain an isolated
component using existing node/block interfaces. Do not distribute BIP-352 changes
through `src/wallet/` unless an unavoidable Core integration requirement is
identified and reviewed.

If WAM Core later needs a native adapter, keep it thin: expose existing block/prevout
capabilities to the scanner rather than moving scanner/index/key logic into Core.

## Explicit interface

`wam_sp.block_source.BlockSource` is the protocol-facing capability boundary.
Scanner methods accept this protocol, while existing `SDKChain` adapters satisfy it
without behavioral changes.

The protocol intentionally exposes no signing, seed, keyring or wallet methods.

## Failure policy

- a block source that cannot attest must stop scanning;
- inconsistent best hash / height / block linkage must stop or retry;
- reorgs beyond configured limits require rescan;
- missing prevout data is an error, not a silent skip;
- scanner/database identity mismatch requires rescan;
- signing cannot be performed by Scanner, Wallet coordinator or BlockSource;
- a spend private key crossing the scanner boundary is a design failure.

## Qualification

Boundary tests verify that:

1. a minimal local block-source capability can drive an empty-chain sync;
2. `ScanAccount` exposes scan secret plus spend public key, not spend secret;
3. a non-empty Silent Payments scan and coordinator balance read complete while
   `Keyring.spend_secret` is replaced with a throwing sentinel, so any direct or
   indirect attempt to cross the spend-key boundary fails the test.

Existing BIP-352 vectors, scanner tests, conformance, differential and fuzz gates
remain authoritative for protocol behavior. This architecture change must not weaken
or bypass any of them.
