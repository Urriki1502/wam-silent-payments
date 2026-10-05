# WSP-1 node / scanner / wallet architecture

Status: design contract for maintainer review. This document describes the
existing WSP-1 implementation at `a8522fee9b6eda285998a5ff4a45d6bc4eb991b3`
and the smallest stable boundary for integrating it with WAM Core without
moving Silent Payments logic into upstream `src/wallet/`.

## Security ownership

The current implementation remains a **regtest-only qualification build**. `profile.py` keeps `MAINNET_ENABLED = False`, `core.py` uses the draft `wamrtsp` namespace, and `hd.py` defaults to test-chain coin type 1. Mainnet/testnet Silent Payments namespace and HD profile adoption are therefore maintainer decisions, not assumptions made by this document.

The design has three trust domains:

| Domain | Owns | Must not own |
| --- | --- | --- |
| WAM Core node | validated chain, block/transaction data, UTXO/mempool truth | WSP seed, scan secret, spend secret, labels |
| WSP scanner | scan capability, scan/index/checkpoint state, matched-output metadata | seed, base spend secret, derived spend private keys |
| Wallet security domain | seed, spend authority, user intent, signing approval, recovery metadata | authority to redefine chain truth |

The desktop application may currently host more than one domain in one Python
process, but capability ownership remains explicit: the scanner receives
`ScanAccount` values, never `Keyring`. A `ScanAccount` contains the BIP-352
scan secret and the public spend key; it contains no spend secret and is not
sufficient to authorize a spend.

The wallet security domain includes the offline/signing role. The coordinator
may hold scan-derived output metadata, reservations and PSBT intent while the
`Signer` is the component that receives `Keyring` and derives spend keys.

## 1. Chain data contract

The current scanner is a full-block client of a local validating node. It calls:

- `getbestblockhash`
- `getblockcount`
- `getblockhash`
- `getblock(blockhash, 3)`
- `getrawmempool`
- `getrawtransaction` for mempool fallback prevout lookup

For each non-coinbase transaction the scanner needs:

### Inputs

For every input:

- previous outpoint: `txid`, `vout`;
- previous output script: `vin[].prevout.scriptPubKey.hex`;
- `scriptSig.hex`;
- witness stack `txinwitness[]`.

Those fields are the material used by `Input.public_key()` and
`input_context()` to recover the eligible input public keys and the BIP-352
input aggregate/tweak context.

A confirmed block that does not provide the required prevout data fails closed
with `PREVOUT_DATA_REQUIRED`. The current WSP implementation does not guess
or query an external indexer.

### Outputs

For every output:

- output number `n`;
- amount `value`;
- `scriptPubKey.hex`.

The scanner only sends P2TR candidates (`OP_1 <32-byte x-only key>`) to the
BIP-352 receiver. Non-candidates are ignored before ECDH work.

### Chain consistency

A scan batch is accepted only while:

- the node attests the expected chain;
- height and best-block hash agree;
- each block links to the scanner's current durable tip;
- the block hash still maps to the same height after processing;
- the best-block hash has not changed across the scan snapshot.

A detected reorg is resolved by finding the common ancestor and rolling the
local derived chain state back before processing the replacement branch.

### Core integration decision

No WAM-specific wallet change is required for the current correctness model.
The WSP layer remains outside Core and consumes read-only node RPC data.

Do not add a WAM Core Silent Payments index or `src/wallet/` patch merely to
make scanning thinner. A Core-facing addition should be considered only after
measurement shows that full-block verbosity-3 scanning is the bottleneck.

If such an optimization is ever justified, the preferred shape is a small,
read-only chain-data RPC returning exactly the same validated input-prevout and
P2TR candidate data. It must not receive scan keys and must not perform wallet
ownership detection.

## 2. Scan capability

The minimum receiving capability for one account/epoch is logically:

```text
ScanCapability {
    account_id
    epoch
    scan_secret
    spend_public
    birthday
    labels[]
}
```

The existing `ScanAccount` is this capability.

Properties:

- `scan_secret` is intentionally private scanning material;
- `spend_public` is public;
- no seed is present;
- no spend private key is present;
- no per-output spend private key is present;
- label metadata is bounded and explicit.

A compromised scanner can discover and suppress receipt information for the
capabilities it holds. It cannot derive the independent base spend secret from
the scan capability.

## 3. Durable scanner state

The scanner database separates reconstructable chain state from private
application metadata.

Derived/reconstructable state:

- block chain tip/history used for rollback;
- matched coins and spend heights;
- BIP-352 prepared-input cache;
- mempool matched coins/spends;
- transaction credit/debit history.

Private local metadata:

- labels and display names;
- contacts;
- reservations;
- payment intents;
- durable outbox state.

The durable tip is the highest row in `blocks`. `ready` and
`verified_tip` are process-local assertions and are invalidated before every
sync attempt.

### Restart

Opening an existing database validates:

- schema shape;
- file permissions;
- SQLite integrity;
- stored wallet/account identity;
- chain continuity;
- matched-output ownership;
- reservations and private metadata.

A restart never treats an old in-memory `ready` value as proof of freshness.
The node must be attested and the stored tip reconciled again.

### Reorg

Rollback removes:

- received coins above the ancestor;
- spend marks above the ancestor;
- blocks/history above the ancestor;
- mempool snapshot state.

Private contacts/reservations/labels/intents are not chain-derived and are not
silently discarded by a reorg.

### Rescan/reset

`rescan()` invalidates readiness and rolls derived chain state back to height
zero. A completely lost scanner database can be rebuilt from scan capability,
recovery metadata and the validating chain.

## 4. Wallet / scanner API

The public integration boundary should remain capability-oriented rather than
exposing SQLite or raw arbitrary RPC.

### Scanner registration

```text
configure_scan_capabilities(capabilities[])
    -> scanner_identity
```

Semantics:

- capabilities are immutable account/epoch records;
- old epochs cannot be silently removed;
- label expansion or epoch rotation may rewind the minimum affected birthday;
- changing spend-public identity requires a new scanner database or explicit
  recovery migration.

The existing `Scanner(..., accounts)` and `reconfigure(accounts)` implement
this contract internally.

### Synchronization

```text
scan(chain, max_blocks=None)
    -> ScanResult {
         verified_height,
         verified_hash,
         blocks,
         transactions,
         candidates,
         rollback
       }

rescan()
    -> void
```

The result is diagnostic only. Balance/payment decisions must call scanner
methods that require `assert_current()`.

### Matched-output record

The scanner-to-wallet record is:

```text
MatchedOutput {
    txid
    vout
    account_id
    epoch
    atoms
    output_public_key
    private_key_tweak
    label
    k
    received_height
    spent_height?
}
```

`private_key_tweak` is sensitive wallet metadata but is not sufficient to
spend without the base spend secret. It must not be logged or exposed as
telemetry.

### Read API

```text
list_unspent(min_confirmations)
balance(min_confirmations)
history(page)
list_payments(page)
scanner_status()
```

All money-bearing reads require a current verified scanner tip.

### Recovery API

```text
export_checkpoint(password)   # optional scan/cache snapshot
restore_checkpoint(envelope, password)
export_recovery_bundle(password)
restore_recovery_bundle(envelope, password, new_database)
```

A recovery bundle is authoritative for keys/private metadata, not for chain
truth. Chain state is revalidated/reconstructed from the local node.

## 5. Sending boundary

Silent Payment output construction requires sender-side knowledge of the
selected input private keys. Therefore sending remains in the wallet/signing
domain, not the scanner.

Current flow:

1. scanner supplies confirmed matched UTXOs and metadata;
2. coordinator selects and reserves coins;
3. proposal freezes recipients, values, fee and change epoch;
4. signer receives the `Keyring`;
5. signer reconstructs each selected spend key from base spend secret + stored
   tweak;
6. signer derives BIP-352 outputs from the selected input keys and destination
   codes;
7. PSBTv2 carries the transaction and SP derivation metadata;
8. signer verifies the supplied PSBT against the approved proposal before
   signing;
9. broadcaster rechecks UTXOs and mempool policy before one
   `sendrawtransaction` attempt.

The scanner never needs sender input private keys or spend authority.

## 6. Receiving boundary

Receiving is:

1. read one validated block from the local node;
2. reject malformed/inconsistent block/transaction structure;
3. extract eligible input public keys from prevout/scriptSig/witness data;
4. prepare one BIP-352 input context per transaction;
5. filter P2TR candidate outputs;
6. perform scan ECDH per registered scan capability;
7. derive candidate tweaks and match output keys;
8. atomically persist matched-output metadata with the block;
9. expose balances/history only after the scan tip is reverified.

Duplicate transaction IDs inside a block are rejected. SQLite primary keys
prevent duplicate matched outpoints. Reprocessing a committed height is not a
normal forward operation; restart resumes from the stored block tip.

## 7. Backup and recovery

Must be backed up:

- seed / key algorithm;
- epoch birthdays;
- registered labels;
- contacts and other application metadata that cannot be inferred from chain;
- unresolved reservations/intents/outbox decisions when application semantics
  depend on them.

Can be reconstructed:

- block rows;
- confirmed matched coins;
- spend heights;
- transaction history derived from chain;
- prepared-input cache;
- mempool snapshot.

A lost scanner database is therefore recoverable from the key/recovery bundle
plus the validating chain. A backup predating a sparse label cannot discover
that off-chain label assignment by guessing; label metadata is part of recovery
state.

## 8. Failure and threat model

### Malicious/buggy scanner

Can:

- omit a match;
- report stale local state;
- expose scan metadata;
- attempt to feed incorrect tweak/output metadata to the coordinator.

Cannot authorize a spend without the independent wallet spend secret.

Mitigation:

- chain data originates from the validating node;
- scanner state validates matched-output ownership against public spend key +
  stored tweak;
- signer reconstructs spend keys and verifies the complete proposal/PSBT;
- wallet UI must not treat scanner observation as proof of global-chain truth.

### Scanner database compromise

Assume labels, receipt history, output tweaks, contacts and invoice linkage are
exposed. Do not assume the attacker obtained the seed or spend secret.

Structurally valid malicious edits are not cryptographically authenticated.
Recovery from a suspect database means create a new database and rescan trusted
chain data.

### Scanner omission

BIP-352 inclusion proof for one observed payment does not prove completeness.
Completeness comes from scanning every relevant block from the configured
birthday through a locally validated chain tip.

### Incorrect chain tip

A local node is the chain-truth boundary. Scanner tip checks detect local
changes during a scan, but they do not prove that the local node sees the
globally best chain.

### IPC / process separation

If scanner and signer are separated into different processes later, the IPC
contract should carry only:

- scan capability during provisioning;
- matched-output metadata from scanner to wallet;
- public status/health;
- explicit rescan/reconfigure commands.

Never serialize `Keyring`, seed bytes or base spend secrets onto scanner IPC.

## 9. Conformance matrix

Existing coverage already includes:

- official/reference BIP-352 send/receive vectors;
- address/key derivation;
- restart and warm resume;
- reorg depths including deep rollback;
- malformed-block atomic rollback;
- checkpoint identity/authentication;
- lost database + recovery bundle + full rescan;
- duplicate/missing block handling;
- scanner database corruption/future schema rejection;
- concurrent coin reservation;
- ambiguous broadcast reservation retention;
- scan database contains no scan/spend secret bytes.

Additional boundary tests to add before calling this architecture complete:

1. scanner capability object has no seed/spend-secret surface;
2. recovery from seed + label metadata into a completely empty scanner DB
   reproduces the same matched outputs after rescan;
3. stale/corrupt checkpoint never overrides chain truth;
4. scanner omission simulation is repaired by a full rescan from birthday;
5. signer refuses matched-output metadata whose tweak/public key does not
   reconstruct against the account spend public key;
6. wallet/scanner process-boundary serialization contains no spend authority.

## 10. Integration rule for WAM Core

WAM Core remains the validated data source and broadcaster. WSP remains a
separate layer.

Do not patch `src/wallet/` for Silent Payments unless a future requirement
cannot be expressed through a small read-only chain-data interface. Any such
change must be justified independently because every upstream wallet edit
becomes a permanent rebase and review obligation.
