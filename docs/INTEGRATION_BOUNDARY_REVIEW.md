# Node / scanner / wallet integration review

Review scope:

- WSP implementation: `Urriki1502/wam-silent-payments@a8522fee9b6eda285998a5ff4a45d6bc4eb991b3`
- Silent Wallet: `Urriki1502/wam-silent-wallet@44e749a5c8fde82f672d0bc9d11e43af4e52c673`
- WAM SDK: `Urriki1502/wam-sdk@9d15f4c7698362210c50f26803cedaaf03d8a038`
- reviewed WAM source: `wamcoin-core-dev/wam-coin@bb6d5214f2f5de3b7464587cc1b2949d221dcd18`
- pinned upstream Core: Bitcoin Core v28.1

This review is about component authority and data contracts. It does not enable
WSP mainnet and does not change WAM Core.

## Result

The existing repositories already follow the intended authority split closely
enough that no SDK, Silent Wallet or Core source change is required for the
architecture boundary itself.

### WAM SDK

The SDK remains a bounded local Core-RPC transport and typed node/wallet client.
It does not receive WSP seed material and does not implement BIP-352 ownership
logic.

The WSP `SDKChain` adapter allowlists only the chain reads/broadcast operation
needed by the WSP layer. This keeps "node transport" separate from "scan
ownership".

**Decision: no SDK code change required for this review.**

### WAM Silent Wallet

The application owns UI/session/orchestration. `WalletService` opens the
encrypted keyring only inside wallet operations; scanner construction receives
`ring.accounts()`, not `Keyring` itself. The signing path constructs a
`Signer(ring)` separately.

This is process-level separation of authority, not hardware isolation. The
current desktop application may still host scanner and signer in one Python
process while unlocked.

**Decision: no Silent Wallet code change required for this review.**

### WSP scanner / signer

The scanner receives the existing `ScanAccount` capability:

- scan secret;
- spend public key;
- birthday;
- label metadata.

It does not receive the seed or base spend private key.

The signer receives `Keyring`, reconstructs output spend keys from the base
spend secret plus scan-derived tweak, and verifies the proposal/PSBT before
signing.

The architecture branch names this existing security role
`ScanCapability` without introducing a second key object.

## Core chain-data contract

The confirmed scanner uses:

```text
getblock(blockhash, 3)
```

For each non-coinbase transaction it needs:

- input txid/vout;
- previous-output `scriptPubKey.hex`;
- `scriptSig.hex`;
- witness stack;
- transaction outputs including P2TR scripts and values.

Bitcoin Core v28.1 implements verbosity 3 by reading block undo data and
serializing each input with a `prevout` object. The RPC documentation in that
source states that prevout information is available for unpruned blocks in the
current best chain.

WSP already fails closed with `PREVOUT_DATA_REQUIRED` when the required
prevout material is absent.

Therefore, for the supported local **unpruned validating-node** profile:

> **NO CORE CHANGE REQUIRED FOR CORRECTNESS**

A WAM-specific Silent Payments index is not required to implement correct
scanning. It may only be reconsidered as a measured optimization.

A pruned-node scanning profile is not established by this review. Do not treat
the verbosity-3 contract as a promise that historical prevout data exists after
pruning.

## Scanner database completeness

`ready=True` means the scanner has reconciled its stored chain tip with the
configured local node during the current process. It is not a cryptographic
proof that a structurally valid local database was never maliciously edited.

A structurally valid omission therefore requires the documented recovery
procedure: discard/rebuild derived scanner state and rescan from trusted chain
data using the retained scan capability and recovery metadata.

## Mainnet status

This review changes no production profile decision.

The implementation remains a regtest qualification build:

- `MAINNET_ENABLED = False`;
- draft `wamrtsp` address namespace;
- test-chain HD profile.

Mainnet/testnet Silent Payments naming and HD profile adoption remain WAM
maintainer decisions.
