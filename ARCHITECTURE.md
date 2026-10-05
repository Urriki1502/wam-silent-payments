# Architecture

The existing v0.2 Python protocol core and test oracle are retained. Native
libsecp256k1 provides points, scalar tweaks, ECDH and BIP-340 signing. Pure Python
handles bounded parsing, metadata, policy and orchestration.

| Boundary | Modules | Responsibility |
| --- | --- | --- |
| Public facade | `api.py` | Versioned wallet operations, no application crypto internals |
| Protocol | `core.py`, `codec.py`, `crypto.py`, `chain.py`, `hd.py` | BIP-352/BIP32 and bounded encoding |
| Scan state | `scanner.py`, `store.py`, `state.py`, `limits.py` | Verified checkpoints, transaction caches, atomic accounting/reorg |
| Coordinator | `wallet.py`, `descriptors.py` | Coin policy, approved intent, stable metadata |
| Offline custody | `keystore.py`, `backup.py`, `offline_signer.py` | Encrypted export/recovery, isolated signing |
| Transaction interchange | `psbt.py`, `adapters/sp_psbt.py`, `psbt_document.py`, `dleq.py` | PSBTv2, draft proof/spend adapters |
| Applications | `adapters/sdk.py`, `pay.py`, `watchtower.py` | Existing SDK transport, scan-only merchant, public health |
| Operations | `rpc.py`, `privacy.py`, `errors.py`, `conformance.py` | Local bounded RPC, redaction, error classes, Forge gate |

The scanner receives immutable ScanAccount objects, never Keyring. The coordinator
stores per-output tweaks, which are sensitive metadata but insufficient to spend
without the base spend secret. Offline transport encrypts the complete intent
sidecar; standard PSBT fields carry standardized SP derivation data.

Each database connection has an RLock. A POSIX nonblocking file lease serializes
scanner mutations across processes. SQLite BEGIN IMMEDIATE serializes wallet
reservations and label identity compare-and-swap prevents lost reconfiguration.
Readers of accounting/history use a transaction snapshot. Application code must
not mutate `store.db` directly; it is not the public integration boundary.

## Node / scanner / wallet capability boundary

The review contract is in [docs/NODE_SCANNER_WALLET_ARCHITECTURE.md](docs/NODE_SCANNER_WALLET_ARCHITECTURE.md), with the cross-repository source review in [docs/INTEGRATION_BOUNDARY_REVIEW.md](docs/INTEGRATION_BOUNDARY_REVIEW.md). The scanner receives the existing scan capability, not the seed or spend secret. For the supported unpruned local-node profile, Bitcoin Core v28.1 `getblock(..., 3)` supplies the required confirmed prevout data, so **no Core change is required for correctness**.

This remains a regtest-only qualification architecture. Mainnet/testnet Silent Payments profile adoption is outside this branch.
