# Integration contracts

## WAM SDK

`SDKChain` accepts the actual WamClient from wam-sdk 0.1.0, supplied as an unchanged
source snapshot under integration-deps/wam-sdk. It verifies network/readiness,
allowlists scanner RPC methods and requires explicit broadcast capability.
Real-node E2E stage 007 executes this adapter and the independent production RPC
transport. Existing SDK code is not replaced by a mock implementation.

## WAM Pay

Merchant accepts only SilentWallet/scan accounts. create_intent allocates a durable
label, atomic amounts, confirmation policy and expiry. refresh reads receipts
including already-spent coins, derives pending/partial/confirming/paid/expired
states and records durable outbox transitions. Reorg of a paid invoice emits
payment.reorg; reconfirm emits payment.paid. Late sufficient payments remain paid,
even after expiry; expiry is a business deadline, not an on-chain revocation.

Applications drain events and acknowledge only after their configured delivery
succeeds. At-least-once delivery means recipients deduplicate WSP-Event-ID.
Merchant.webhook returns canonical body and HMAC-SHA256 timestamp/body headers;
it performs no network send. Receiver transport must enforce TLS, authenticate
signatures, check timestamp/replay bounds and retain event IDs. No private spend
key is required for invoice creation or incoming monitoring. Invoice mapping is
sensitive merchant data and is included in authenticated recovery bundles.

## Watchtower

health returns profile/API/schema, height/behind and fixed signals: SCANNER_BEHIND,
CHAIN_MISMATCH, DATABASE_CORRUPTION, REORG_DETECTED, RPC_FAILURE, STALE_CHECKPOINT,
INCOMPATIBLE_SCHEMA and INCOMPATIBLE_WSP_VERSION. It includes no wallet identifier,
address, balance, receipt or spend secret. The caller supplies a classified error
code; raw exception strings are refused.

## Forge

`wsp-conformance test` is the machine-readable release boundary. Read the exit
status and result, not just individual PASS fields. Missing or changed source-bound
evidence fails. Contract-only results are explicitly distinct from full release
qualification. CI contains no deploy, tag, external message or public webhook action.

## Reviewed component boundary

The exact SDK / Silent Wallet / WAM Core boundary review is recorded in [INTEGRATION_BOUNDARY_REVIEW.md](INTEGRATION_BOUNDARY_REVIEW.md). No SDK or Silent Wallet source change was required by that review. The confirmed scanner uses the local validating node as chain truth and requires verbosity-3 prevout data from an unpruned node; it does not require a WAM-specific Silent Payments index for correctness.
