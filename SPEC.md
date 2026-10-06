# WSP-1 specification baseline

Protocol semantics are BIP-352 version 1.1.1 at Bitcoin BIPs revision
`3a10b5b5f0a7586df8928d580a3009744ebb2079`. WSP-1 adds wallet, storage, recovery,
resource and integration rules; it does not change elliptic-curve operations,
Silent Payment input hashing, output derivation or ownership rules.

## Normative implementation rules

1. BIP-352 version-0 payload is two compressed secp256k1 keys encoded with Bech32m.
   Keys must be valid, non-infinite points. Mixed case, wrong HRP/checksum/version,
   invalid padding or invalid payload lengths fail. Bitcoin `sp` is accepted only
   by explicitly selected protocol/vector APIs; wallet calls pin the WAM profile.
2. Eligible keys are extracted from P2PKH, P2SH-P2WPKH, P2WPKH and P2TR. Taproot
   key-path parity, annex, script-path NUMS exclusion and unsupported future witness
   versions follow BIP-352. No eligible key or an infinite aggregate aborts sending.
3. The lexicographically smallest serialized outpoint and compressed aggregate
   input key are tagged-hashed as BIP0352/Inputs. Sender/receiver compute the same
   raw compressed ECDH point. An ordinary hashed-ECDH API is not interchangeable.
4. Outputs group by scan public key; `k` increments within that group, including
   repeated destinations and labels. Kmax is 2323. No additional BIP-341 TapTweak
   is applied to an SP output. Output ownership uses both x-only parities as required.
5. Label 0 is reserved for private change. Public invoice labels are registered
   uint32 values from 1; no duplicate allocation. Sparse exact labels remain in
   stable recovery data. Descriptor max-label expansion is bounded to 1000.
6. Scalar zero/out-of-range, invalid points and point-at-infinity are errors or
   ineligible transaction cases as defined by the pinned protocol. No modulo
   reduction substitutes for required scalar validation.
7. Scanner credits a unique `(txid,vout)` once. Received/spent/history/checkpoint
   writes commit in one transaction. Verified checkpoints alone serve balances.
8. Backup identity/network/algorithm mismatches fail before usable state is created.
   Restoring chain state never bypasses node verification.
9. Offline signing recomputes recipients, change and fee from approved intent;
   malformed/conflicting PSBT, incorrect DLEQ or spend tweak never reaches signing.

WAM maximum money is 22,000,000 × 100,000,000 atoms, from the pinned Core source.
Bounds are local policy, not new consensus rules. Exceeding a bound requires an
explicit policy/recovery decision and leaves the scanner non-current.
