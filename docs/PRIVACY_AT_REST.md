# Privacy at rest contract

Silent Payments separates spending authority from scanning capability, but that
does not make every local artifact non-sensitive. This document states the
privacy properties that are enforced by tests and the residual exposure that
remains by design.

## Artifact classification

| Artifact | Contains / can reveal | Must not contain in plaintext | Handling |
| --- | --- | --- | --- |
| Live `wallet.db` | txids/outpoints, amounts, matched output keys/tweaks, labels, history, contacts, reservations and invoice metadata | seed, scan secret, base spend secret | Private host, private directory/file permissions, encrypted volume recommended |
| Scan export | scan secret plus public account metadata | plaintext scan/spend secrets outside the authenticated envelope | Treat as privacy-sensitive secret |
| Key backup | seed/derivation metadata inside authenticated encryption | plaintext seed or derived private keys outside the envelope | Offline secret storage |
| Recovery bundle | encrypted key backup plus descriptors/local metadata | plaintext seed/scan/spend secrets outside the authenticated envelope | Highest-sensitivity backup artifact |
| Signing request | recipient/amount/UTXO/intent metadata inside authenticated encryption | spend secret | Private transport across the signing boundary |
| PSBT / signed PSBT | transaction graph, amounts, scripts, public SP derivation metadata, signatures | seed/base private keys | Private transaction artifact; not telemetry |
| Operational logs | fixed event names and bounded counters | addresses, txids, balances, PSBTs, backups, scan/spend/shared secrets | Safe only through the allowlisted logger |

## Compromise semantics

Compromise of the scan secret is a privacy compromise: the holder can identify
payments to the corresponding account. It does not grant spending authority.

Compromise of `wallet.db` alone exposes substantial wallet metadata even though
the seed and scan/spend private material are not stored there. SQLite structure
validation is not encryption or authentication. A copied database can be mined
offline for transaction and application metadata.

Compromise of both the scanner host and its scan material should be treated as
loss of payment privacy for the affected epochs. Rotation limits future exposure
but cannot erase historical observations.

Compromise of the seed or base spend secret is a funds-custody incident and
requires migration to an independent fresh seed.

## Machine-checked invariants

The privacy-at-rest regression suite creates a real scanner database containing a
matched Silent Payment and application metadata, then verifies that the following
forms never appear in the SQLite bytes:

- raw seed bytes;
- raw scan-secret scalar;
- raw spend-secret scalar;
- hex encodings of those values;
- base64 encodings of those values;
- decimal scalar encodings.

It also verifies that encrypted scan/key/recovery exports do not expose those
plaintext forms and that the structured logger rejects wallet identifiers and
secret-bearing fields.

These tests are regression guards, not a cryptographic proof of secure erasure.
Python/native temporary copies, swap, crash dumps, screenshots and a compromised
OS remain outside this guarantee.

## Deliberate non-goal

This branch does not invent application-layer SQLite encryption or a new key
hierarchy. Adding an encrypted database format changes recovery, migration,
availability and key-custody semantics and therefore requires a separate design
review rather than an ad-hoc cipher layer.
