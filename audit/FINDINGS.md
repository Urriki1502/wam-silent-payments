# Internal findings and dispositions

| Finding | Fix / evidence | Status |
| --- | --- | --- |
| Missing prevout scriptPubKey caused KeyError | Validate nested RPC shape, stable error; retain crash-d4c16780c7bfaddbc31652cd12afa5c3498de7a1 and replay test | Fixed |
| Copied Bitcoin 21M bound inconsistent with WAM | Pin WAM Core 22M money range across parser/wallet/storage | Fixed |
| Signature accepted independently of explicit PSBT sighash | Bind final signature type to declared field; SP requires ALL; regression test | Fixed |
| Database profile could be overwritten; row widths alone insufficient | Reject profile mismatch, compare schema names/types/PK, validate private local tables/ownership | Fixed |
| Whole mempool retained in memory | Stream transactions into atomic snapshot; bounded txids/transport/parsers | Fixed |
| Compound accounting reads could observe concurrent writes | Transaction snapshot for balance/history; process lease and SQLite reservations | Fixed |
| Runtime cryptography 46.0.7 had four reported advisories | Upgrade to 50.0.0; rerun dependency scanner and crypto/recovery suites | Fixed for scanned dependency set |
| BIP-375 valid field fixtures do not bind public keys to UTXOs | Keep reference field tests and strict signer rejection separately; see below | Investigated, not ignored |
| One-block branch test mined identical coinbase/block | Use distinct branch mining destination; actual common-ancestor rollback now checked | Test fixture fixed |

## BIP-375 fixture discrepancy

At pinned revision 3a10b5b5f0a7586df8928d580a3009744ebb2079, valid indices 2–14 and
17–19 contain BIP32 public keys whose HASH160 differs from the supplied witness
UTXO program. Example fixture values: pubkey HASH160
`1e2ad7872d329413a56df0968be338222783163b`, UTXO program
`229a72d34a645bd3496bbbf50bbb81c9063f4f94`. Valid index 12 also supplies Taproot
origin metadata that does not commit to the stated output key.

These vectors validate field workflow with prevalidated input keys assumed by the
reference helper. They are not all spendable consensus transactions. The adapter
can reproduce field checks with strict_inputs=False and reports unbound input
status. All signing/resolution paths remain strict; tests require explicit
SP_INPUT_PUBLIC_KEY_REQUIRED or TAPROOT_ORIGIN rejection for affected fixtures.
No mismatches are discarded or counted as valid wallet signatures.

## Remaining review limits

No unresolved crash is known in the completed fuzz corpus. No claim is made that
internal review found every HIGH/CRITICAL issue. Python key lifetime/timing,
consensus trust boundary and deployment metadata require independent review.
No external audit has occurred. Production WAM namespace/HD adoption is pending.
Unsupported platforms/script policies are explicit rejections, not hidden fallback.
