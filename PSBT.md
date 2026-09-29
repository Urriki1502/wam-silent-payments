# PSBT and offline signing

Native construction uses BIP-370 PSBTv2. PSBTv0 can be parsed explicitly. Maps reject
noncanonical CompactSize, duplicate keys, incompatible versions/fields, missing
counts/outpoints/UTXOs, conflicting locktime requirements and policy size overruns.
Unknown fields survive decode, combine, partial signing and finalization. Combination
rejects any conflicting known or unknown field; it never arbitrarily picks one.

The software signer supports P2TR key-path signatures with BIP-341 SIGHASH_DEFAULT
or ALL; Silent Payment sender transactions require ALL. An explicit declared
sighash must match the final signature. Finalization verifies every Schnorr
signature and rejects negative fees. Wallet signing additionally reconstructs
approved Silent Payment destinations, fee, ownership and private change label 0.
No unsupported signature policy is silently downgraded.

Pinned BIP-375 fields carry sender scan/spend public keys, per-input/global ECDH
shares and BIP-374 DLEQ proofs. Proof verification precedes output acceptance or
signing. BIP-376 fields carry the SP tweak/base spend-key origin. The specialized
wallet stores imported base keys with an unspecified zero fingerprint; it does
not claim an xpub derivation path it cannot verify. Draft fields are not a database
format. Draft updates enter through adapter revisions and migration tests.

`adapters.psbt_document.Document` supports unresolved SP output maps and resolves
outputs only after complete validated share coverage. `validate(strict_inputs=False)`
is a **reference fixture inspection mode**, not a signing path. It explicitly
reports unbound inputs. `resolve`, `PSBT.sign` and wallet signing always bind keys
to UTXO scripts and validate supplied Taproot origin commitments.

The official pinned BIP-375 corpus has 20 valid/23 invalid field-level cases.
Sixteen "valid" fixtures contain public keys that do not match their witness
UTXO HASH160; case 12 also has inconsistent Taproot origin metadata. Field-level
compatibility is tested, and these fixtures must separately fail strict input
binding. This discrepancy is recorded in audit/FINDINGS.md; it is not ignored.

WAM Core v0.1.11 accepts PSBTv0. `core_v0_export` first verifies/finalizes the v2
transaction, then explicitly removes completed SP draft derivation metadata for
Core handoff. Other unknown fields remain. Generic `to_v0` rejects draft fields
rather than discarding them. This handoff is exercised against Core decodepsbt
and finalizepsbt, including equality of the final raw transaction.

Offline requests use encrypted approved-intent sidecars, not proprietary PSBT
fields replacing standards. `wam-sp-signer` takes private files and asks for
passwords through a terminal; passwords/keys are never command arguments. Hardware
transport and general multisig/script-path signing are not implemented signing
policies; unsupported input policies fail closed. The protocol scan layer still
handles all eligible BIP-352 input classes.
