# Cryptographic primitives and assumptions

* Curve and group order: secp256k1 via coincurve 21.0.0/libsecp256k1. No Python
  elliptic-curve implementation is used in production; the independent test oracle
  has its own reference arithmetic and never enters the installed runtime wheel.
* Signatures: native BIP-340 Schnorr; BIP-341 key-path sighash assembled by bounded
  transaction code, compared with actual WAM Core finalization/broadcast acceptance.
* BIP-352: tagged SHA256, compressed-point ECDH, x-only output keys and labels.
  crypto.shared_point uses libsecp256k1_ecdh plus a raw-compressed-point callback;
  coincurve's default hashed ECDH output is deliberately not substituted.
* BIP32: HMAC-SHA512 plus native private-key tweaks. Invalid child derivations
  fail explicitly rather than silently choosing a different deterministic path.
* BIP374: pinned DLEQ tagged-hash proof algorithm, native curve/scalar operations,
  public verification; all official generation/verification rows tested.
* Encryption: cryptography 50.0.0 AES256GCM and scrypt. Nonce/salt/seed randomness
  uses OS-backed secrets. Network/version/purpose binds encrypted envelopes.
* Legacy derivation: old authenticated v2 wallets retain their exact HMAC-SHA256
  domain-separated hierarchy solely for recovery compatibility.

Security depends on discrete-log assumptions, correct primitives/interpreter,
sufficient backup password entropy and an uncompromised signer. Python scalar
handling/memory is not claimed constant-time or securely erasable. No independent
review of this composition has occurred. Version inventory and original notices
are in dependencies.json, THIRD_PARTY.md and upstream/.
