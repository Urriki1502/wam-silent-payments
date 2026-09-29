# Internal timing and resource review

Secret ECDH uses libsecp256k1_ecdh with a callback serializing the raw compressed
point required by BIP-352. Native PrivateKey tweaks implement scalar product/sum
helpers and BIP32 tweaks. BIP-340 signing uses native Schnorr operations. Public
verification/output construction use public point operations.

Python still handles secret scalar representation, parity selection, reductions,
HMAC outputs, key lifetimes and label lookup. There is no whole-program constant-
time or reliable zeroization claim. Hit/miss, label count, DB commits and coin
selection affect runtime. The library exposes no unauthenticated network scan API.

Parser, transaction, label, curve, cache, mempool, database and reorg bounds are
explicit. A limit failure leaves scanning incomplete, never silently omits funds.
Performance tests include 1000 synthetic disk-backed blocks, restart, 300-block
rollback, full database-loss recovery and maximum resident memory. The older
single-output label microbenchmark remains available separately. Neither benchmark
is a side-channel security proof. Independent cryptographic/custody review remains
an external release requirement.
