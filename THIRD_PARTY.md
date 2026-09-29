# Third-party provenance and licenses

Bitcoin BIPs snapshot: `3a10b5b5f0a7586df8928d580a3009744ebb2079`.
Source: https://github.com/bitcoin/bips/tree/3a10b5b5f0a7586df8928d580a3009744ebb2079

* BIP-352 vectors/reference: BSD-2-Clause; authors josibake, Ruben Somsen and
  Sebastian Falbesoner. License retained in tests/vectors/LICENSE. Independent
  reference and secp256k1lab are unchanged/test-only, not runtime cryptography.
* BIP-374 generation/verification CSVs and BIP-375 JSON: verbatim pinned upstream
  files. Their specification/source license notices are retained alongside vectors.
* secp256k1lab: MIT; notice in tests/reference/secp256k1lab/COPYING.
* coincurve 21.0.0: MIT OR Apache-2.0, native libsecp256k1 wrapper; external package.
* cryptography 50.0.0: Apache-2.0 OR BSD-3-Clause, AES-GCM/scrypt; external package.
* cffi 2.1.1: MIT-0. pycparser 3.0: BSD-3-Clause. Native libraries bundled in wheels
  have their own retained distribution notices; do not strip them when packaging.
* WAM SDK 0.1.0: supplied source snapshot under integration-deps/wam-sdk, MIT notice
  retained. Harness node/RPC/privacy/error helpers derive from this contribution.
* WAM Core: source/binary not redistributed here. Verified v0.1.11 Linux x86_64
  binary digest appears in README and real-node qualification configuration.

Machine-readable runtime requirements/licenses: audit/dependencies.json. Vendored
spec/source notices must be retained on redistribution; package metadata does not
replace upstream license text. Dev-tool licenses remain with their distributions.
