# Compatibility matrix

| Component | Pin / support |
| --- | --- |
| WAM Core | v0.1.11, commit `8a3f4fe4f1d804c378f795d4cc281ec5125f75f3`, regtest |
| WAM SDK | 0.1.0 supplied source snapshot in integration-deps; actual WamClient/Transport tested |
| WSP | Profile WSP-1; API 1; package 1.0.0.dev0 pending release qualification/adoption |
| BIP-340 / 341 | Native Schnorr verification/signing; P2TR key-path default/ALL sighash |
| BIP-350 / 352 | Bech32m, BIP-352 version 1.1.1, v0 payloads; 28 official vector groups |
| BIP-370 | PSBTv2 map construction/parsing; bounded P2TR signing policy |
| BIP-374 | Draft 0.3.0, generation/verification official vectors |
| BIP-375 | Draft 0.1.2, all 43 field-level official cases; strict signer binding retained |
| BIP-376 | Draft at pinned revision, SP spend-key/tweak adapter |
| BIP-392 | Draft at pinned revision, single-key tspscan/tspspend expressions with origins |
| BIP-393 | Draft at pinned revision, bh/ml and preserved unknown numeric annotations |
| Persistence | SQLite 3; recovery 1; internal descriptor 1; legacy v0.2 imports |

Every BIP draft above is pinned to Bitcoin BIPs git revision
`3a10b5b5f0a7586df8928d580a3009744ebb2079`; version numbers alone are insufficient.
Vendored BIP-352 independent reference code is unchanged (BSD-2-Clause; bundled secp256k1lab MIT).

Descriptor two-key WIF/xprv/MuSig expressions are outside the supported descriptor
subset and rejected. Stable internal records still contain all required scan
identity, key origin, exact labels, birthday and network data. Import/export of
max-label descriptors expands the declared range, never assumes sparse labels.
SP address HRP `wamrtsp` is regtest-only and unregistered. Mainnet/testnet HD/network
profile decisions are intentionally unresolved, not silently inferred from Bitcoin.
