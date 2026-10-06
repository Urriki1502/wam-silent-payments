# Security policy

External audit status: **pending**. This qualification package has no mainnet
release tag. Its verified operational scope is WAM Core v0.1.11 regtest on Linux.

Review THREAT_MODEL.md, RECOVERY.md, PSBT.md and audit/README.md before integrating.
Use a local validating full node, private directories and a separate offline
signer. Verify recipient/amount/fee against an independent trusted request. Never
provide a scan server with the seed/base spend secret; scan credentials themselves
still expose history and must be encrypted when transported.

Production logging accepts fixed event names and bounded integer counters only.
Debug mode permits more counters, not secrets or arbitrary text. Do not add raw
RPC errors, serialized exceptions, transaction maps, addresses, PSBTs, backups,
seeds or any scan/spend/shared secret to application logs.

On suspected compromise: stop issuing addresses and broadcasting, preserve the
latest authenticated recovery bundle, isolate the affected host and reproduce
with synthetic fixtures. A fresh seed and a clean signer are required for master
seed/spend-key compromise; rotation alone cannot cure a stolen master seed.

Use the WAM project's verified private disclosure channel for security findings.
This package does not invent an official contact or send disclosures automatically.
Public reports must omit real secrets, RPC cookies and address/output mappings.
Include the exact source/report digest and minimal synthetic regression when safe.

Pinned dependencies and license inventory are in audit/dependencies.json.
Qualification reruns the advisory scanner; zero known advisories at that run is
not a proof of absence of vulnerabilities. Native wheels and the interpreter are
part of the supply-chain trust boundary. Do not release through a failing gate.
