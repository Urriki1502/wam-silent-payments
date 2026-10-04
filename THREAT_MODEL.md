# Privacy and security threat model

Silent Payments hides a public reusable destination's direct on-chain address
reuse. It is **not a Monero-like anonymity system**. Transaction amounts, timing,
inputs, fees and subsequent spends remain public. Privacy is conditional on
endpoint integrity, sender behavior, coin policy and trusted local node access.

| Adversary / asset | Control | Residual exposure / assumption |
| --- | --- | --- |
| Blockchain observer / chain analyst | BIP-352 fresh outputs; private label-0 change | Amount/timing correlation, input clustering and change heuristics remain |
| Malicious sender | Validating-node boundary; strict point/NUMS/input checks; bounded labels/work | Sender knows their payment and can fingerprint amount/time, dust or withhold a payment |
| Malicious receiver | Sender verifies address points, DLEQ, output derivation and approved intent | Receiver can publish malicious invoices or correlate off-chain identities |
| Malicious Electrum/indexer | No Electrum/indexer protocol is used | An arbitrary server is not a substitute for the validating-node trust boundary |
| RPC operator | Whole-block scans; no silent-address lookup parameters; loopback cookie RPC | Sees selected spend outpoints/broadcasts; malicious operator can lie or withhold chain data |
| ISP/network observer | Test RPC is loopback; no external telemetry or explorer queries | P2P broadcast timing/IP and traffic volume are not hidden; Tor routing is a separate deployment concern |
| Compromised scan server | Scan key is separate from spend key; scanner receives no seed/base spend secret | Reveals receipt mapping, labels and history; can suppress payments or falsify UI state |
| Compromised scan key | Cannot derive the independent base spend key | Enables retrospective/future scanning of that epoch; rotation does not erase old exposure |
| Compromised spend key | Distinct scan key limits automatic discovery | Spend key plus detected-output tweaks/scan data compromises funds; treat as an emergency |
| Leaked derived spend key | No API exports per-output private keys to application logs | Derived key plus its tweak reveals the epoch base spend key |
| Compromised wallet database | 0700 directory/0600 file; schema, chain and ownership validation | Plaintext metadata/tweaks/history/contact/invoice linkage exposed; structure checks are not authentication |
| Compromised encrypted backup | Scrypt + AES-256-GCM; version/network/purpose binding | Offline password guessing; old copies stay decryptable if password later leaks; no forward secrecy |
| Compromised backup plaintext/seed | No recovery secret in scanner or public reports | All derived epochs compromised; a new seed and trusted sweep are required |
| Log leakage | Allowlisted event names and integer counters; no raw exception export | Caller-created logs/screenshots/OS crash dumps are outside this logging module |
| Timing correlation | Bounded local processing; no public scan service | Match rates, labels, DB writes and native/Python operations vary in time; no full constant-time claim |
| Address reuse | Reusable silent address does not repeat the derived chain output | Reusing the address in websites/invoices links those off-chain contexts |
| Change heuristics | Reserved private change label 0, SP change construction | Amount/position and later coin use can still reveal change |
| Coin-selection leakage | One account/label cluster by default; explicit merge opt-in and coin control | Consolidation/coin control can reveal common ownership; cannot defeat arbitrary graph analysis |
| Application metadata | No automatic telemetry or public wallet identifiers; private address book | Application accounts, analytics, support tickets and clipboard history can reveal identity |
| Invoice metadata | Distinct registered label per intent; no spend key on merchant host; private durable outbox | Merchant necessarily knows invoice-to-payment mapping; webhook payloads require access control |
| Host/OS compromise | Separate signer role; encrypted exports; best-effort seed clearing | Root, malicious interpreter/dependency, swap, RAM and screen capture can defeat custody |

## Four independent boundaries

**On-chain:** BIP-352 unlinkability of reusable addresses, not hidden amounts or
transaction graph. **Network:** broadcast IP protection is not supplied by SP.
**Application:** invoice/contact history is sensitive even without private keys.
**Endpoint:** no protocol compensates for an infected signer or stolen plaintext
backup. Deploy and assess each boundary separately.

The at-rest artifact contract and machine-checked plaintext exclusions are
documented in [docs/PRIVACY_AT_REST.md](docs/PRIVACY_AT_REST.md). The live SQLite
database is explicitly treated as sensitive metadata, not encrypted storage.

The offline user sees intended destination/amount/fee for approval. Generated
output mappings are not placed in operational logs. PSBT carries standard SP
public derivation metadata and is therefore private transport, not safe telemetry.
Unknown PSBT fields may themselves contain sensitive data; preservation is an
interoperability requirement, not a statement that they are safe to publish.

A label allocation interrupted after identity commit can consume a label without
its optional display name. The label is never reused and remains recoverable.
A backup predating an invoice cannot reconstruct that invoice's off-chain data.
A structurally consistent but maliciously edited database requires a trusted
rescan; database checks do not provide tamper-proof storage or availability.
