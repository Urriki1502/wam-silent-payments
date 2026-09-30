# Key lifecycle and custody

New Keyring seeds are 32 random bytes from the OS CSPRNG. Import accepts an exact
32-byte seed; no BIP39 mnemonic interpretation is implied. BIP32 m/352'/1'/account'/
role'/0 provides separate scan/spend roles for the regtest profile. Authenticated
legacy-v2 imports keep the original network-bound HMAC derivation unchanged.

Export policy: applications receive public destination strings or encrypted scan
bundles. Only the offline signer receives Keyring. Recovery export is privileged
and contains the seed; signing-request export contains private intent/UTXO data
but no spend key. No API automatically writes a plaintext seed/derived private key.
`save_private` creates encrypted files exclusively with private permissions.

Rotate by creating a new epoch at the chosen birthday and reconfiguring the
scanner while retaining all old epochs/labels. Old published addresses cannot be
revoked; retain historical monitoring. Back up the new metadata before advertising
new destinations. Sparse labels need exact backup metadata, not a guessed range.

| Event | Procedure |
| --- | --- |
| Scan key/scan host leaked | Re-provision the host and publish a new epoch/address; old receipt privacy is permanently reduced |
| Base/derived spend key leaked | Stop use of that epoch; use a clean signer to sweep to a fresh independent keyring |
| Seed or decrypted recovery bundle leaked | Treat all existing/future epochs of that seed as compromised; use a new seed |
| Database corrupt or suspect | Preserve encrypted backups; restore into a new DB and rescan a trusted node |
| Wallet retirement | Stop invoice/address issuance, sweep intended funds with independently approved intent, retain historical scan/recovery records and never republish retired destinations |

After signing, close Keyring: its mutable seed buffer is overwritten and future
key/backup requests fail. This is best-effort disposal. CPython integers/bytes,
CFFI/native temporaries, garbage collector copies, swap and storage wear leveling
prevent a general secure-erasure guarantee. Removing files is not cryptographic
erasure. Use platform storage encryption and an independently reviewed custody
process; do not claim hardware-grade key isolation for a Python process.
