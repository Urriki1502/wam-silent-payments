# Recovery, backups and upgrades

A WSP recovery bundle is authenticated AES-256-GCM with a random 16-byte salt and
12-byte nonce, using scrypt N=32768, r=8, p=1 and a 32-byte derived key. Associated
data binds the envelope version, WAM regtest genesis and purpose. Password length
is 12–1024 bytes; length alone does not guarantee entropy. Use an independently
stored strong passphrase. Wrong passwords and tampering share a fixed error.

The encrypted JSON payload includes profile/version/network/schema, encrypted
seed/derivation algorithm/epochs, stable scan descriptors, birthdays, exact label
sets, private contacts, reservations, merchant intents and outbox delivery state.
A canonical SHA256 checksum additionally detects malformed inner data; it does not
replace AEAD authentication. Scan/spend secrets and raw bundles never enter logs.

## Complete procedure

1. Create `wallet.backup(offline_keyring, password)` in a trusted context and write
   it using `keystore.save_private`. Keep independent copies and the password.
   Combining keys and scan metadata for backup is a privileged operation.
2. Test restore in a private new directory; do not overwrite the active database.
3. After loss/corruption, call `SilentWallet.restore(envelope,password,new_path)`.
   Authentication and identity checks precede creation of usable state. Failed
   local-state validation deletes only the newly created failed restore database.
4. Scan the same pinned network from the recorded account birthdays/genesis through
   a validating full node. Only then inspect balances/history and construct spends.
5. Match known payments and labels, retain irreversible exported-signature locks,
   create a fresh encrypted backup and resume applications.

Database contents are not the source of funds ownership: keys, exact derivation
algorithm and labels reconstruct ownership. Tests delete the entire database,
restore and rescan, then compare balances, labels/history and sign a valid spend.
Invoice metadata/contacts cannot be reconstructed from the blockchain; only the
most recent backup preserves them. No system can recover labels or invoice data
created after the last backup merely from a seed without a recorded search bound.

Legacy v0.2 key envelopes retain their exact `legacy-v2` HMAC hierarchy. New keys
use BIP32 m/352'/1'/account'/role'/0 (spend role 0', scan role 1') for regtest. Never
reinterpret old seeds as the new hierarchy. Legacy key-only backups cannot restore
contacts/reservations they never contained. See MIGRATION.md.

The SQLite file contains sensitive plaintext metadata and must stay on a protected
host/encrypted volume. AEAD protects backup/key exports, not running Python memory,
swap, screenshots or a compromised endpoint. Best-effort seed clearing is provided
by Keyring.close; temporary Python/native copies cannot be guaranteed erased.
