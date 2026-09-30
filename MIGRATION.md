# Migration

Keep the existing v0.2 backup/database and test an isolated restored copy first.
Never change a seed's derivation algorithm in place.

* Key envelope v2 restores as `legacy-v2`; re-export writes payload v3 and retains
  that algorithm. New BIP32 accounts require a new wallet or explicit new keyring.
* SQLite user_version 0/2 migrates atomically to 3. Old v0.2 omitted spending txids,
  so blocks/coins/history are rebuilt by rescan; private contacts and conservative
  reservations remain. Interrupted migrations roll back through SQLite.
* Future database/recovery/profile versions fail closed. Recovery checks network,
  profile, version, identity and schema before restoring metadata.
* Wire descriptor/PSBT drafts are parsed into stable internal records. When a draft
  changes, add a revision-specific adapter plus old/new fixtures. Never rewrite
  stored keys, labels or recovery identities based on a new draft's text syntax.
* Existing v0.2 PSBTv0 values remain readable. New transactions use v2. Core handoff
  is explicit and verified; don't replace a stored signing request with its v0 export.

The clean-install test installs the built wheel in a fresh interpreter, restores
legacy key material, migrates a v0.2-shaped database, tests crash/restart and runs
black-box conformance. Downgrading schema 3 to an old binary is unsupported; use
preserved original files, not a live upgraded database.
