# WSP-1 scanner lease portability — Windows x86 and x64

## Implementation (defensive / no consensus modification)

The legacy scanner imported POSIX-only `fcntl` at module load and called
`flock(LOCK_EX | LOCK_NB)` before scanning or modifying its SQLite state.
That import fails under both native Windows x86 and x64.

This branch introduces `src/wam_sp/file_lock.py` and routes scanner
`_lease` through it:

- macOS/Linux: preserve POSIX `flock` nonblocking exclusive semantics.
- Windows x86/x64: use native `kernel32.LockFileEx` with
  `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY`, locking byte 0
  of a persistent lockfile using a native `OVERLAPPED` structure.
  `ULONG_PTR` fields use pointer-size storage; both Windows architectures
  are verified in dedicated native runners.
- Return the existing `SCANNER_BUSY` error when another handle/process owns
  the lock; unexpected OS failures propagate rather than falling back.
- Explicit release on normal/exception exits, automatic release on process
  termination; the lock file itself is never removed.

A thread-only lock, no-op `fcntl` shim, or lockfile-existence flag is
**not** an acceptable substitute for operating-system-enforced exclusivity.

## Qualification / limitations

Dedicated tests check same-process and cross-process contention, clean and
crashed process release, exceptions, persistent lockfile data, symlink
rejection when supported, and the `OVERLAPPED` ABI layouts on both Windows
x86/x64. Full scanner/wallet regression is run on Windows **x64**, macOS and
Linux.

**Windows x86 native locking does not by itself qualify a complete 32-bit
WAM wallet.** Production WSP-1 packaging, Python cryptographic extension
availability, PySide6 GUI architecture support, WAM Core interoperability
and 32-bit integration testing require separate review. WSP-1 mainnet remains
disabled, and the upstream frozen baseline stays unchanged until the branch
is independently reviewed.

## Review gates

1. Source and ownership correctness review of ctypes/Win32 lock ABI.
2. Confirm no competing process can open a second exclusive lock.
3. Confirm abnormal process termination releases the OS lock.
4. CI green on Windows x86, Windows x64, macOS and Linux for native lock.
5. Scanner regression and existing conformance green on Windows x64/macOS/Linux.
6. Keep production usage disabled pending external review.
