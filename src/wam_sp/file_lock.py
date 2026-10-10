"""Native, nonblocking inter-process scanner lease for POSIX and Windows x86/x64.

The lock file is persistent. Only the OS-level lock indicates ownership;
never delete the file or use a no-op fallback.
"""

from __future__ import annotations

import errno
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        """Win32 OVERLAPPED, with pointer-sized ULONG_PTR members."""

        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _lock_file_ex = _kernel32.LockFileEx
    _lock_file_ex.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    )
    _lock_file_ex.restype = wintypes.BOOL

    _unlock_file_ex = _kernel32.UnlockFileEx
    _unlock_file_ex.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    )
    _unlock_file_ex.restype = wintypes.BOOL

    _LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    _ERROR_LOCK_VIOLATION = 33


@contextmanager
def _locked_fd(fd: int) -> Iterator[None]:
    """Lock the same one-byte range on every platform and process."""
    if os.name == "nt":
        handle = msvcrt.get_osfhandle(fd)
        offset = _Overlapped()
        acquired = _lock_file_ex(
            handle,
            _LOCKFILE_FAIL_IMMEDIATELY | _LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            ctypes.byref(offset),
        )
        if not acquired:
            error = ctypes.get_last_error()
            if error == _ERROR_LOCK_VIOLATION:
                raise ValueError("SCANNER_BUSY") from None
            raise ctypes.WinError(error)
        try:
            yield
        finally:
            if not _unlock_file_ex(handle, 0, 1, 0, ctypes.byref(offset)):
                raise ctypes.WinError(ctypes.get_last_error())
    elif os.name == "posix":
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                raise ValueError("SCANNER_BUSY") from None
            raise
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        raise RuntimeError("SCANNER_LOCK_UNSUPPORTED_OS")


@contextmanager
def exclusive_file_lock(path: str | os.PathLike[str]) -> Iterator[None]:
    """Hold an OS-enforced exclusive scanner lock until exit or process death."""
    lock_path = Path(path)
    if lock_path.is_symlink():
        raise ValueError("SCANNER_UNSAFE_LOCK_PATH")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        with _locked_fd(fd):
            yield
    finally:
        os.close(fd)
