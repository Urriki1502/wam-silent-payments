"""Native x86/x64 Windows and POSIX scanner lock regression tests.

Import the dependency-free lock module by file path, allowing x86 verification
without assuming third-party cryptographic extension wheels are available.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "wam_sp" / "file_lock.py"
HELPER = ROOT / "tests" / "helpers" / "hold_scanner_lock.py"
spec = importlib.util.spec_from_file_location("scanner_file_lock_test", MODULE)
assert spec is not None and spec.loader is not None
lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock)


class ScannerFileLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "scanner.db.scan.lock"

    def spawn_holder(self):
        ready = Path(self.tmp.name) / "ready"
        proc = subprocess.Popen(
            [sys.executable, str(HELPER), str(MODULE), str(self.path), str(ready)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def cleanup():
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=8)

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            if proc.poll() is not None:
                _, error = proc.communicate(timeout=4)
                self.fail("lock holder exited: " + error.decode(errors="replace"))
            time.sleep(0.025)
        self.assertTrue(ready.exists(), "lock holder never acquired lease")
        return proc

    def test_acquire_release_and_reacquire(self):
        with lock.exclusive_file_lock(self.path):
            self.assertTrue(self.path.exists())
        with lock.exclusive_file_lock(self.path):
            pass

    def test_second_descriptor_in_same_process_rejected(self):
        with lock.exclusive_file_lock(self.path):
            with self.assertRaisesRegex(ValueError, "^SCANNER_BUSY$"):
                with lock.exclusive_file_lock(self.path):
                    self.fail("double-locking violated exclusivity")

    def test_other_process_rejected_and_clean_exit_releases(self):
        proc = self.spawn_holder()
        with self.assertRaisesRegex(ValueError, "^SCANNER_BUSY$"):
            with lock.exclusive_file_lock(self.path):
                self.fail("competing process acquired locked file")
        proc.stdin.write(b"x")
        proc.stdin.flush()
        _, error = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, error.decode(errors="replace"))
        with lock.exclusive_file_lock(self.path):
            pass

    def test_forced_process_termination_releases_lease(self):
        proc = self.spawn_holder()
        with self.assertRaisesRegex(ValueError, "^SCANNER_BUSY$"):
            with lock.exclusive_file_lock(self.path):
                self.fail("lock acquired before holder termination")
        proc.kill()
        proc.communicate(timeout=8)
        with lock.exclusive_file_lock(self.path):
            pass

    def test_exception_releases_lease(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
            with lock.exclusive_file_lock(self.path):
                raise RuntimeError("synthetic failure")
        with lock.exclusive_file_lock(self.path):
            pass

    def test_lock_file_never_deleted_or_truncated(self):
        self.path.write_bytes(b"preserve-this-data\n")
        with lock.exclusive_file_lock(self.path):
            pass
        self.assertEqual(self.path.read_bytes(), b"preserve-this-data\n")

    def test_symlink_rejected_when_supported(self):
        target = Path(self.tmp.name) / "target"
        target.write_text("target", encoding="ascii")
        try:
            self.path.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink privileges unavailable")
        with self.assertRaisesRegex(ValueError, "^SCANNER_UNSAFE_LOCK_PATH$"):
            with lock.exclusive_file_lock(self.path):
                self.fail("followed an untrusted symlink")
        self.assertEqual(target.read_text(encoding="ascii"), "target")

    @unittest.skipUnless(os.name == "nt", "Only Windows uses native OVERLAPPED")
    def test_windows_structure_abi_matches_python_architecture(self):
        import ctypes

        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertEqual(ctypes.sizeof(lock._Overlapped), 20 if pointer_size == 4 else 32)
        self.assertEqual(lock._Overlapped.Offset.offset, 8 if pointer_size == 4 else 16)
        self.assertEqual(lock._Overlapped.hEvent.offset, 16 if pointer_size == 4 else 24)


if __name__ == "__main__":
    unittest.main()
