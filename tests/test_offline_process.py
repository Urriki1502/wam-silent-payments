import unittest
from pathlib import Path
from unittest import mock

from devtools.offline_process import _spawn_signer


class OfflineSignerProcessTests(unittest.TestCase):
    def test_spawn_starts_new_session_and_keeps_dedicated_pty(self):
        with mock.patch("devtools.offline_process.subprocess.Popen") as popen:
            _spawn_signer(
                ["python", "-m", "wam_sp.offline_signer"],
                41,
                Path("/tmp/wam-offline-test"),
                {"PATH": "/usr/bin"},
            )

        kwargs = popen.call_args.kwargs
        self.assertEqual(kwargs["stdin"], 41)
        self.assertEqual(kwargs["stdout"], 41)
        self.assertEqual(kwargs["stderr"], 41)
        self.assertTrue(kwargs["close_fds"])
        self.assertTrue(kwargs["start_new_session"])


if __name__ == "__main__":
    unittest.main()
