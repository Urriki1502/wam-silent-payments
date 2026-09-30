"""Exercise the actual signer executable over a private PTY using synthetic secrets."""

import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import time
import wam_sp
from wam_sp.keystore import save_private
from wam_sp.psbt import PSBT


def sign_in_process(directory, ring, request, password):
    directory = Path(directory)
    keys = directory / "offline-keys.enc"
    req = directory / "offline-request.enc"
    out = directory / "offline-response.psbt"
    save_private(keys, ring.backup(password))
    save_private(req, request)
    master, slave = pty.openpty()
    env = {k: os.environ[k] for k in ("PATH", "LD_LIBRARY_PATH") if k in os.environ}
    env["PYTHONPATH"] = str(Path(wam_sp.__file__).resolve().parent.parent)
    process = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "wam_sp.offline_signer",
                "--keys",
                str(keys),
                "--request",
                str(req),
                "--output",
                str(out),
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=directory,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        slave = -1
        pending = [
            (b"Key backup passphrase: ", password + b"\n"),
            (b"Request passphrase: ", password + b"\n"),
            (b"Type SIGN to approve exactly this payment: ", b"SIGN\n"),
        ]
        captured = b""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                captured += chunk
                if len(captured) > 65536:
                    raise ValueError("SIGNER_OUTPUT_LIMIT")
                if pending and pending[0][0] in captured:
                    _, response = pending.pop(0)
                    os.write(master, response)
                    captured = b""
            if process.poll() is not None:
                break
        if process.wait(timeout=2) != 0 or pending or not out.exists():
            raise ValueError("OFFLINE_SIGNER_FAILED")
        psbt = PSBT.from_base64(out.read_text())
        psbt.finalize()
        return psbt.encode()
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        if slave != -1:
            os.close(slave)
