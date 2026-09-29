"""Standalone, TTY-only offline signer. No RPC/network capability is used."""

import argparse
import getpass
import os
from pathlib import Path
import sys
from .keystore import Keyring, load_private
from .psbt import PSBT
from .wallet import decode_request, Signer


def main():
    p = argparse.ArgumentParser(
        description="Experimental WAM REGTEST offline signer; no real funds"
    )
    p.add_argument("--keys", required=True, help="Encrypted v0.2 keyring")
    p.add_argument("--request", required=True, help="Encrypted intent sidecar")
    p.add_argument("--output", required=True, help="New signed PSBT file (0600)")
    args = p.parse_args()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("INTERACTIVE_TERMINAL_REQUIRED")
        return 1
    try:
        ring = Keyring.restore(
            load_private(args.keys), getpass.getpass("Key backup passphrase: ").encode()
        )
        request = decode_request(
            load_private(args.request), getpass.getpass("Request passphrase: ").encode()
        )
        signer = Signer(ring)
        prepared = signer.prepare(request)
        print("REGTEST payment approval — amounts in atomic units")
        for intent in request.intents:
            print(f"Recipient: {intent.code}  Amount: {intent.atoms}")
        print(f"Inputs: {len(request.coins)}  Fee: {request.fee}")
        print("Compare recipients and amounts with your independently trusted request.")
        if input("Type SIGN to approve exactly this payment: ") != "SIGN":
            print("CANCELLED")
            return 1
        signed = PSBT.decode(signer.sign(prepared, request.intents, request.fee)).base64().encode()
        path = Path(args.output)
        if path.parent.is_symlink() or (os.name == "posix" and path.parent.stat().st_mode & 0o077):
            raise ValueError("PRIVATE_DIRECTORY_REQUIRED")
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(signed)
            f.flush()
            os.fsync(f.fileno())
        print("SIGNED_PSBT_SAVED")
        return 0
    except (Exception, KeyboardInterrupt):
        print("SIGNER_FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
