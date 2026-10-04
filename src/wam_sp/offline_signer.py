"""Standalone, TTY-only two-stage offline signer. No RPC/network capability is used."""

import argparse
import getpass
from hashlib import sha256
import hmac
import os
from pathlib import Path
import sys

from .keystore import Keyring, load_private
from .psbt import PSBT
from .wallet import decode_request, Signer


def _password(getpass_fn, prompt):
    value = getpass_fn(prompt)
    if not isinstance(value, str):
        raise ValueError("PASSPHRASE_INPUT")
    return value.encode()


def _review_request(request, print_fn):
    if (
        not 1 <= len(request.intents) <= 128
        or not 1 <= len(request.coins) <= 128
        or type(request.fee) is not int
        or not 1 <= request.fee <= 1_000_000
        or type(request.change_epoch) is not int
        or not 0 <= request.change_epoch < 2**31
    ):
        raise ValueError("SIGNING_REQUEST_POLICY")
    for intent in request.intents:
        intent.validate()

    print_fn("REGTEST payment request review — amounts in atomic units")
    for intent in request.intents:
        print_fn(f"Recipient: {intent.code}  Amount: {intent.atoms}")
    print_fn(f"Inputs: {len(request.coins)}  Fee: {request.fee}")
    print_fn("Compare recipients, amounts and fee with your independently trusted request.")


def _with_keyring(keys_path, getpass_fn, prompt, action):
    ring = None
    try:
        ring = Keyring.restore(load_private(keys_path), _password(getpass_fn, prompt))
        return action(ring)
    finally:
        if ring is not None:
            ring.close()


def _review_prepared(prepared, print_fn):
    psbt = PSBT.decode(prepared.psbt)
    if any(sig is not None for sig in psbt.signatures):
        raise ValueError("PREPARED_ALREADY_SIGNED")
    total_in = sum(value for value, _ in psbt.utxos)
    total_out = sum(value for value, _ in psbt.tx.outputs)
    fee = total_in - total_out
    if fee != prepared.proposal.fee:
        raise ValueError("PREPARED_FEE_MISMATCH")

    fingerprint = sha256(prepared.psbt).hexdigest()
    print_fn("Prepared transaction review — exact bytes to be signed")
    print_fn(f"Inputs: {len(psbt.tx.inputs)}  Outputs: {len(psbt.tx.outputs)}  Fee: {fee}")
    for index, (amount, script) in enumerate(psbt.tx.outputs):
        print_fn(f"Output {index}: Amount: {amount}  Script: {script.hex()}")
    print_fn(f"PSBT SHA256: {fingerprint}")
    print_fn("The spend key is closed while this prepared transaction is reviewed.")
    return fingerprint


def _write_signed(path, signed):
    target = Path(path)
    if target.parent.is_symlink() or (
        os.name == "posix" and target.parent.stat().st_mode & 0o077
    ):
        raise ValueError("PRIVATE_DIRECTORY_REQUIRED")
    fd = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(signed)
        stream.flush()
        os.fsync(stream.fileno())


def run(keys_path, request_path, output_path, getpass_fn=getpass.getpass, input_fn=input, print_fn=print):
    request = decode_request(
        load_private(request_path),
        _password(getpass_fn, "Request passphrase: "),
    )
    _review_request(request, print_fn)
    if input_fn("Type REVIEW to continue to key unlock: ") != "REVIEW":
        print_fn("CANCELLED")
        return 1

    prepared = _with_keyring(
        keys_path,
        getpass_fn,
        "Key backup passphrase (prepare): ",
        lambda ring: Signer(ring).prepare(request),
    )
    fingerprint = _review_prepared(prepared, print_fn)

    expected = f"SIGN {fingerprint}"
    response = input_fn(
        f"Type {expected} to approve this exact prepared transaction: "
    )
    if not hmac.compare_digest(response, expected):
        print_fn("CANCELLED")
        return 1

    signed_raw = _with_keyring(
        keys_path,
        getpass_fn,
        "Key backup passphrase (sign): ",
        lambda ring: Signer(ring).sign(prepared, request.intents, request.fee),
    )
    signed_psbt = PSBT.decode(signed_raw)
    signed_psbt.finalize()
    _write_signed(output_path, signed_psbt.base64().encode())
    print_fn("SIGNED_PSBT_SAVED")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Experimental WAM REGTEST offline signer; no real funds"
    )
    parser.add_argument("--keys", required=True, help="Encrypted keyring")
    parser.add_argument("--request", required=True, help="Encrypted intent sidecar")
    parser.add_argument("--output", required=True, help="New signed PSBT file (0600)")
    args = parser.parse_args()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("INTERACTIVE_TERMINAL_REQUIRED")
        return 1
    try:
        return run(args.keys, args.request, args.output)
    except (Exception, KeyboardInterrupt):
        print("SIGNER_FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
