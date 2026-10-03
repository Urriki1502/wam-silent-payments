"""WSP public API v1. Coordinator owns scan credentials, never spend keys."""

from dataclasses import replace
from .profile import API_VERSION, PROFILE
from .block_source import BlockSource
from .scanner import Scanner
from .wallet import Wallet, Intent
from .descriptors import Descriptor


class SilentWallet:
    api_version = API_VERSION
    profile = PROFILE

    def __init__(self, path, accounts):
        self.scanner = Scanner(path, accounts)
        self.wallet = Wallet(self.scanner)

    def close(self):
        self.scanner.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def get_silent_address(self, epoch=None, label=None):
        return self._account(epoch).payment_code(label)

    def _account(self, epoch):
        if epoch is None:
            epoch = max(a.epoch for a in self.scanner.accounts)
        for a in self.scanner.accounts:
            if a.epoch == epoch:
                return a
        raise ValueError("UNKNOWN_EPOCH")

    def create_labeled_address(self, name="", epoch=None, label=None):
        if not isinstance(name, str) or len(name) > 128 or any(ord(c) < 32 for c in name):
            raise ValueError("LABEL_NAME")
        with self.scanner._lease():
            a = self._account(epoch)
            if label is None:
                label = max(a.labels, default=0) + 1
            if type(label) is not int or not 1 <= label < 2**32 or label in a.labels:
                raise ValueError("LABEL_ALREADY_ALLOCATED_OR_INVALID")
            updated = replace(a, labels=tuple(sorted((*a.labels, label))))
            accounts = tuple(updated if x.epoch == a.epoch else x for x in self.scanner.accounts)
            self.scanner.reconfigure(accounts)
            self.scanner.store.db.execute(
                "INSERT INTO labels VALUES(?,?,?)", (a.account_id, label, name)
            )
            # A crash after metadata commit consumes the label, never reuses it.
            return {"label": label, "address": updated.payment_code(label), "epoch": a.epoch}

    def descriptor(self, epoch=None):
        return Descriptor(self._account(epoch))

    def scan(self, rpc: BlockSource, max_blocks=None, mempool=False):
        metrics = self.scanner.sync(rpc, max_blocks=max_blocks)
        if mempool and self.scanner.ready:
            self.scanner.sync_mempool(rpc)
        return metrics

    def get_balance(self, min_confirmations=1):
        return self.wallet.balance(min_confirmations)

    def list_payments(self, limit=100, offset=0):
        self.scanner.assert_current()
        if (
            type(limit) is not int
            or not 1 <= limit <= 1000
            or type(offset) is not int
            or not 0 <= offset <= 1000000
        ):
            raise ValueError("PAYMENT_PAGE")
        tip = self.scanner.store.tip()[0]
        return [
            dict(r) | {"confirmations": tip - r["received"] + 1}
            for r in self.scanner.store.db.execute(
                "SELECT txid,vout,atoms,label,epoch,received,spent FROM coins ORDER BY received,txid,vout LIMIT ? OFFSET ?",
                (limit, offset),
            )
        ]

    def construct_payment(self, destinations, fee, **policy):
        return self.wallet.propose(
            tuple(Intent(code, value) for code, value in destinations), fee, **policy
        )

    def construct_spend(self, destinations, fee, **policy):
        return self.construct_payment(destinations, fee, **policy)

    def export_signing_request(self, proposal, password):
        return self.wallet.export_request(proposal, password)

    def broadcast(self, psbt, token, rpc):
        return self.wallet.broadcast(psbt, token, rpc)

    def history(self, **page):
        return self.wallet.history(**page)

    def backup(self, keyring, password):
        from .backup import create

        return create(keyring, self.scanner, password)

    @classmethod
    def restore(cls, envelope, password, path):
        from .backup import restore

        ring, scanner = restore(envelope, password, path)
        obj = cls.__new__(cls)
        obj.scanner = scanner
        obj.wallet = Wallet(scanner)
        return ring, obj


def create_silent_wallet(path, seed=None):
    from .keystore import Keyring

    ring = Keyring(seed)
    return ring, SilentWallet(path, ring.accounts())
