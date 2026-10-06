"""Runnable scan-only SDK/merchant setup with synthetic keys, no live RPC."""

from pathlib import Path
from tempfile import TemporaryDirectory
from wam_sp.api import create_silent_wallet, SilentWallet
from wam_sp.adapters.pay import Merchant
from wam_sp.adapters.watchtower import health


def main():
    with TemporaryDirectory() as d:
        ring, wallet = create_silent_wallet(Path(d) / "wallet.db", bytes(range(32)))
        try:
            invoice = Merchant(wallet).create_intent(100000, confirmations=6)
            assert invoice["destination"] == wallet.get_silent_address(label=1)
            assert "STALE_CHECKPOINT" in health(wallet.scanner)["signals"]
            envelope = wallet.backup(ring, b"synthetic demonstration password")
            recovered, other = SilentWallet.restore(
                envelope, b"synthetic demonstration password", Path(d) / "restored.db"
            )
            try:
                assert other.get_silent_address(label=1) == invoice["destination"]
            finally:
                other.close()
                recovered.close()
        finally:
            wallet.close()
            ring.close()
    print("API / merchant / encrypted recovery: PASS")


if __name__ == "__main__":
    main()
