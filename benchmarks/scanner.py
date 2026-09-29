"""Synthetic disk-backed benchmark; no network, fixed seed and measured units."""

import json
from pathlib import Path
import resource
import sys
import tempfile
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_scanner_wallet import Chain, payment
from wam_sp.api import SilentWallet
from wam_sp.keystore import Keyring


def run(blocks=1000):
    ring = Keyring(bytes(range(32)))
    ring.add_label(0, 7)
    account = ring.accounts()[0]
    chain = Chain()
    for i in range(blocks):
        chain.append([payment(account, number=i + 1, label=7)])
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "wallet.db"
        w = SilentWallet(path, ring.accounts())
        try:
            start = perf_counter()
            metrics = w.scan(chain)
            scan = perf_counter() - start
            assert w.get_balance()["confirmed_atoms"] == blocks * 100000
            size = path.stat().st_size
            w.close()
            start = perf_counter()
            w = SilentWallet(path, ring.accounts())
            resume = w.scan(chain)
            restart = perf_counter() - start
            assert resume.blocks == 0
            encrypted = w.backup(ring, b"synthetic benchmark password")
            w.close()
            path.unlink()
            start = perf_counter()
            restored, w = SilentWallet.restore(encrypted, b"synthetic benchmark password", path)
            w.scan(chain)
            recovery = perf_counter() - start
            assert w.get_balance()["confirmed_atoms"] == blocks * 100000
            chain.blocks = chain.blocks[:-300]
            for _ in range(301):
                chain.append()
            start = perf_counter()
            m = w.scan(chain)
            reorg = perf_counter() - start
            assert (
                m.rollback == 300 and w.get_balance()["confirmed_atoms"] == (blocks - 300) * 100000
            )
            restored.close()
            return {
                "suite": "wsp-scanner-benchmark",
                "blocks": blocks,
                "transactions": metrics.transactions,
                "scan_seconds": scan,
                "blocks_per_second": blocks / scan,
                "transactions_per_second": metrics.transactions / scan,
                "database_bytes": size,
                "bytes_per_detected_output": size / blocks,
                "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "restart_seconds": restart,
                "restart_blocks_rescanned": resume.blocks,
                "reorg_depth": 300,
                "reorg_seconds": reorg,
                "recovery_seconds": recovery,
                "scope": "synthetic local chain, SQLite synchronous FULL; includes RPC adapter calls but no network latency",
                "result": "PASS",
            }
        finally:
            w.close()
            ring.close()


if __name__ == "__main__":
    report = run()
    Path("reports/benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
