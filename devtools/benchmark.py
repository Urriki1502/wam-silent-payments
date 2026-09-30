"""Synthetic repeatable microbenchmark. Timing numbers are NOT a constant-time proof."""

import json
from statistics import median
from time import perf_counter
from wam_sp.core import (
    Input,
    Receiver,
    prepare,
    pub,
    send,
    address,
    label_scalar,
    scalar,
    tagged,
    ser,
    N,
)
from wam_sp.transaction import p2wpkh
from coincurve import PublicKey


def run(samples=64, labels=999):
    bs, bd = 11, 29
    label_values = [0, *range(1, labels + 1)]
    started = perf_counter()
    receiver = Receiver(bs, pub(bd), range(1, labels + 1))
    setup = perf_counter() - started
    # Frozen v0.1-style linear label search for this single-output workload.
    old_offsets = [0] + [label_scalar(bs, m) for m in label_values]
    base = PublicKey(pub(bd))
    code = address(bs, pub(bd), labels)
    old_times = []
    new_times = []
    miss_times = []
    operations = []
    for i in range(samples):
        vin = Input(format(i + 1, "064x"), 0, p2wpkh(31), witness=(b"x", pub(31)), secret=31)
        point = prepare([vin])
        outputs = send([vin], [code])
        started = perf_counter()
        shared = PublicKey(point).multiply(ser(bs)).format()
        t = scalar(tagged("BIP0352/SharedSecret", shared + bytes(4)))
        old_match = None
        for offset in old_offsets:
            tweak = (t + offset) % N
            candidate = base if tweak == 0 else base.add(ser(tweak))
            if candidate.format()[1:] == outputs[0]:
                old_match = candidate.format()[1:]
                break
        old_times.append(perf_counter() - started)
        started = perf_counter()
        found = receiver.scan_prepared(point, outputs)
        new_times.append(perf_counter() - started)
        assert len(found) == 1 and found[0].public_key == old_match
        operations.append(receiver.operations)
        started = perf_counter()
        unrelated = receiver.scan_prepared(point, [pub(131)[1:]])
        miss_times.append(perf_counter() - started)
        assert not unrelated
    return {
        "suite": "wam-sp-v2-benchmark",
        "synthetic_samples": samples,
        "registered_labels": labels,
        "label_setup_ms": round(setup * 1000, 3),
        "linear_v01_style_median_ms": round(median(old_times) * 1000, 3),
        "v02_late_label_median_ms": round(median(new_times) * 1000, 3),
        "v02_unrelated_median_ms": round(median(miss_times) * 1000, 3),
        "relative_scan_speedup": round(median(old_times) / median(new_times), 2),
        "max_curve_operations_after_setup": max(operations),
        "constant_time_claim": False,
        "scope": "single-output synthetic scan; excludes RPC, disk and label setup",
    }


def main():
    try:
        result = run()
    except Exception:
        print('{"suite":"wam-sp-v2-benchmark","failed":true}')
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
