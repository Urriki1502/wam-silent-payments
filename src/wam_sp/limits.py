"""Fail-closed resource limits for a research wallet; never skip oversized blocks."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_inputs: int = 2048
    max_outputs: int = 4096
    max_script: int = 10000
    max_witness_items: int = 1000
    max_transaction_bytes: int = 1_000_000
    max_block_transactions: int = 10000
    max_labels: int = 1000
    max_curve_operations: int = 100000
    max_accounts: int = 16
    max_reorg: int = 10000
    max_cache: int = 2048


DEFAULT = Limits()


def check_inputs(inputs, limits=DEFAULT):
    if not inputs or len(inputs) > limits.max_inputs:
        raise ValueError("INPUT_LIMIT")
    seen, size = set(), 0
    for i in inputs:
        outpoint = i.outpoint()
        if outpoint in seen:
            raise ValueError("DUPLICATE_INPUT")
        seen.add(outpoint)
        if (
            len(i.script) > limits.max_script
            or len(i.script_sig) > limits.max_script
            or len(i.witness) > limits.max_witness_items
        ):
            raise ValueError("SCRIPT_LIMIT")
        size += 36 + len(i.script) + len(i.script_sig) + sum(len(w) for w in i.witness)
        if size > limits.max_transaction_bytes:
            raise ValueError("TRANSACTION_LIMIT")
