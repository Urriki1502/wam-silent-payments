"""Minimal node/block capability consumed by the Silent Payments scanner."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BlockSource(Protocol):
    """Chain-truth boundary. Deliberately exposes no wallet or signing capability."""

    def attest(self) -> None:
        """Authenticate/validate the configured source before chain reads."""
        ...

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Perform one bounded node/block-source request."""
        ...
