"""Common interface for all threat-intelligence providers.

To add or swap a source (e.g. MISP later), write one subclass that sets
`name` and `supported_types` and implements `_lookup()`. Nothing else in M4
changes.
"""
from abc import ABC, abstractmethod
from typing import FrozenSet

from ..schema import STATUS_ERROR, ProviderResult


class Provider(ABC):
    name: str = "base"
    supported_types: FrozenSet[str] = frozenset()
    #: True for noisy community sources (OTX): their hits can never on their
    #: own make an indicator "malicious".
    context_only: bool = False

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        """Look up one normalised indicator. NEVER raises.

        Any unexpected exception becomes a ProviderResult with status
        "error", so one broken provider can never break alert handling.
        """
        if not self.supports(ioc_type):
            return self.error(f"type '{ioc_type}' not supported")
        try:
            return self._lookup(ioc_type, value)
        except Exception as exc:  # last line of defence; see docstring
            return self.error(f"unexpected {type(exc).__name__}: {exc}")

    @abstractmethod
    def _lookup(self, ioc_type: str, value: str) -> ProviderResult:
        """Provider-specific lookup. May raise; lookup() catches it."""

    def close(self) -> None:
        """Release resources (HTTP sessions). No-op by default."""
        http = getattr(self, "_http", None)
        if http is not None:
            http.close()

    def error(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.name, status=STATUS_ERROR, error=message)
