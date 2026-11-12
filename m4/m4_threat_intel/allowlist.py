"""Local allowlist: the ONLY source of a "clean" verdict.

JSON file (path in M4_ALLOWLIST_PATH), e.g. data/allowlist.example.json:
    {"hash": ["<sha256>"], "ip": ["203.0.113.10"], "domain": ["example.org"]}

Exact match on the normalised value: allowlisting "example.org" does NOT
allowlist "evil.example.org". A malformed entry stops start-up.
"""
import json
from typing import Dict, Iterable, Optional

from .schema import INDICATOR_TYPES, normalize


class Allowlist:
    def __init__(self, entries: Optional[Dict[str, Iterable[str]]] = None):
        self._entries = {t: set() for t in INDICATOR_TYPES}
        for ioc_type, values in (entries or {}).items():
            if ioc_type not in self._entries:
                raise ValueError(f"unknown allowlist section: {ioc_type!r}")
            for value in values:
                self._entries[ioc_type].add(normalize(ioc_type, value))

    @classmethod
    def from_file(cls, path: Optional[str]) -> "Allowlist":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def contains(self, ioc_type: str, normalized_value: str) -> bool:
        return normalized_value in self._entries.get(ioc_type, ())
