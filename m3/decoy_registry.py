"""
AI-RDR  |  M3 Honey-File / Deception path
decoy_registry.py  --  the Decoy_Registry (checkpoint 1)

Scope of THIS checkpoint:
  - hold the authoritative record of which files are decoys
  - expose the parent directories that must be watched
  - exact-path lookup only (no prefix / no filename-begins-with heuristic)

Out of scope here (later cards): decoy generation, rename tracking,
encrypted-variant detection, the event-trigger logic, and any external
M5/M6 alert contract. This class stores NO pid / Incident ID / external
timestamp — those belong to the future integration contract.

All fields below are IMPLEMENTATION-LOCAL to M3.
"""

import json
import os
from datetime import datetime, timezone


class DecoyRegistry:
    def __init__(self):
        # each entry: {decoy_id, path, watch_dir, active, registered_at}
        self._decoys = []
        self._seq = 0

    # ---- building the registry -------------------------------------------
    def add(self, path):
        """Register one decoy by absolute, symlink-resolved path.
        Exact path is the identity of the decoy. Returns the entry."""
        real = os.path.realpath(path)
        # ignore a duplicate exact path
        for d in self._decoys:
            if d["path"] == real:
                return d
        self._seq += 1
        entry = {
            "decoy_id": f"d{self._seq}",
            "path": real,
            "watch_dir": os.path.dirname(real),
            "active": True,
            # local bookkeeping only -- NOT the alert timestamp sent to M5/M6
            "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._decoys.append(entry)
        return entry

    # ---- persistence ------------------------------------------------------
    def save(self, registry_path):
        with open(registry_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "decoys": self._decoys}, f, indent=2)

    @classmethod
    def load(cls, registry_path):
        reg = cls()
        with open(registry_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        reg._decoys = data.get("decoys", [])
        reg._seq = len(reg._decoys)
        return reg

    # ---- read helpers -----------------------------------------------------
    def active_decoys(self):
        return [d for d in self._decoys if d.get("active", True)]

    def watch_dirs(self):
        """Unique parent directories of all active decoys."""
        return sorted({d["watch_dir"] for d in self.active_decoys()})

    def decoys_in(self, watch_dir):
        return [d for d in self.active_decoys() if d["watch_dir"] == watch_dir]

    def is_registered_decoy(self, path):
        """EXACT-PATH match only. Used later by the trigger logic.
        A file whose name merely starts with a decoy name (e.g.
        report.txt.backup vs report.txt) is deliberately NOT a match."""
        real = os.path.realpath(path)
        return any(d["path"] == real for d in self.active_decoys())
