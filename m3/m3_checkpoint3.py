"""
AI-RDR | M3 Honey-File Deception
Checkpoint 3 - production-quality detection

Built directly on top of Checkpoint 1/2:
  - same Decoy_Registry (decoy_registry.py), same test_lab layout,
  - same WATCH_MASK, same "fire on first interaction" philosophy,
  - the Checkpoint 2 READ/WRITE alert is preserved unchanged in meaning.

Checkpoint 3 adds:
  A. Operation-aware alert de-duplication (cooldown keyed on
     (decoy_id, logical_operation) instead of path only, monotonic clock,
     bounded state).
  B. Honeyfile DELETION detection.
  C. Honeyfile RENAME detection (MOVED_FROM/MOVED_TO correlated by cookie).
  D. Honeyfile MOVE detection (out of / into a monitored directory), with
     honest handling of unobservable destinations.
  E. Registry <-> watch synchronisation (atomic registry writes, watch
     add/remove, Q_OVERFLOW recovery).

------------------------------------------------------------------------
Raw inotify event  ->  logical operation  (documented mapping)
------------------------------------------------------------------------
    IN_ACCESS                       -> READ
    IN_CLOSE_WRITE                  -> WRITE   (NOT IN_MODIFY: a write burst
                                               produces many MODIFY events but
                                               exactly one CLOSE_WRITE, so we
                                               alert once per logical write)
    IN_DELETE (name in watched dir) -> DELETE
    IN_MOVED_FROM + IN_MOVED_TO     -> RENAME  (same cookie, both sides seen)
    IN_MOVED_FROM only              -> MOVE_OUT (destination not observable)
    IN_MOVED_TO only                -> MOVE_IN  (source not observable)

IN_OPEN / IN_MODIFY / IN_CREATE / IN_ATTRIB are intentionally NOT treated as
security incidents on their own; they are the low-level noise that A collapses.

Limits of inotify that this module does NOT pretend to overcome:
  - inotify never reports WHICH process caused an event (no PID); process
    attribution would need M1's audit telemetry. (Kerrisk, 2026)
  - inotify directory watches are NOT recursive; a move out of the watched
    tree cannot reveal its destination, and we never invent one.
  - the kernel event queue can overflow (IN_Q_OVERFLOW); we detect it, warn,
    and re-synchronise watches rather than silently losing state.
"""

import os
import sys
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, List, Dict

from inotify_simple import INotify, flags
from decoy_registry import DecoyRegistry

# ---- test_lab layout (unchanged from Checkpoint 1/2) ---------------------
BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_lab")
DECOY_DIR = os.path.join(BASE, "documents")
REGISTRY_FILE = os.path.join(BASE, "registry.json")

PLACEHOLDER_DECOYS = ["report.txt", "budget.txt", "notes.txt"]
CONTROL_FILE = "real_user_file.txt"

WATCH_MASK = (
    flags.ACCESS
    | flags.OPEN
    | flags.MODIFY
    | flags.CLOSE_WRITE
    | flags.MOVED_FROM
    | flags.MOVED_TO
    | flags.CREATE
    | flags.DELETE
    | flags.DELETE_SELF
    | flags.ATTRIB
)

COOLDOWN_SECONDS = 5
# How long to wait for a MOVED_TO to pair with a buffered MOVED_FROM before
# concluding the decoy was moved OUT of the monitored tree.
MOVE_MATCH_WINDOW = 1.0

# logical operations
OP_READ = "READ"
OP_WRITE = "WRITE"
OP_DELETE = "DELETE"
OP_RENAME = "RENAME"
OP_MOVE_OUT = "MOVE_OUT"
OP_MOVE_IN = "MOVE_IN"


@dataclass
class Alert:
    """One honeyfile security event. 'time' is a local wall-clock string for
    display only; the authoritative ordering uses the monotonic clock."""
    decoy_id: str
    path: str
    operation: str
    event_flags: list
    time: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    details: dict = field(default_factory=dict)


# ---- test_lab helpers (same behaviour as Checkpoint 1/2) -----------------
def build_test_files():
    os.makedirs(DECOY_DIR, exist_ok=True)
    for name in PLACEHOLDER_DECOYS:
        path = os.path.join(DECOY_DIR, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("placeholder decoy content\n")
    control_path = os.path.join(DECOY_DIR, CONTROL_FILE)
    if not os.path.exists(control_path):
        with open(control_path, "w", encoding="utf-8") as f:
            f.write("ordinary non-decoy file\n")


def build_registry():
    reg = DecoyRegistry()
    for name in PLACEHOLDER_DECOYS:
        reg.add(os.path.join(DECOY_DIR, name))
    reg.save(REGISTRY_FILE)
    return reg


def load_registry_safe(registry_file=REGISTRY_FILE):
    """Load a registry, tolerating a corrupted JSON file without destroying it.

    If the file is unreadable/corrupt it is preserved under a .corrupt-<ts>
    backup and a fresh empty registry is returned, so the watcher can still
    start and the bad copy is never overwritten by save()'s atomic replace.
    """
    try:
        return DecoyRegistry.load(registry_file)
    except FileNotFoundError:
        return DecoyRegistry()
    except (ValueError, OSError) as exc:  # JSONDecodeError is a ValueError
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{registry_file}.corrupt-{ts}"
        try:
            os.replace(registry_file, backup)
            print(f"[WARN] registry file was corrupt ({exc}); preserved as {backup}",
                  file=sys.stderr)
        except OSError:
            print(f"[WARN] registry file was corrupt ({exc}) and could not be backed up",
                  file=sys.stderr)
        return DecoyRegistry()


class HoneyfileWatcher:
    """Encapsulates Checkpoint 3 detection so it can be driven both by the
    live read loop (main) and by the automated tests (real inotify events)."""

    def __init__(self, reg: DecoyRegistry, registry_file: str = REGISTRY_FILE,
                 cooldown: float = COOLDOWN_SECONDS,
                 move_match_window: float = MOVE_MATCH_WINDOW,
                 on_alert: Optional[Callable[[Alert], None]] = None,
                 verbose: bool = False):
        self.reg = reg
        self.registry_file = registry_file
        self.cooldown = cooldown
        self.move_match_window = move_match_window
        self.on_alert = on_alert
        self.verbose = verbose

        self.inotify = INotify()
        self.wd_map: Dict[int, str] = {}   # wd -> directory
        self.dir_wd: Dict[str, int] = {}   # directory -> wd

        # Feature A: cooldown keyed on (decoy_id, operation), monotonic clock
        self._last_alert: Dict[tuple, float] = {}
        # Features C/D: buffered MOVED_FROM awaiting a MOVED_TO, keyed by cookie
        self._pending_from: Dict[int, dict] = {}

        self.alerts: List[Alert] = []      # full history (used by tests)
        self._stop = threading.Event()

        self.sync_watches()

    # ---- watch management (Feature E) ------------------------------------
    def _desired_dirs(self):
        """Directories we should be watching: every active decoy's dir, plus
        dirs a moved-out decoy could legitimately return to (so MOVE_IN is
        observable). Deleted decoys do not by themselves keep a watch alive."""
        desired = set(self.reg.watch_dirs())
        for d in self.reg.all_decoys():
            if not d.get("active", True) and d.get("deactivated_reason") == "moved_out":
                wd = d["watch_dir"]
                if os.path.isdir(wd):
                    desired.add(wd)
        return desired

    def sync_watches(self):
        desired = self._desired_dirs()
        current = set(self.wd_map.values())

        for directory in desired - current:
            if not os.path.isdir(directory):
                continue
            try:
                wd = self.inotify.add_watch(directory, WATCH_MASK)
                self.wd_map[wd] = directory
                self.dir_wd[directory] = wd
            except OSError as exc:  # permission / gone between check and add
                print(f"[WARN] could not watch {directory}: {exc}", file=sys.stderr)

        for directory in current - desired:
            wd = self.dir_wd.pop(directory, None)
            if wd is not None:
                self.wd_map.pop(wd, None)
                try:
                    self.inotify.rm_watch(wd)
                except OSError:
                    pass  # kernel may have auto-removed it (IGNORED)

    def _drop_watch(self, wd):
        directory = self.wd_map.pop(wd, None)
        if directory is not None:
            self.dir_wd.pop(directory, None)

    # ---- cooldown (Feature A) --------------------------------------------
    def _cooldown_ok(self, decoy_id, operation, now=None):
        now = time.monotonic() if now is None else now
        key = (decoy_id, operation)
        if now - self._last_alert.get(key, 0.0) < self.cooldown:
            return False
        self._last_alert[key] = now
        self._prune(now)
        return True

    def _prune(self, now):
        """Bound cooldown-state growth: forget entries older than the window."""
        self._last_alert = {k: t for k, t in self._last_alert.items()
                            if now - t < self.cooldown}

    # ---- alert emission ---------------------------------------------------
    def _emit(self, decoy_id, path, operation, event_flags, details=None):
        alert = Alert(decoy_id=decoy_id, path=path, operation=operation,
                      event_flags=list(event_flags), details=details or {})
        self.alerts.append(alert)
        # The alert block is always printed (this is the Checkpoint 2 output,
        # preserved). The per-event trace above it is what `verbose` gates.
        print(f"!!! HONEYFILE ALERT !!! Time: {alert.time}")
        print(f"File: {path}")
        print(f"Decoy ID: {decoy_id}")
        print(f"Operation: {operation}")
        if details:
            for k, v in details.items():
                print(f"  {k}: {v}")
        print(f"Event: {alert.event_flags}")
        if self.on_alert:
            self.on_alert(alert)
        return alert

    # ---- event handlers ---------------------------------------------------
    def _on_moved_from(self, cookie, path, directory):
        d = self.reg.find_active_by_path(path)
        if d is None:
            return  # a normal file left the dir; not our concern
        # buffer until we (maybe) see the paired MOVED_TO
        self._pending_from[cookie] = {
            "decoy_id": d["decoy_id"],
            "from_path": path,
            "at": time.monotonic(),
        }

    def _on_moved_to(self, cookie, path, directory, event_flags):
        info = self._pending_from.pop(cookie, None)
        if info is not None:
            # Features C/D: both sides observed -> rename/move within the tree
            decoy_id = info["decoy_id"]
            old_path = info["from_path"]
            self.reg.update_path(decoy_id, path)
            self._persist()
            self.sync_watches()
            if self._cooldown_ok(decoy_id, OP_RENAME):
                self._emit(decoy_id, path, OP_RENAME, event_flags,
                           details={"from": old_path, "to": path})
            return
        # No buffered FROM: this is a MOVE_IN candidate.
        known = self.reg.find_any_by_path(path)
        if known is not None and not known.get("active", True):
            self.reg.reactivate_moved_in(known["decoy_id"], path)
            self._persist()
            self.sync_watches()
            if self._cooldown_ok(known["decoy_id"], OP_MOVE_IN):
                self._emit(known["decoy_id"], path, OP_MOVE_IN, event_flags,
                           details={"source": "unobservable"})
        # else: an unregistered file arrived -> not a honeyfile, ignore

    def _on_delete(self, path, event_flags):
        d = self.reg.find_active_by_path(path)
        if d is None:
            return  # normal file deleted; stay silent
        decoy_id = d["decoy_id"]
        if self._cooldown_ok(decoy_id, OP_DELETE):
            self.reg.deactivate(decoy_id, reason="deleted")
            self._persist()
            self.sync_watches()
            self._emit(decoy_id, path, OP_DELETE, event_flags)

    def _maybe_access_write(self, path, operation, event_flags):
        d = self.reg.find_active_by_path(path)
        if d is None:
            return
        if self._cooldown_ok(d["decoy_id"], operation):
            self._emit(d["decoy_id"], path, operation, event_flags)

    def _handle_overflow(self):
        print("[WARN] inotify queue overflow (IN_Q_OVERFLOW) -- "
              "some events may have been lost; re-synchronising watches.",
              file=sys.stderr)
        # drop pending correlations we can no longer trust, then re-sync
        self._pending_from.clear()
        self.sync_watches()

    def _persist(self):
        try:
            self.reg.save(self.registry_file)
        except OSError as exc:
            # atomic save failed -> the previous good file is intact
            print(f"[WARN] could not persist registry ({exc}); "
                  "in-memory state kept, on-disk copy unchanged.", file=sys.stderr)

    # ---- the read loop ----------------------------------------------------
    def process_once(self, timeout_ms=500):
        """Read and handle one batch of events, then flush expired moves.
        Returns the Alerts produced in this cycle (handy for tests)."""
        before = len(self.alerts)
        for event in self.inotify.read(timeout=timeout_ms):
            self._handle_event(event)
        self._flush_pending_moves()
        return self.alerts[before:]

    def _handle_event(self, event):
        event_flags = flags.from_mask(event.mask)

        if flags.Q_OVERFLOW in event_flags or event.wd == -1:
            self._handle_overflow()
            return
        if flags.IGNORED in event_flags:
            self._drop_watch(event.wd)
            return

        directory = self.wd_map.get(event.wd)
        if directory is None:
            return
        name = event.name
        path = os.path.join(directory, name) if name else directory

        if self.verbose and name:
            is_decoy = self.reg.is_registered_decoy(path)
            print(f"Event: {event_flags} | File: {path}")
            print(f"File type : {'HONEYFILE' if is_decoy else 'NORMAL FILE'}")

        if flags.MOVED_FROM in event_flags:
            self._on_moved_from(event.cookie, path, directory)
        if flags.MOVED_TO in event_flags:
            self._on_moved_to(event.cookie, path, directory, event_flags)
        if flags.DELETE in event_flags:
            self._on_delete(path, event_flags)
        if flags.ACCESS in event_flags:
            self._maybe_access_write(path, OP_READ, event_flags)
        if flags.CLOSE_WRITE in event_flags:
            self._maybe_access_write(path, OP_WRITE, event_flags)

    def _flush_pending_moves(self, now=None):
        """A buffered MOVED_FROM with no paired MOVED_TO within the window
        means the decoy left the monitored tree (Feature D). We never invent
        a destination path."""
        now = time.monotonic() if now is None else now
        expired = [c for c, info in self._pending_from.items()
                   if now - info["at"] >= self.move_match_window]
        for cookie in expired:
            info = self._pending_from.pop(cookie)
            decoy_id = info["decoy_id"]
            self.reg.deactivate(decoy_id, reason="moved_out")
            self._persist()
            self.sync_watches()
            if self._cooldown_ok(decoy_id, OP_MOVE_OUT):
                self._emit(decoy_id, info["from_path"], OP_MOVE_OUT,
                           [flags.MOVED_FROM],
                           details={"destination": "unobservable (left monitored tree)"})

    # ---- lifecycle --------------------------------------------------------
    def run(self, poll_ms=500):
        try:
            while not self._stop.is_set():
                self.process_once(timeout_ms=poll_ms)
        except KeyboardInterrupt:
            print("\nCtrl+C received -- shutting down.")
        finally:
            self.close()

    def stop(self):
        self._stop.set()

    def close(self):
        try:
            self.inotify.close()
        except OSError:
            pass
        print("Watches closed cleanly. Checkpoint 3 complete.")


def main():
    build_test_files()
    reg = build_registry()

    print("=" * 60)
    print("AI-RDR M3 | Checkpoint 3 - Honeyfile detection")
    print("=" * 60)
    print(f"\nRegistry file: {REGISTRY_FILE}")
    print(f"\nRegistered decoys ({len(reg.active_decoys())}):")
    for decoy in reg.active_decoys():
        print(f"  [{decoy['decoy_id']}] {decoy['path']}")

    watcher = HoneyfileWatcher(reg, registry_file=REGISTRY_FILE, verbose=True)
    print(f"\nWatched directories ({len(watcher.wd_map)}):")
    for wd, directory in watcher.wd_map.items():
        names = [d["path"].split(os.sep)[-1] for d in reg.decoys_in(directory)]
        print(f"  wd={wd}  dir={directory}")
        print(f"  Decoys here: {', '.join(names)}")

    print("\nWatcher is running. Press Ctrl+C to stop.")
    watcher.run()


if __name__ == "__main__":
    main()
