"""
Shared test harness for the M3 Checkpoint 3 suite.

Every test runs against REAL Linux inotify events: the HoneyfileWatcher runs in
a background thread on a per-test temporary test_lab, and the tests drive it with
genuine filesystem operations (open/read, write, rm, mv). Nothing about inotify
is mocked.

Fast-but-real timing: the watcher uses a short cooldown and a short move-match
window so the suite stays quick; the logic exercised is identical to production.
"""

import os
import sys
import time
import shutil
import tempfile
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import m3_checkpoint3 as c3          # noqa: E402
from decoy_registry import DecoyRegistry  # noqa: E402

DECOYS = ["report.txt", "budget.txt", "notes.txt"]  # d1, d2, d3 in order
CONTROL = "real_user_file.txt"

# short, real timings for the test suite
TEST_COOLDOWN = 1.0
TEST_MOVE_WINDOW = 0.4
POLL_MS = 80


class Harness:
    """Owns a temp test_lab, a registry, and a running watcher thread."""

    def __init__(self, cooldown=TEST_COOLDOWN, move_window=TEST_MOVE_WINDOW):
        self.base = tempfile.mkdtemp(prefix="m3cp3_")
        self.docs = os.path.join(self.base, "documents")
        os.makedirs(self.docs)
        self.registry_file = os.path.join(self.base, "registry.json")

        self.reg = DecoyRegistry()
        for name in DECOYS:
            p = os.path.join(self.docs, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write("placeholder decoy content\n")
            self.reg.add(p)
        with open(os.path.join(self.docs, CONTROL), "w", encoding="utf-8") as f:
            f.write("ordinary non-decoy file\n")
        self.reg.save(self.registry_file)

        self.alerts = []
        self.watcher = c3.HoneyfileWatcher(
            self.reg, registry_file=self.registry_file,
            cooldown=cooldown, move_match_window=move_window,
            on_alert=self.alerts.append, verbose=False,
        )
        self._thread = None

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self.watcher.run,
                                        kwargs={"poll_ms": POLL_MS}, daemon=True)
        self._thread.start()
        time.sleep(0.25)  # let the first blocking read arm
        return self

    def stop(self):
        if self._thread is not None:
            self.watcher.stop()
            self._thread.join(timeout=5)
            self._thread = None

    def close(self):
        self.stop()
        shutil.rmtree(self.base, ignore_errors=True)

    # -- paths -------------------------------------------------------------
    def path(self, name):
        return os.path.join(self.docs, name)

    def external(self, name):
        return os.path.join(self.base, name)  # a dir that is NOT watched

    # -- real filesystem operations ---------------------------------------
    def read(self, name):
        with open(self.path(name), "r", encoding="utf-8") as f:
            f.read()

    def write(self, name, text="more\n"):
        with open(self.path(name), "a", encoding="utf-8") as f:
            f.write(text)

    def delete(self, name):
        os.remove(self.path(name))

    def rename(self, old, new):
        os.rename(self.path(old), self.path(new))

    def move_out(self, name):
        os.rename(self.path(name), self.external(name))

    def move_in(self, name):
        os.rename(self.external(name), self.path(name))

    # -- waiting -----------------------------------------------------------
    def wait(self, predicate, timeout=4.0):
        """Poll until predicate() is true or timeout; returns predicate()."""
        end = time.time() + timeout
        while time.time() < end:
            if predicate():
                return True
            time.sleep(0.03)
        return predicate()

    def ops(self, operation=None, decoy_id=None):
        out = self.alerts
        if operation is not None:
            out = [a for a in out if a.operation == operation]
        if decoy_id is not None:
            out = [a for a in out if a.decoy_id == decoy_id]
        return out

    def wait_count(self, operation, n, timeout=4.0):
        self.wait(lambda: len(self.ops(operation)) >= n, timeout)
        return self.ops(operation)


@pytest.fixture
def harness():
    h = Harness().start()
    try:
        yield h
    finally:
        h.close()
