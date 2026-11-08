#!/usr/bin/env python3
"""
AI-RDR | M3 Honeyfile Deception — IN_Q_OVERFLOW stress test (STANDALONE)

This is a SEPARATE, OPT-IN stress test. It is intentionally NOT part of the
pytest regression suite (that suite lives in tests/ and is run with
`pytest tests/`). Run this one explicitly:

    python3 test_inotify_overflow_stress.py            # real-overflow attempt
    python3 test_inotify_overflow_stress.py --simulate # also run the simulated check
    python3 test_inotify_overflow_stress.py --events 40000 --timeout 10

What it does
------------
Phase 1 — Kernel capability (REAL):
    Independently proves a genuine kernel IN_Q_OVERFLOW can be produced on this
    machine, by flooding a disposable inotify watch and reading back the kernel's
    overflow marker. If the kernel never produces one here, the whole run is
    reported NOT VERIFIED (an environment limitation), never PASS.

Phase 2 — Watcher recovery (REAL):
    Drives a real HoneyfileWatcher into overflow on a disposable test_lab,
    confirms it (a) recognises the overflow and reports a degraded state, and
    (b) resumes correct monitoring afterwards (a fresh decoy READ still alerts).

Phase 3 — Simulated handler check (SIMULATED, only with --simulate):
    Feeds a synthetic overflow event object straight into the watcher's handler
    to exercise the code path without a kernel overflow. This is clearly labelled
    SIMULATED and can NEVER stand in for the real-overflow verdict.

Safety
------
  * Operates only inside tempfile.mkdtemp() directories; removes them at the end.
  * Never touches real user files; creates and unlinks throwaway files one at a
    time, so disk use stays near zero.
  * Never changes kernel settings and never needs root. It only READS
    /proc/sys/fs/inotify/max_queued_events to size the flood, and refuses to run
    an unreasonably large flood (reports NOT VERIFIED instead).

Exit codes:  0 = PASS,  2 = NOT VERIFIED,  1 = error/real defect.
"""

import argparse
import io
import os
import shutil
import sys
import tempfile
import time
from contextlib import redirect_stderr

from inotify_simple import INotify, flags

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import m3_checkpoint3 as c3          # noqa: E402
from decoy_registry import DecoyRegistry  # noqa: E402

FLOOD_MASK = (
    flags.CREATE | flags.DELETE | flags.MODIFY | flags.ATTRIB
    | flags.OPEN | flags.ACCESS | flags.CLOSE_WRITE | flags.CLOSE_NOWRITE
)
SAFETY_EVENT_CAP = 300_000   # refuse to churn more files than this


def read_threshold():
    try:
        with open("/proc/sys/fs/inotify/max_queued_events") as f:
            return int(f.read().strip())
    except OSError:
        return 16384  # documented Linux default


def flood_dir(directory, cycles):
    """Create+unlink `cycles` throwaway files (≈3-4 inotify events each).
    One file exists on disk at a time, so disk use stays negligible."""
    for i in range(cycles):
        p = os.path.join(directory, f"f{i}")
        fd = os.open(p, os.O_CREAT | os.O_WRONLY)
        os.close(fd)
        os.unlink(p)


# -------------------------------------------------------------------------
def phase1_kernel_capability(cycles, timeout_ms):
    """Prove a genuine kernel overflow is observable. Returns (observed, info)."""
    d = tempfile.mkdtemp(prefix="m3ovf_kernel_")
    ino = INotify()
    try:
        ino.add_watch(d, FLOOD_MASK)
        flood_dir(d, cycles)                 # flood WITHOUT reading
        time.sleep(0.1)
        observed = False
        total = 0
        # drain, looking for the kernel's overflow marker
        while True:
            evs = ino.read(timeout=timeout_ms)
            if not evs:
                break
            for e in evs:
                total += 1
                if flags.Q_OVERFLOW in flags.from_mask(e.mask) or e.wd == -1:
                    observed = True
        return observed, {"events_read": total}
    finally:
        ino.close()
        shutil.rmtree(d, ignore_errors=True)


def phase2_watcher_recovery(cycles, timeout_ms):
    """Drive a real HoneyfileWatcher into overflow and verify recovery.
    Returns (overflow_seen, degraded_reported, resumed, info)."""
    base = tempfile.mkdtemp(prefix="m3ovf_watcher_")
    docs = os.path.join(base, "documents")
    os.makedirs(docs)
    reg = DecoyRegistry()
    for n in ("report.txt", "budget.txt", "notes.txt"):
        p = os.path.join(docs, n)
        with open(p, "w") as f:
            f.write("decoy\n")
        reg.add(p)
    regfile = os.path.join(base, "registry.json")
    reg.save(regfile)

    alerts = []
    watcher = c3.HoneyfileWatcher(reg, registry_file=regfile,
                                  on_alert=alerts.append, verbose=False)
    try:
        # flood the watcher's OWN watched dir without letting it read
        flood_dir(docs, cycles)
        time.sleep(0.1)

        # drain while capturing the watcher's degraded-state report (stderr)
        err = io.StringIO()
        overflow_seen = False
        with redirect_stderr(err):
            empty_rounds = 0
            for _ in range(2000):
                produced = watcher.process_once(timeout_ms=timeout_ms)
                # did any event this round carry the overflow marker?
                # process_once hides raw events, so we detect via the warning text
                if "IN_Q_OVERFLOW" in err.getvalue():
                    overflow_seen = True
                if not produced:
                    empty_rounds += 1
                    if empty_rounds >= 3 and overflow_seen:
                        break
                    if empty_rounds >= 20:
                        break
                else:
                    empty_rounds = 0
        degraded_reported = "IN_Q_OVERFLOW" in err.getvalue()

        # recovery: after the storm, a clean decoy READ must still alert
        before = len(alerts)
        with open(os.path.join(docs, "report.txt")) as f:
            f.read()
        resumed = False
        for _ in range(40):
            watcher.process_once(timeout_ms=100)
            if any(a.operation == c3.OP_READ and a.decoy_id == "d1"
                   for a in alerts[before:]):
                resumed = True
                break
        still_watching = docs in watcher.wd_map.values()
        return overflow_seen, degraded_reported, (resumed and still_watching), {
            "stderr": err.getvalue().strip(),
        }
    finally:
        watcher.close()
        shutil.rmtree(base, ignore_errors=True)


def phase3_simulated(timeout_ms):
    """SIMULATED only: feed a synthetic overflow event into the handler.
    This never counts toward the real-overflow verdict."""
    base = tempfile.mkdtemp(prefix="m3ovf_sim_")
    docs = os.path.join(base, "documents")
    os.makedirs(docs)
    reg = DecoyRegistry()
    p = os.path.join(docs, "report.txt")
    open(p, "w").write("decoy\n")
    reg.add(p)
    regfile = os.path.join(base, "registry.json")
    reg.save(regfile)
    watcher = c3.HoneyfileWatcher(reg, registry_file=regfile, verbose=False)
    try:
        class _FakeEvent:
            wd = -1
            mask = int(flags.Q_OVERFLOW)
            cookie = 0
            name = ""
        err = io.StringIO()
        with redirect_stderr(err):
            watcher._handle_event(_FakeEvent())
        handled = "IN_Q_OVERFLOW" in err.getvalue()
        # monitoring still works afterwards
        before = len(watcher.alerts)
        with open(p) as f:
            f.read()
        resumed = False
        for _ in range(40):
            watcher.process_once(timeout_ms=100)
            if any(a.operation == c3.OP_READ for a in watcher.alerts[before:]):
                resumed = True
                break
        return handled, resumed
    finally:
        watcher.close()
        shutil.rmtree(base, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="M3 IN_Q_OVERFLOW stress test")
    ap.add_argument("--events", type=int, default=None,
                    help="create/unlink cycles to flood with "
                         "(default: max(threshold, 20000))")
    ap.add_argument("--timeout", type=int, default=5,
                    help="per-read timeout in seconds while draining (default 5)")
    ap.add_argument("--simulate", action="store_true",
                    help="also run the SIMULATED handler check")
    args = ap.parse_args()

    threshold = read_threshold()
    cycles = args.events if args.events is not None else max(threshold, 20000)
    est_events = cycles * 3  # ~3-4 inotify events per create/unlink cycle
    timeout_ms = max(1, args.timeout) * 1000

    print("=" * 68)
    print("AI-RDR M3 | IN_Q_OVERFLOW stress test")
    print("=" * 68)
    print(f"kernel max_queued_events : {threshold}")
    print(f"flood cycles             : {cycles}  (~{est_events} events est.)")
    print(f"environment              : Linux, no root, no kernel changes")

    if est_events > SAFETY_EVENT_CAP:
        print(f"\nRESULT: NOT VERIFIED")
        print(f"Reason: this kernel's max_queued_events ({threshold}) would need "
              f"more than the safety cap of {SAFETY_EVENT_CAP} events to overflow; "
              f"refusing to run so large a flood. Re-run with an explicit --events "
              f"if you accept the cost.")
        return 2

    # Phase 1 — real kernel capability
    print("\n[Phase 1] attempting a REAL kernel IN_Q_OVERFLOW ...")
    observed, info1 = phase1_kernel_capability(cycles, timeout_ms)
    print(f"  events read back        : {info1['events_read']}")
    print(f"  real kernel overflow    : {'OBSERVED' if observed else 'NOT observed'}")

    if not observed:
        print("\nRESULT: NOT VERIFIED")
        print("Reason: no genuine kernel IN_Q_OVERFLOW occurred in this "
              "environment, so real recovery cannot be honestly verified. "
              "(This is an environment limitation, not a PASS and not a defect.)")
        if args.simulate:
            handled, resumed = phase3_simulated(timeout_ms)
            print(f"\n[Phase 3 SIMULATED] handler recognised injected overflow: "
                  f"{handled}; monitoring resumed: {resumed}")
            print("NOTE: the simulated result is NOT a substitute for a real "
                  "kernel overflow and does not change the verdict above.")
        return 2

    # Phase 2 — real watcher recovery
    print("\n[Phase 2] driving the HoneyfileWatcher into REAL overflow ...")
    ov_seen, degraded, resumed, info2 = phase2_watcher_recovery(cycles, timeout_ms)
    print(f"  watcher saw overflow    : {ov_seen}")
    print(f"  degraded state reported : {degraded}")
    if info2.get("stderr"):
        first_line = info2["stderr"].splitlines()[0]
        print(f"    -> {first_line}")
    print(f"  monitoring resumed OK   : {resumed}")

    if args.simulate:
        handled, sim_resumed = phase3_simulated(timeout_ms)
        print(f"\n[Phase 3 SIMULATED] handler recognised injected overflow: "
              f"{handled}; monitoring resumed: {sim_resumed}")
        print("NOTE: simulated; shown for completeness, not part of the verdict.")

    if ov_seen and degraded and resumed:
        print("\nRESULT: PASS")
        print("A genuine kernel IN_Q_OVERFLOW was observed, the watcher reported "
              "the degraded state, re-synchronised, and monitoring resumed "
              "correctly afterwards.")
        return 0

    print("\nRESULT: FAIL")
    print("A real kernel overflow occurred but the watcher did not fully "
          "recognise and recover from it. This indicates a genuine defect to fix.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
