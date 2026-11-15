"""
Checkpoint 3 feature suite — real Linux inotify events throughout.

Maps to the M3 Test Plan 'Proposed Checkpoint 3 enhancements':
  M3-UT-011 distinct operation within cooldown still alerts   (Feature A)
  M3-UT-012 deletion of a decoy raises an alert               (Feature B)
  M3-UT-013 rename of a decoy raises an alert                 (Feature C)
  M3-UT-014 move out of / into the monitored directory        (Feature D)
  M3-UT-015 registry accuracy after a path change             (Feature E)
plus operation-mapping, cooldown-bounding, and Linux edge cases.
"""

import os
import time

from inotify_simple import flags
from decoy_registry import DecoyRegistry
from conftest import Harness, TEST_COOLDOWN


# ---- Feature A: operation-aware de-duplication --------------------------
def test_m3_ut_011_distinct_operation_within_cooldown(harness):
    # READ then WRITE on the SAME decoy inside the cooldown window.
    harness.read("report.txt")
    harness.wait_count("READ", 1)
    harness.write("report.txt")            # well within TEST_COOLDOWN
    harness.wait_count("WRITE", 1)
    reads = harness.ops("READ", decoy_id="d1")
    writes = harness.ops("WRITE", decoy_id="d1")
    assert len(reads) == 1 and len(writes) == 1   # not cross-suppressed


def test_operation_aware_independent_decoys(harness):
    harness.read("report.txt")
    harness.read("budget.txt")
    harness.wait(lambda: len(harness.ops("READ")) >= 2)
    assert {a.decoy_id for a in harness.ops("READ")} == {"d1", "d2"}


def test_cooldown_state_is_bounded(harness):
    w = harness.watcher
    base = time.monotonic()
    # simulate many distinct (decoy, op) keys spread over time
    for i in range(1000):
        w._cooldown_ok(f"d{i}", "READ", now=base + i * 10.0)
    # pruning keeps only entries newer than the cooldown window
    assert len(w._last_alert) <= 2


# ---- Feature B: deletion detection --------------------------------------
def test_m3_ut_012_deletion_raises_alert(harness):
    harness.delete("notes.txt")            # d3
    alerts = harness.wait_count("DELETE", 1)
    assert len(alerts) == 1 and alerts[0].decoy_id == "d3"
    # registry stays consistent: d3 now inactive, d1/d2 still active
    assert harness.reg.get("d3")["active"] is False
    assert {d["decoy_id"] for d in harness.reg.active_decoys()} == {"d1", "d2"}
    # ...and the inactive state is persisted on disk
    disk = DecoyRegistry.load(harness.registry_file)
    assert disk.get("d3")["active"] is False


def test_deleting_normal_file_is_silent(harness):
    os.remove(harness.path("real_user_file.txt"))
    time.sleep(0.6)
    assert harness.ops("DELETE") == []


# ---- Feature C: rename detection ----------------------------------------
def test_m3_ut_013_rename_raises_alert_and_preserves_identity(harness):
    harness.rename("budget.txt", "budget_renamed.txt")   # d2, same dir
    alerts = harness.wait_count("RENAME", 1)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.decoy_id == "d2"                              # identity preserved
    assert a.details.get("to", "").endswith("budget_renamed.txt")
    # registry now points d2 at the new path
    assert harness.reg.get("d2")["path"] == harness.path("budget_renamed.txt")
    # and a subsequent access on the NEW name is still detected
    harness.read("budget_renamed.txt")
    assert harness.wait(lambda: any(
        o.decoy_id == "d2" for o in harness.ops("READ")))


# ---- Feature D: move detection ------------------------------------------
def test_m3_ut_014_move_out_then_in(harness):
    # move report.txt (d1) OUT of the watched dir into an unwatched one
    harness.move_out("report.txt")
    out = harness.wait_count("MOVE_OUT", 1, timeout=4.0)
    assert len(out) == 1 and out[0].decoy_id == "d1"
    # destination is honestly reported as not observable
    assert "unobservable" in out[0].details.get("destination", "")
    assert harness.reg.get("d1")["active"] is False

    # now move it BACK into the watched dir
    harness.move_in("report.txt")
    back = harness.wait_count("MOVE_IN", 1, timeout=4.0)
    assert len(back) == 1 and back[0].decoy_id == "d1"
    assert harness.reg.get("d1")["active"] is True


# ---- Feature E: registry / watcher synchronisation ----------------------
def test_m3_ut_015_registry_accuracy_after_path_change(harness):
    harness.rename("report.txt", "report_v2.txt")
    harness.wait_count("RENAME", 1)
    d1 = harness.reg.get("d1")
    assert d1["path"] == harness.path("report_v2.txt")
    assert d1["watch_dir"] == harness.docs
    # the old path must no longer resolve to a decoy; the new one must
    assert harness.reg.is_registered_decoy(harness.path("report.txt")) is False
    assert harness.reg.is_registered_decoy(harness.path("report_v2.txt")) is True


def test_atomic_save_roundtrip(tmp_path):
    reg = DecoyRegistry()
    p = tmp_path / "report.txt"; p.write_text("x\n")
    reg.add(str(p))
    rf = tmp_path / "registry.json"
    reg.save(str(rf))
    # no stray temp files left behind by the atomic replace
    leftovers = [f for f in os.listdir(tmp_path) if f.startswith("registry.json.tmp")]
    assert leftovers == []
    assert DecoyRegistry.load(str(rf)).get("d1")["path"] == os.path.realpath(str(p))


def test_corrupt_registry_is_preserved_not_destroyed(tmp_path):
    import m3_checkpoint3 as c3
    rf = tmp_path / "registry.json"
    rf.write_text("{ this is not valid json ")
    reg = c3.load_registry_safe(str(rf))
    assert isinstance(reg, DecoyRegistry)
    assert reg.active_decoys() == []
    # the corrupt original is preserved under a backup, not overwritten
    backups = [f for f in os.listdir(tmp_path) if f.startswith("registry.json.corrupt-")]
    assert len(backups) == 1


# ---- Linux filesystem edge cases ----------------------------------------
def test_unicode_and_space_filename_detected(harness):
    name = "quarterly report éçñ.txt"       # spaces + unicode
    p = harness.path(name)
    with open(p, "w", encoding="utf-8") as f:
        f.write("decoy\n")
    harness.reg.add(p)
    harness.watcher.sync_watches()          # same dir; already watched
    harness.read(name)
    assert harness.wait(lambda: any(
        os.path.basename(a.path) == name for a in harness.ops("READ")))


def test_delete_then_no_crash_on_further_events(harness):
    # deleting a decoy and then touching a sibling must not raise in the loop
    harness.delete("notes.txt")
    harness.wait_count("DELETE", 1)
    harness.read("report.txt")
    assert harness.wait(lambda: any(a.decoy_id == "d1" for a in harness.ops("READ")))
    # thread is still alive and healthy
    assert harness._thread.is_alive()
