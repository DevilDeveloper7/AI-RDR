"""
Checkpoint 2 REGRESSION suite — every pre-existing behaviour must still hold.

Maps to the M3 Test Plan 'Current checkpoint functionality' cases:
  M3-UT-001 exact-path identification     M3-UT-006 modification -> alert
  M3-UT-002 registry persistence          M3-UT-007 ordinary file -> no alert
  M3-UT-003 duplicate path ignored        M3-UT-008 de-dup within cooldown
  M3-UT-004 parent-dir watch established  M3-UT-009 new alert after cooldown
  M3-UT-005 access -> alert               M3-UT-010 clean shutdown
"""

import json
import os
import time

from inotify_simple import flags
from decoy_registry import DecoyRegistry
from conftest import Harness, TEST_COOLDOWN, DECOYS


# ---- registry-level behaviour (no watcher needed) -----------------------
def test_m3_ut_001_exact_path_identification(harness):
    assert harness.reg.is_registered_decoy(harness.path("report.txt")) is True
    assert harness.reg.is_registered_decoy(harness.path("real_user_file.txt")) is False
    # a name that merely begins with a decoy name is NOT a match
    assert harness.reg.is_registered_decoy(harness.path("report.txt.backup")) is False


def test_m3_ut_002_registry_persistence(tmp_path):
    reg = DecoyRegistry()
    d = tmp_path / "documents"; d.mkdir()
    for n in DECOYS:
        p = d / n; p.write_text("x\n"); reg.add(str(p))
    rf = tmp_path / "registry.json"
    reg.save(str(rf))

    raw = json.loads(rf.read_text())
    assert raw["version"] == 1
    assert len(raw["decoys"]) == 3

    reloaded = DecoyRegistry.load(str(rf))
    before = [(x["decoy_id"], x["path"]) for x in reg.active_decoys()]
    after = [(x["decoy_id"], x["path"]) for x in reloaded.active_decoys()]
    assert before == after


def test_m3_ut_003_duplicate_path_ignored(tmp_path):
    reg = DecoyRegistry()
    p = tmp_path / "report.txt"; p.write_text("x\n")
    first = reg.add(str(p))
    second = reg.add(str(p))               # exact same path again
    assert len(reg.active_decoys()) == 1
    assert first["decoy_id"] == second["decoy_id"]


# ---- watcher-level behaviour (real inotify) -----------------------------
def test_m3_ut_004_parent_directory_watch_established(harness):
    assert harness.docs in harness.watcher.wd_map.values()
    assert len(harness.watcher.wd_map) == 1


def test_m3_ut_005_access_raises_alert(harness):
    harness.read("report.txt")
    alerts = harness.wait_count("READ", 1)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.decoy_id == "d1"
    assert flags.ACCESS in a.event_flags


def test_m3_ut_006_modification_raises_alert(harness):
    harness.write("budget.txt")
    alerts = harness.wait_count("WRITE", 1)
    assert len(alerts) == 1
    assert alerts[0].decoy_id == "d2"
    assert flags.CLOSE_WRITE in alerts[0].event_flags


def test_m3_ut_007_ordinary_file_no_alert(harness):
    with open(harness.path("real_user_file.txt"), "r", encoding="utf-8") as f:
        f.read()
    # give the watcher time to (not) react
    time.sleep(0.6)
    assert harness.ops() == []


def test_m3_ut_008_dedup_within_cooldown(harness):
    for _ in range(3):
        harness.read("report.txt")
        time.sleep(0.05)
    time.sleep(0.5)
    # three equivalent reads within the cooldown collapse to one alert
    assert len(harness.ops("READ", decoy_id="d1")) == 1


def test_m3_ut_009_new_alert_after_cooldown(harness):
    harness.read("report.txt")
    harness.wait_count("READ", 1)
    time.sleep(TEST_COOLDOWN + 0.3)        # let the cooldown expire
    harness.read("report.txt")
    alerts = harness.wait_count("READ", 2)
    assert len(alerts) == 2


def test_m3_ut_010_clean_shutdown(harness):
    # watcher thread is running; stop() must join and close without error
    assert harness.watcher._stop.is_set() is False
    harness.stop()
    assert harness.watcher._stop.is_set() is True
    # inotify fd is closed; a second close must not raise
    harness.watcher.close()
