# M3 Honeyfile Deception — Checkpoint 3 Test Execution Report

**Project:** AI-RDR (AI-Driven Ransomware Detection and Response) — CSIT321 Capstone
**Component:** M3 — Honeyfile Deception, Checkpoint 3
**Latest verification:** 4 November 2026

## 1. Environment

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS |
| Kernel | Linux 6.18.44 |
| Python | 3.13.16 |
| inotify_simple | 2.0.1 |
| pytest | 9.2.0 |
| `fs.inotify.max_queued_events` | 16384 |
| Event source | **Real Linux inotify** (no mocking) |

The watcher runs in a background thread on a per-test temporary `test_lab`; each
test performs genuine filesystem operations (`open`/read, append, `rm`, `mv`) and
asserts on the alerts the real kernel events produce. Test timings use a short
cooldown (1.0 s) and move-match window (0.4 s) so the suite is quick; the logic is
identical to the production defaults (5 s / 1.0 s).

## 2. How to reproduce

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v                      # the 22-test suite
python3 test_inotify_overflow_stress.py          # separate overflow stress test
```

## 3. Execution evidence (this verification session)

Precise, recorded counts for this session — no aggregate is stated that was not
actually run here:

| Activity | Runs | Result |
|---|---|---|
| `pytest tests/` — baseline before adding the stress test | 1 | 22 passed |
| `pytest tests/` — repeat runs (timing-stability check) | 5 | 22 passed each |
| **Total `pytest tests/` runs this session** | **6** | **22 passed every run (0 failures, 0 flakes)** |
| `test_inotify_overflow_stress.py` | 2 | PASS both (real kernel overflow observed) |

Representative final line:

```
============================== 22 passed in 9.84s ==============================
```

The core source and the `tests/` suite are **byte-identical** to the pre-change
baseline backup (`diff` shows no differences); the only addition this session is
the standalone `test_inotify_overflow_stress.py`. No working feature was changed.

## 4. Result classification (as required)

### 4.1 Tests executed and PASSED (22)

**Checkpoint 2 regression (10):**

| Test Plan case | Test | Result |
|---|---|---|
| M3-UT-001 Exact-path identification | `test_m3_ut_001_exact_path_identification` | PASS |
| M3-UT-002 Registry persistence | `test_m3_ut_002_registry_persistence` | PASS |
| M3-UT-003 Duplicate path ignored | `test_m3_ut_003_duplicate_path_ignored` | PASS |
| M3-UT-004 Parent-directory watch established | `test_m3_ut_004_parent_directory_watch_established` | PASS |
| M3-UT-005 Decoy access → alert | `test_m3_ut_005_access_raises_alert` | PASS |
| M3-UT-006 Decoy modification → alert | `test_m3_ut_006_modification_raises_alert` | PASS |
| M3-UT-007 Ordinary file → no alert | `test_m3_ut_007_ordinary_file_no_alert` | PASS |
| M3-UT-008 De-duplication within cooldown | `test_m3_ut_008_dedup_within_cooldown` | PASS |
| M3-UT-009 New alert after cooldown | `test_m3_ut_009_new_alert_after_cooldown` | PASS |
| M3-UT-010 Clean shutdown on interrupt | `test_m3_ut_010_clean_shutdown` | PASS |

**Checkpoint 3 features (12):**

| Test Plan case / feature | Test | Result |
|---|---|---|
| M3-UT-011 Distinct operation within cooldown still alerts (A) | `test_m3_ut_011_distinct_operation_within_cooldown` | PASS |
| Feature A — independent per-decoy cooldown | `test_operation_aware_independent_decoys` | PASS |
| Feature A — cooldown state is bounded (pruned) | `test_cooldown_state_is_bounded` | PASS |
| M3-UT-012 Deletion raises an alert (B) | `test_m3_ut_012_deletion_raises_alert` | PASS |
| Feature B — deleting a normal file is silent | `test_deleting_normal_file_is_silent` | PASS |
| M3-UT-013 Rename raises alert, identity preserved (C) | `test_m3_ut_013_rename_raises_alert_and_preserves_identity` | PASS |
| M3-UT-014 Move out / back into monitored dir (D) | `test_m3_ut_014_move_out_then_in` | PASS |
| M3-UT-015 Registry accuracy after a path change (E) | `test_m3_ut_015_registry_accuracy_after_path_change` | PASS |
| Feature E — atomic save, no temp-file leak | `test_atomic_save_roundtrip` | PASS |
| Feature E — corrupt registry preserved, not destroyed | `test_corrupt_registry_is_preserved_not_destroyed` | PASS |
| Edge — Unicode/space filename detected | `test_unicode_and_space_filename_detected` | PASS |
| Edge — delete then no crash on further events | `test_delete_then_no_crash_on_further_events` | PASS |

### 4.2 Tests executed and FAILED

**None.** No failures were observed in any of the 6 suite runs this session.

### 4.3 Tests NOT executed

- The **live Ubuntu demonstration** steps (guide §8) are to be executed by the
  team member on their own machine; they are not part of the automated suite and
  are marked PENDING in `DEMO_EVIDENCE_CHECKLIST.md`.

### 4.4 Tests blocked by environmental limitations

- **None in this environment.** The one previously-unverified item — real
  `IN_Q_OVERFLOW` recovery — was successfully verified here (Section 5). On a
  machine whose kernel queue does not overflow within the safety cap, the stress
  test reports `NOT VERIFIED` (environment limitation), which is neither a PASS
  nor a failure.

## 5. IN_Q_OVERFLOW stress test — REAL vs SIMULATED

Run with `python3 test_inotify_overflow_stress.py` (and `--simulate`).

| Phase | Nature | This environment |
|---|---|---|
| Phase 1 — kernel can produce `IN_Q_OVERFLOW` | **REAL** | **OBSERVED** (flooded a disposable watch; kernel returned the overflow marker after 16384 queued events) |
| Phase 2 — watcher recognises overflow, reports degraded state, re-synchronises, monitoring resumes | **REAL** | **VERIFIED** — stderr showed `[WARN] inotify queue overflow (IN_Q_OVERFLOW) …`, and a fresh decoy READ alerted afterwards |
| Phase 3 — synthetic overflow event fed to the handler | **SIMULATED** | handler recognised it; shown only for completeness |
| **Overall verdict** | | **PASS** (real overflow + real recovery), exit code 0 |

The stress test **never reports PASS for recovery unless a genuine kernel
overflow was observed**; if none occurs it reports `NOT VERIFIED`. The simulated
phase is always labelled SIMULATED and never contributes to the verdict.

Safety: the stress test runs only inside `tempfile.mkdtemp()` directories,
creates and unlinks throwaway files one at a time (negligible disk), needs no
root, and never changes kernel settings (it only reads `max_queued_events`).

## 6. Live demonstration transcript (verbose watcher, real events)

From `python3 m3_checkpoint3.py` with real interactions:

```
!!! HONEYFILE ALERT !!!  Decoy ID: d1  Operation: READ
!!! HONEYFILE ALERT !!!  Decoy ID: d2  Operation: WRITE
!!! HONEYFILE ALERT !!!  Decoy ID: d3  Operation: DELETE
!!! HONEYFILE ALERT !!!  Decoy ID: d1  Operation: RENAME
    from: .../documents/report.txt
    to:   .../documents/report_v2.txt
!!! HONEYFILE ALERT !!!  Decoy ID: d2  Operation: MOVE_OUT
    destination: unobservable (left monitored tree)
Ctrl+C received -- shutting down.
Watches closed cleanly. Checkpoint 3 complete.
```

Reading the non-decoy control file produced **no** alert, as required.

## 7. Scope and honesty notes

- **Not claimed:** process attribution (inotify has no PID), and the M3 → M5/M6
  alert contract (not implemented; alerts are in-process objects / console output
  only). The project is **not** claimed to be error-free or integrated with
  M5/M6.
- **Cross-filesystem moves** appear to inotify as DELETE+CREATE rather than a
  cookie-paired move; M3 reads them honestly (a deletion, plus a move-in if the
  destination is watched) and does not invent a destination.

## 8. Status

Checkpoint 3 acceptance tests (M3-UT-001…015 and the supporting feature/edge
tests) **pass on real Linux inotify events across 6 suite runs**, Checkpoint 2
behaviour is preserved (source byte-identical to baseline), and the previously
open item — real `IN_Q_OVERFLOW` recovery — is now **verified** by a dedicated,
safe, standalone stress test. Remaining open items are the live Ubuntu
demonstration (to be performed by the team) and the unimplemented M5/M6
integration.
