# M3 Checkpoint 3 — Demonstration Evidence Checklist

For assembling the Capstone Test Plan evidence (Section 8, M3). Each row names
the screenshot/terminal output to capture, the demo step that produces it, and
the M3-UT case(s) it supports.

**Two kinds of evidence:**

- **[AUTO-VERIFIED]** — already executed in the development environment on real
  Linux inotify events and recorded in `TEST_EXECUTION_REPORT.md`. You can cite
  the report, and optionally reproduce it on Ubuntu for your own screenshots.
- **[PENDING — your Ubuntu run]** — you must execute and screenshot this on your
  own machine for the live demonstration. It has **not** been pre-filled; the
  Actual Result / Verdict in the Test Plan stay blank until you run it.

Do not paste any result you did not personally produce. No screenshots or
outputs are invented in this package.

---

## A. Environment evidence

| # | Capture | Command | Supports |
|---|---|---|---|
| A1 | Ubuntu + Python version | `lsb_release -a` and `python3 --version` | Test environment (§5 of Test Plan) |
| A2 | Dependency install success | `pip install -r requirements.txt` output | Test environment |
| A3 | inotify library version | `python3 -c "import inotify_simple,sys;print(inotify_simple.__version__)"` | Test environment |

## B. Checkpoint 2 regression evidence (functionality preserved)

| # | Capture | Demo step (guide) | M3-UT | Status |
|---|---|---|---|---|
| B1 | Watcher start-up banner: 3 registered decoys d1/d2/d3, 1 watched dir | §6 | M3-UT-004 | [PENDING — your Ubuntu run] |
| B2 | READ alert for d1 after `cat report.txt` | §8.1 | M3-UT-005 | [PENDING — your Ubuntu run] |
| B3 | WRITE alert for d2 after `echo >> budget.txt` | §8.2 | M3-UT-006 | [PENDING — your Ubuntu run] |
| B4 | No alert after `cat real_user_file.txt` | §8.3 | M3-UT-007 | [PENDING — your Ubuntu run] |
| B5 | Only ONE alert after three quick `cat`s | §8.4 (first block) | M3-UT-008 | [PENDING — your Ubuntu run] |
| B6 | A fresh READ alert after waiting > 5 s | §8.4 (note) | M3-UT-009 | [PENDING — your Ubuntu run] |
| B7 | Clean shutdown lines after `Ctrl+C` | §9 | M3-UT-010 | [PENDING — your Ubuntu run] |
| B8 | `pytest tests/ -v` showing the 10 regression tests PASS | §11 | M3-UT-001…010 | [AUTO-VERIFIED] + reproduce for screenshot |

## C. Checkpoint 3 feature evidence

| # | Capture | Demo step (guide) | M3-UT | Status |
|---|---|---|---|---|
| C1 | READ then WRITE on d1 within 5 s → TWO alerts | §8.4 (second block) | M3-UT-011 | [PENDING — your Ubuntu run] |
| C2 | DELETE alert for d3 after `rm notes.txt` | §8.5 | M3-UT-012 | [PENDING — your Ubuntu run] |
| C3 | RENAME alert for d1 with from/to; ID stays d1 | §8.6 | M3-UT-013 | [PENDING — your Ubuntu run] |
| C4 | MOVE_OUT alert for d2, destination "unobservable"; then MOVE_IN | §8.7 | M3-UT-014 | [PENDING — your Ubuntu run] |
| C5 | After rename, old name no longer alerts; new name does | §8.6 then `cat` new name | M3-UT-015 | [PENDING — your Ubuntu run] |
| C6 | `pytest tests/ -v` showing the 12 Checkpoint 3 tests PASS | §11 | M3-UT-011…015 (+ edges) | [AUTO-VERIFIED] + reproduce for screenshot |

## D. Overflow stress-test evidence (Feature E — degraded state & recovery)

| # | Capture | Command | Note | Status |
|---|---|---|---|---|
| D1 | Stress test verdict line + "real kernel overflow: OBSERVED" | `python3 test_inotify_overflow_stress.py` | REAL kernel overflow | [AUTO-VERIFIED] in dev env (PASS); re-run on Ubuntu |
| D2 | Degraded-state line `[WARN] inotify queue overflow (IN_Q_OVERFLOW)` and "monitoring resumed OK: True" | same as D1 | REAL recovery | [AUTO-VERIFIED] in dev env; re-run on Ubuntu |
| D3 | Simulated handler check (clearly labelled SIMULATED) | `python3 test_inotify_overflow_stress.py --simulate` | SIMULATED — not a substitute for D1/D2 | [AUTO-VERIFIED] in dev env |

> **Important for the write-up:** D1/D2 are a *real* kernel overflow + recovery
> (verified in the development environment). On a different machine the stress
> test may instead print `NOT VERIFIED` if that kernel's queue does not overflow
> within the safe event cap — that is an environment limitation, **not** a failure
> and **not** a PASS. Record whichever result your own run actually produces.

## E. What must stay PENDING / cannot be screenshotted as PASS

| Item | Why | How to record it |
|---|---|---|
| Live Ubuntu demonstration (B1–B7, C1–C5) | must be executed by you on your machine | capture your own screenshots; fill the Test Plan Actual Result/Verdict only after running |
| Cross-filesystem move (across mount points) | appears as DELETE+CREATE, not a cookie-paired move; not separately demoed | note as a known inotify behaviour, not a tested case |
| Process attribution (which process touched the decoy) | inotify provides no PID | state as an M3 limitation; needs M1 audit data |
| M3 → M5/M6 alert delivery | interface not implemented | state as not implemented / unconfirmed |

## F. Suggested screenshot set (minimum for the Test Plan)

1. A1 (environment) — one screenshot.
2. B1 (watcher start-up) — one screenshot.
3. One combined screenshot of Terminal 2 commands beside Terminal 1 alerts for:
   READ (B2), WRITE (B3), normal-file-no-alert (B4).
4. Cooldown: B5 (one alert from three reads) and C1 (READ+WRITE two alerts).
5. C2 DELETE, C3 RENAME, C4 MOVE_OUT/MOVE_IN — one screenshot each.
6. B7 clean shutdown.
7. B8/C6 `pytest -v` summary showing `22 passed`.
8. D1/D2 stress-test verdict (`RESULT: PASS` with the OBSERVED/resumed lines),
   or your machine's actual `NOT VERIFIED` output.
