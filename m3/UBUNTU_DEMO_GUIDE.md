# M3 Honeyfile Deception — Ubuntu Demonstration Guide (Checkpoint 3)

A step-by-step guide for running and demonstrating M3 on Ubuntu. No prior Linux
experience is assumed — every command is written out in full. Everything happens
inside a **disposable** `test_lab/` folder that the program creates for itself;
none of your real files are touched.

> You will use **two terminal windows**:
> **Terminal 1** runs the watcher (the "security monitor").
> **Terminal 2** is where you act like a user/ransomware touching the decoys.

---

## 0. What you need

- Ubuntu (22.04 or 24.04 are fine). M3 is **Linux-only** — it uses the Linux
  `inotify` feature and will not run on Windows or macOS.
- Python 3.8 or newer (Ubuntu 24.04 ships Python 3.12; this project was verified
  on 3.13). You do **not** need root/sudo for the demo.

---

## 1. Extract the ZIP

If the file is in your Downloads folder:

```bash
cd ~/Downloads
unzip AI-RDR_M3_Checkpoint3.zip -d ~/ai-rdr-m3-demo
```

This creates `~/ai-rdr-m3-demo/ai-rdr-m3/` with the project inside.

## 2. Open the project folder in the Terminal

Open a terminal (press `Ctrl+Alt+T`) and go into the project folder:

```bash
cd ~/ai-rdr-m3-demo/ai-rdr-m3
ls
```

You should see `m3_checkpoint3.py`, `decoy_registry.py`, `tests/`, and so on.

## 3. Check your Python version

```bash
python3 --version
```

If it prints `Python 3.8` or higher, you are good. If `python3` is not found:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
```

## 4. Create and activate a virtual environment

A virtual environment keeps this project's dependency separate from your system.

```bash
python3 -m venv venv
source venv/bin/activate
```

Your prompt now starts with `(venv)`. (To leave it later, type `deactivate`.)

## 5. Install the dependencies

```bash
pip install -r requirements.txt
```

This installs `inotify_simple` (the runtime library) and `pytest` (for the tests).

## 6. Start the watcher (Terminal 1)

```bash
python3 m3_checkpoint3.py
```

Expected output (your paths will differ):

```
============================================================
AI-RDR M3 | Checkpoint 3 - Honeyfile detection
============================================================

Registry file: .../test_lab/registry.json

Registered decoys (3):
  [d1] .../test_lab/documents/report.txt
  [d2] .../test_lab/documents/budget.txt
  [d3] .../test_lab/documents/notes.txt

Watched directories (1):
  wd=1  dir=.../test_lab/documents
  Decoys here: report.txt, budget.txt, notes.txt

Watcher is running. Press Ctrl+C to stop.
```

**Leave this terminal running.** The alerts will appear here.

## 7. Open a second terminal (Terminal 2)

Press `Ctrl+Alt+T` again for a new window, then go to the same folder:

```bash
cd ~/ai-rdr-m3-demo/ai-rdr-m3
```

All the decoys live in `test_lab/documents/`. The three decoys are
`report.txt` (d1), `budget.txt` (d2), `notes.txt` (d3). `real_user_file.txt`
is a normal file (NOT a decoy).

---

## 8. The demonstrations

Run each command in **Terminal 2**, then look at **Terminal 1** for the alert.

### 8.1 READ a decoy  → READ alert  (maps to M3-UT-005)

```bash
cat test_lab/documents/report.txt
```

Terminal 1 shows:

```
!!! HONEYFILE ALERT !!! Time: 2026-... ...
File: .../test_lab/documents/report.txt
Decoy ID: d1
Operation: READ
Event: [<flags.ACCESS: 1>]
```

### 8.2 WRITE a decoy  → WRITE alert  (maps to M3-UT-006)

```bash
echo "extra line" >> test_lab/documents/budget.txt
```

Terminal 1 shows an alert with `Decoy ID: d2`, `Operation: WRITE`,
`Event: [<flags.CLOSE_WRITE: 8>]`.

### 8.3 Normal file → NO alert  (maps to M3-UT-007)

```bash
cat test_lab/documents/real_user_file.txt
```

Terminal 1 shows **nothing** (no alert). This proves only decoys trigger alerts.

### 8.4 Operation-aware cooldown  (maps to M3-UT-008, M3-UT-011)

**Same operation repeated quickly → only ONE alert** (de-duplication):

```bash
cat test_lab/documents/report.txt
cat test_lab/documents/report.txt
cat test_lab/documents/report.txt
```

Terminal 1 shows **one** READ alert for d1, not three (repeats within the
5-second cooldown are suppressed).

**Different operation within the window → a SEPARATE alert** (operation-aware):

```bash
cat  test_lab/documents/report.txt      # READ  alert
echo hi >> test_lab/documents/report.txt   # WRITE alert, even within 5s
```

Terminal 1 shows **two** alerts — one READ and one WRITE — because a different
logical operation is not suppressed. Wait more than 5 seconds and repeat a
`cat` to see a fresh READ alert after the cooldown expires (M3-UT-009).

### 8.5 DELETE a decoy → DELETE alert  (maps to M3-UT-012)

```bash
rm test_lab/documents/notes.txt
```

Terminal 1 shows an alert with `Decoy ID: d3`, `Operation: DELETE`.

### 8.6 RENAME a decoy → RENAME alert  (maps to M3-UT-013)

```bash
mv test_lab/documents/report.txt test_lab/documents/report_v2.txt
```

Terminal 1 shows `Decoy ID: d1`, `Operation: RENAME`, with `from:` and `to:`
lines. The Decoy ID stays **d1** — identity is preserved across the rename.

### 8.7 MOVE a decoy out of the watched folder → MOVE_OUT alert  (maps to M3-UT-014)

```bash
mv test_lab/documents/budget.txt /tmp/budget.txt
```

After about a second, Terminal 1 shows `Decoy ID: d2`, `Operation: MOVE_OUT`,
and `destination: unobservable (left monitored tree)`. (The tool does not guess
where the file went, because Linux cannot tell it.)

Move it back in to see a MOVE_IN alert:

```bash
mv /tmp/budget.txt test_lab/documents/budget.txt
```

---

## 9. Stop the watcher safely

In **Terminal 1**, press:

```
Ctrl + C
```

You will see:

```
Ctrl+C received -- shutting down.
Watches closed cleanly. Checkpoint 3 complete.
```

## 10. Reset between demonstrations

To start fresh (new decoys, empty registry), stop the watcher and delete the
disposable `test_lab/` folder — then start the watcher again, which recreates it:

```bash
rm -rf test_lab
python3 m3_checkpoint3.py
```

---

## 11. Run the automated test suite

With the watcher **stopped** (or in a third terminal), from the project folder
with the virtual environment active:

```bash
python3 -m pytest tests/ -v
```

Expected: **22 passed**. These drive the real watcher with real file events and
cover both the Checkpoint 2 regression and the Checkpoint 3 features.

## 12. Run the optional overflow stress test

This is a **separate, optional** test. It floods a disposable folder to try to
force a real Linux inotify queue overflow and checks the watcher recovers:

```bash
python3 test_inotify_overflow_stress.py
```

- `RESULT: PASS` means a real kernel overflow happened **and** the watcher
  recovered.
- `RESULT: NOT VERIFIED` means your machine's inotify queue did not overflow
  (an environment limit, not a failure). Add `--simulate` to also exercise the
  handler with a simulated overflow event (clearly labelled, not counted as the
  real result):

```bash
python3 test_inotify_overflow_stress.py --simulate
```

---

## 13. Common errors and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'inotify_simple'` | dependencies not installed, or venv not active | `source venv/bin/activate` then `pip install -r requirements.txt` |
| `python3: command not found` | Python not installed | `sudo apt install python3 python3-venv python3-pip` |
| `pip: command not found` | pip missing | `sudo apt install python3-pip`, or use `python3 -m pip ...` |
| No alert when you `cat` a decoy | you ran the command in the wrong folder, or the watcher is not running | make sure Terminal 1 shows "Watcher is running", and run the `cat` from the project folder so the path `test_lab/documents/...` is correct |
| Alerts for a decoy stop after you renamed/moved it | expected — use the **new** path (e.g. `report_v2.txt`) after a rename | interact with the new filename |
| `OSError: inotify instance limit reached` | too many leftover inotify instances (rare) | close extra watcher processes, or log out and back in |
| Stress test prints `NOT VERIFIED` | your kernel's queue did not overflow within the safe event cap | this is acceptable; it is an environment limit, not a defect. Try `--events 60000` if you want to push harder |

## 14. What this demo does NOT show (be honest in your write-up)

- M3 **cannot say which process** touched a decoy — Linux inotify gives no
  process ID. Naming the ransomware process needs M1's audit data.
- The **M3 → M5/M6 alert hand-off is not built** — alerts are shown in the
  terminal only; the integration interface is a separate, not-yet-confirmed step.
- A move **out** of the watched folder never shows a destination — the tool
  reports it as "unobservable" rather than guessing.
