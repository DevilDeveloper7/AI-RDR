"""Loader for LID-DS-2019 and LID-DS-2021 (Tier 1 — raw-event).

See planning/lid-ds-integration-progress.md for the full task spec and the critical
scoping correction this loader implements: **LID-DS's "exploit" recordings are NOT
ransomware.** Each scenario is a different CVE/CWE against a real production service
(Heartbleed, SQL injection, ZipSlip path traversal, brute-force, various RCEs,
Juice-Shop). Only `is_executing_exploit=False` ("normal") recordings become new benign
training data (`label="benign"`, `training_eligible=True`); exploit recordings become a
second, independent generic-attack validation set (`label="other"`,
`training_eligible=False`) — never ransomware positive-class training signal.

Source archives: data/lid-ds-2019/LID-DS-2019.zip (13GB), data/lid-ds-2021/LID-DS-2021.zip
(87GB). Both are extracted **selectively and in-memory, never bulk-unzipped** — see
`_load_2019_scenario`/`_load_2021_scenario` below. Outer-zip members are stored
uncompressed (`compress_type == 0`, verified: `compress_size == file_size` for every
member in both archives), so `zipfile.open(member)` returns a genuinely seekable stream
directly into the outer archive with no extraction cost — this loader never writes a
temporary copy of any multi-gigabyte scenario archive to local disk.

## Format — verified per-scenario, NOT assumed identical across versions

**2019** (10 scenarios, one `<scenario>.tar.gz` member per scenario — the archive also
has a top-level `Readme-LID-DS-2019.md`, which is not a scenario, hence 10 not 11):
`<scenario>/runs.csv` (columns `image_name, scenario_name, is_executing_exploit,
warmup_time, recording_time, exploit_start_time` — `scenario_name` is the docker random
name matching the `.txt` recording's filename) plus one `<scenario>/<name>.txt` per
recording, sysdig text format with a leading line-number column:
`<line#> <HH:MM:SS.nnnnnnnnn> <cpu> <tid> <proc> <pid> <dir:>/<> <syscall> <args...>`.
`runs.csv` was found positioned **~94% through** the tar (member 1039 of 1102 on
CVE-2014-0160) — not near the start — so extraction requires two sequential streaming
passes per scenario (pass 1: scan forward until `runs.csv` is found, to learn which
recordings are normal/exploit; pass 2: fresh stream, extract only the selected `.txt`
members). Verified on CVE-2014-0160 (1000 normal/100 exploit, matches the tracker's
prior finding), CVE-2017-7529 (983/174 — a **much higher** 15.0% exploit ratio, not
9.1%), and Bruteforce_CWE-307 (994/98, 9.0%) — **the exploit ratio genuinely varies by
scenario and was not assumed** to be the CVE-2014-0160 figure everywhere.
gzip decompression measured at ~590MB/s in this environment (155MB compressed ->
803MB decompressed in 1.36s), so even the largest 2019 member (ZipSlip, 7.0GB compressed)
costs roughly a minute per pass — tractable without a local scratch copy.

**2021** (15 scenarios, one `<scenario>.zip` member per scenario) is a **materially
different layout** — confirmed by inspecting 5 scenarios (CVE-2014-0160, CVE-2020-13942,
Bruteforce_CWE-307, Juice-Shop, ZipSlip), not assumed from one:
- No `runs.csv` at all. Recordings are split into `training/`, `validation/`,
  `test/normal/` (all exploit=False — LID-DS-2021's own convention reserves
  training/validation for pure baseline profiling) and `test/normal_and_attack/`
  (exploit=True). Per-recording ground truth is also independently confirmed via each
  recording's own `<name>.json` (`"exploit": true/false`) — cross-checked against the
  directory convention on 3 recordings across 2 scenarios, 100% agreement, so the
  (cheaper) directory-based label is used as ground truth for the full run.
- Per-scenario split sizes are **not** identical to 2019's 1000/100 split, and vary a
  little scenario-to-scenario too: CVE-2014-0160 (212 training / 60 validation / 759
  test-normal / 123 test-attack — attack rate over the whole normal+attack test pool is
  123/(123+759)=13.9%), CVE-2020-13942 (211/60/756/118, 13.5%), Bruteforce_CWE-307
  (210/60/768/139, 15.3%), consistently **higher** than 2019's ~9-15% range but same
  order of magnitude.
- **Two different recording packagings coexist across scenarios** (verified, not
  assumed uniform): CVE-2014-0160 stores each recording as a **directory** of 4 loose
  files (`<name>.sc/.json/.pcap/.res`); Bruteforce_CWE-307/CVE-2020-13942/Juice-Shop/
  ZipSlip instead store each recording as a **nested per-recording `.zip`** containing
  the same 4 files. Both are handled by `_iter_2021_recordings` below.
- **The trace format itself changed** — this is the "framework was extended between
  releases" case the tracker warned about. 2021's `.sc` files have **no line-number
  column** and a **different field order**: `<epoch_ns> <cpu> <tid> <proc> <pid>
  <syscall> <dir> <args...>` (syscall *before* direction — 2019 has direction before
  syscall). The timestamp is also a genuine absolute Unix epoch in nanoseconds (2019 only
  has a bare time-of-day with no date). Verified identical field order on 4 different
  scenarios before trusting it as the 2021-wide format.
- Only `.sc` is parsed. `.pcap` is skipped for the same reason EN2025's `dump.pcap` was
  skipped (no independent parsed summary here to justify the duplication effort within
  this task's scope, and it's out of scope for what the SDD 8-feature schema needs).
  `.res` (resource-usage stats) is not a syscall/behavioral signal and is not parsed.

## One row per syscall, entry+exit merged — a judgment call, documented

Unlike the Ransomware Lifecycle ftrace loader (which counts only the "enter" half of an
enter/exit pair because both halves carry the same information there), LID-DS's `>`
(call) and `<` (return) lines carry **asymmetric** information: entry lines carry
`fd=N(<type>target)` + `size=`, while exit lines carry `res=` and, for
read/write-family calls, the actual `data=` content excerpt — and for syscalls like
`open`/`stat`/`rename`, the entry line is frequently **empty** (e.g. literal `> open`
with no args at all; the resolved `name=`/`newpath=` only appears on the exit line).
Taking only one side would silently lose real signal on the other, so this loader
tracks one pending entry per `tid` (a thread can only have one syscall in flight at a
time) and emits **one merged row per completed syscall**, combining entry args + exit
args + parsed `res`/`data`. A `>` for a "fire-and-forget" pseudo-event that sysdig never
pairs with a `<` (observed only for `switch` and `procexit`) is emitted immediately, not
held pending forever. Any entry still pending at end-of-file (traces end mid-syscall) is
emitted as an entry-only row rather than silently dropped.

## entropy_score — real signal exists, but degraded (see pipeline/features/lid_ds.py)

sysdig's own text `data=` field on read/write-family exit lines *does* carry a real,
byte-derived content excerpt (verified — see the features-module docstring for the full
finding and why it's kept anyway despite a structural downward bias for genuinely
high-entropy content).

Output: data/normalized/lid_ds_2019_raw_events.parquet, data/normalized/lid_ds_2021_raw_events.parquet.
"""

from __future__ import annotations

import csv
import io
import json
import random
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from pipeline.schema import validate_tier1

DATA_ROOT = Path(__file__).resolve().parents[2] / "data"
ZIP_2019 = DATA_ROOT / "lid-ds-2019" / "LID-DS-2019.zip"
ZIP_2021 = DATA_ROOT / "lid-ds-2021" / "LID-DS-2021.zip"
OUT_2019 = DATA_ROOT / "normalized" / "lid_ds_2019_raw_events.parquet"
OUT_2021 = DATA_ROOT / "normalized" / "lid_ds_2021_raw_events.parquet"

SOURCE_2019 = "lidds2019"
SOURCE_2021 = "lidds2021"

# Sampling — per planning/lid-ds-integration-progress.md's "200-300 normal, all exploit"
# guidance, ADAPTED after actually inspecting real recording sizes (the tracker
# explicitly asks for this adjustment, not blind adherence to the starting point).
#
# 2019 recordings are uniformly small (a 40s Apache/Heartbleed trace is ~4-7K lines,
# ~150-250KB) — 250 normal/scenario (all exploit, ~100-175/scenario) was confirmed
# tractable with a real dry run (105 recordings -> 444K rows in 6.9s).
#
# 2021 recordings are NOT uniformly small — a real, load-bearing finding, not assumed:
# peeking real .sc sizes (cheaply, via each recording's own zip/dir central-directory
# metadata, WITHOUT decompressing the .sc payload itself — see `_recording_sc_size`)
# across 4 scenarios found CVE-2014-0160/Bruteforce_CWE-307 traces are still small
# (1.7-2.4MB), but CVE-2020-13942 (Elasticsearch/Java) recordings are **81-195MB each**
# with **zero** small ones in a 15-recording sample, EPS_CWE-434 is 63-81MB (with one
# 11KB outlier, likely a failed/truncated capture), ZipSlip 7-48MB, Juice-Shop 3.5-147MB.
# A first unthrottled attempt at Juice-Shop's ~121 exploit recordings (each up to ~95MB
# decompressed, ~1.08M lines) ballooned to >12GB RSS and climbing before being killed —
# the per-line Python row-dict representation this loader uses (chosen for parity with
# ELFEN/EN2025's per-sample streaming-Python pattern, not Lifecycle's Polars-vectorized
# one) does not scale to million-line single recordings at this sample count.
#
# Fix, in the same spirit as the Ransomware Lifecycle loader's "extract up to 50MB,
# skip (not truncate) anything larger, log exactly what was skipped" precedent: cap
# individual 2021 recordings at MAX_SC_BYTES_2021, and reduce the 2021 normal sample
# count to keep total per-scenario volume tractable. This means scenarios that are
# uniformly chatty (CVE-2020-13942 above all — every sampled recording exceeds the cap)
# end up contributing few or zero windows; documented honestly in
# data/features/SUMMARY.md as a real per-scenario limitation, not silently forced.
N_NORMAL_SAMPLE = 250
N_NORMAL_SAMPLE_2021 = 80
MAX_EXPLOIT_SAMPLE_2021 = 150
MAX_SC_BYTES_2021 = 4_000_000  # ~37K lines at this source's observed ~108 bytes/line
# 2019's Heartbleed/Bruteforce/SQL-injection/etc. scenarios were all confirmed small
# during format verification (a 40s Apache trace is ~150-250KB) — but ZipSlip (a file-
# archive-extraction scenario, heavy filesystem I/O even when "normal") was not, and ran
# unbounded for minutes at multi-GB RSS before this cap was added. Kept slightly more
# generous than 2021's cap since 2019's format carries an extra leading line-number
# column per line (a little more bytes/event for the same information).
#
# Measured outcome on the actual full run (not just the ZipSlip spot-check above):
# EPS_CWE-434 and ZipSlip both end up with **zero** recordings under this 6MB cap --
# every single one of their 972/965 normal and 99/98 exploit recordings exceeds it, so
# both scenarios contribute 0 rows to the output, not just a reduced sample. This is
# consistent with (not contradicted by) the 2021 archive's independent finding that
# these same two CVEs are unusually chatty there too (EPS_CWE-434 63-81MB, ZipSlip
# 7-48MB per recording in 2021's format) -- both formats agree these are inherently
# large-trace scenarios, verified by measurement rather than assumed identical to the
# other 8 2019 scenarios. Net effect: 2019 contributes rows from 8 of its 10 scenarios,
# not all 10 -- documented honestly in data/features/SUMMARY.md rather than silently
# padding the scenario count.
MAX_SC_BYTES_2019 = 6_000_000
MAX_EXPLOIT_SAMPLE_2019 = 150
SAMPLE_SEED = 42

# --- syscall -> Tier-1 event_type vocabulary (pipeline/features/event_categories.py's
# existing 13-bit vocabulary already covers everything needed here — no new bits added).
# Deliberately not exhaustive: anything not listed here (mmap/munmap/brk/poll/select/
# epoll_*/fcntl/close/times/semop/wait4/rt_sig*/getcwd/chdir/umask/setitimer/geteuid/
# setuid/... — all observed in real scenario samples) falls back to "syscall"
# (SYSCALL_GENERIC), the same documented-fallback pattern EN2025's _CATEGORY_FALLBACK
# and Linux-APT-2024's wazuh:* catch-all already use for this project.
_FILE_ACCESS = {
    "open", "openat", "stat", "fstat", "fstatat", "lstat", "newfstatat", "access",
    "faccessat", "readlink", "readlinkat", "getdents", "getdents64", "read", "pread",
    "pread64", "preadv", "getxattr", "lgetxattr", "fgetxattr", "statfs", "fstatfs",
}
_FILE_MODIFY = {
    "write", "writev", "pwrite", "pwrite64", "pwritev", "fsync", "fdatasync",
    "ftruncate", "truncate", "chmod", "fchmod", "fchmodat", "chown", "fchown",
    "lchown", "fchownat", "mkdir", "mkdirat", "symlink", "symlinkat", "setxattr",
    "lsetxattr", "fsetxattr", "utime", "utimes", "utimensat",
}
_RENAME = {"rename", "renameat", "renameat2"}
_FILE_DELETE = {"unlink", "unlinkat", "rmdir"}
_PROCESS_SPAWN = {"execve", "execveat", "clone", "clone3", "fork", "vfork"}
_PROCESS_TERM = {"exit", "exit_group", "procexit", "kill", "tgkill"}
_NETWORK = {
    "socket", "connect", "accept", "accept4", "bind", "listen", "sendto", "sendmsg",
    "send", "recvfrom", "recvmsg", "recv", "shutdown", "getsockname", "getpeername",
    "setsockopt", "getsockopt",
}
_IS_WRITE = {"write", "writev", "pwrite", "pwrite64", "pwritev", "send", "sendto", "sendmsg"}
_IS_READ = {"read", "pread", "pread64", "preadv", "recv", "recvfrom", "recvmsg"}
# syscalls sysdig never pairs with a matching exit line in these traces
_NO_EXIT_EXPECTED = {"switch", "procexit"}


def _event_type(syscall: str) -> str:
    if syscall in _RENAME or syscall in _FILE_MODIFY:
        return "file_modify"
    if syscall in _FILE_ACCESS:
        return "file_access"
    if syscall in _FILE_DELETE:
        return "file_delete"
    if syscall in _PROCESS_SPAWN:
        return "process_spawn"
    if syscall in _PROCESS_TERM:
        return "process_terminate"
    if syscall in _NETWORK:
        return "network_connection"
    return "syscall"


_KV_SPLIT_RE = re.compile(r" (?=[A-Za-z_][A-Za-z0-9_]*=)")
_FD_RE = re.compile(r"fd=-?\d+\(<([^>]*)>([^)]*)\)")


def _parse_kv(args: str | None) -> tuple[dict, str | None]:
    """Splits a sysdig args string into a {key: value} dict plus a separately-handled
    `data=` value (kept verbatim, not token-split — the sysdig-substituted printable
    content it carries can itself contain stray " word=" -looking substrings that would
    otherwise corrupt the generic key=value split)."""
    if not args:
        return {}, None
    data_val = None
    idx = args.find(" data=")
    if idx != -1:
        data_val = args[idx + len(" data=") :].rstrip()
        args = args[:idx]
    kv = {}
    for token in _KV_SPLIT_RE.split(args.strip()):
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        kv[k] = v
    return kv, data_val


def _fd_type_and_target(args: str | None) -> tuple[str | None, str | None]:
    if not args:
        return None, None
    m = _FD_RE.search(args)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _extract_path(syscall: str, entry_kv: dict, exit_kv: dict, entry_args, exit_args) -> str | None:
    """Best-effort file path resolution — documented heuristic, not authoritative (same
    spirit as Linux-APT-2024's event_type mapping and EN2025's _extract_file_path)."""
    if syscall in _RENAME and "newpath" in exit_kv:
        return exit_kv["newpath"]
    if "name" in exit_kv:
        return exit_kv["name"]
    if "name" in entry_kv:
        return entry_kv["name"]
    for args in (exit_args, entry_args):
        fd_type, target = _fd_type_and_target(args)
        if fd_type == "f" and target and target.startswith("/"):
            return target
    return None


class _PendingEntries:
    """One in-flight `>` (call) line per tid — a single Linux thread can only have one
    syscall in flight at a time, so this is a plain dict, not a stack."""

    def __init__(self):
        self._pending: dict[int, tuple[str, str | None]] = {}

    def push(self, tid: int, syscall: str, args: str | None) -> None:
        self._pending[tid] = (syscall, args)

    def pop_matching(self, tid: int, syscall: str) -> str | None:
        entry = self._pending.pop(tid, None)
        if entry is not None and entry[0] == syscall:
            return entry[1]
        return None

    def drain(self):
        """Entries still pending at EOF (trace cut off mid-syscall) — emitted rather
        than silently dropped."""
        for tid, (syscall, args) in self._pending.items():
            yield tid, syscall, args


def _build_row(
    *,
    sample_id: str,
    source_dataset: str,
    label: str,
    label_type: str,
    timestamp: str | None,
    host_id: str | None,
    pid: int | None,
    tid: int,
    cpu: int,
    proc: str,
    syscall: str,
    entry_args: str | None,
    exit_args: str | None,
    scenario: str,
    recording_name: str,
    split: str | None,
) -> dict:
    entry_kv, _ = _parse_kv(entry_args)
    exit_kv, data_val = _parse_kv(exit_args)
    file_path = _extract_path(syscall, entry_kv, exit_kv, entry_args, exit_args)
    raw_fields = {
        "syscall": syscall,
        "cpu": cpu,
        "tid": tid,
        "proc_name": proc,
        "entry_args": entry_args,
        "exit_args": exit_args,
        "res": exit_kv.get("res"),
        "scenario": scenario,
        "recording_name": recording_name,
    }
    if split is not None:
        raw_fields["split"] = split
    if data_val:
        raw_fields["data"] = data_val
    return {
        "sample_id": sample_id,
        "source_dataset": source_dataset,
        "label": label,
        "label_type": label_type,
        "label_confidence": 1.0,
        "family": None,
        "timestamp": timestamp,
        "host_id": host_id,
        "process_id": pid,
        "event_type": _event_type(syscall),
        "file_path": file_path,
        "raw_fields": json.dumps(raw_fields, default=str),
    }


def _parse_pid(pid_str: str) -> int | None:
    try:
        pid = int(pid_str)
    except ValueError:
        return None
    # 4294967295 (0xFFFFFFFF) is sysdig's sentinel for an unresolved/kernel thread
    # (always paired with proc_name="<NA>" in these traces) — null is the honest
    # reading, not a fabricated huge PID.
    return None if pid == 4294967295 else pid


def _parse_trace_2019(text: str) -> list[dict]:
    """Parses one 2019 sysdig .txt recording into merged entry+exit syscall rows.
    Field order: <line#> <HH:MM:SS.nnnnnnnnn> <cpu> <tid> <proc> <pid> <dir> <syscall args...>"""
    pending = _PendingEntries()
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        _lineno, ts, cpu, tid, proc, pid, direction = parts[:7]
        rest = parts[7] if len(parts) > 7 else ""
        sc_parts = rest.split(None, 1)
        if not sc_parts:
            continue
        syscall = sc_parts[0]
        args = sc_parts[1] if len(sc_parts) > 1 else None
        try:
            tid_i, cpu_i = int(tid), int(cpu)
        except ValueError:
            continue
        pid_i = _parse_pid(pid)
        # seconds-of-day; no calendar date available in this format (same limitation
        # ELFEN's raw `ts` had before it was resolved with task_start_time's date —
        # LID-DS 2019 has no per-scenario equivalent to reconstruct a real date from).
        try:
            h, m, s = ts.split(":")
            sec_of_day = int(h) * 3600 + int(m) * 60 + float(s)
        except ValueError:
            continue
        rel_ts = f"REL:{sec_of_day}"
        ctx = dict(cpu=cpu_i, tid=tid_i, proc=proc, pid=pid_i, timestamp=rel_ts)
        if direction == ">":
            if syscall in _NO_EXIT_EXPECTED:
                rows.append((ctx, syscall, args, None))
            else:
                pending.push(tid_i, syscall, args)
        elif direction == "<":
            entry_args = pending.pop_matching(tid_i, syscall)
            rows.append((ctx, syscall, entry_args, args))
    for tid_i, syscall, args in pending.drain():
        rows.append((dict(cpu=None, tid=tid_i, proc=None, pid=None, timestamp=None), syscall, args, None))
    return rows


def _parse_trace_2021(text: str) -> list[dict]:
    """Parses one 2021 sysdig .sc recording. Field order: <epoch_ns> <cpu> <tid> <proc>
    <pid> <syscall> <dir> <args...> — note syscall comes BEFORE direction here, the
    opposite of 2019's ordering (verified across 4 scenarios, see module docstring)."""
    pending = _PendingEntries()
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 7:
            continue
        ts_ns, cpu, tid, proc, pid, syscall, direction = parts[:7]
        args = parts[7] if len(parts) > 7 else None
        if direction not in ("<", ">"):
            continue
        try:
            tid_i, cpu_i, ts_ns_i = int(tid), int(cpu), int(ts_ns)
        except ValueError:
            continue
        pid_i = _parse_pid(pid)
        abs_ts = datetime.fromtimestamp(ts_ns_i / 1e9, tz=timezone.utc).isoformat()
        ctx = dict(cpu=cpu_i, tid=tid_i, proc=proc, pid=pid_i, timestamp=abs_ts)
        if direction == ">":
            if syscall in _NO_EXIT_EXPECTED:
                rows.append((ctx, syscall, args, None))
            else:
                pending.push(tid_i, syscall, args)
        elif direction == "<":
            entry_args = pending.pop_matching(tid_i, syscall)
            rows.append((ctx, syscall, entry_args, args))
    for tid_i, syscall, args in pending.drain():
        rows.append((dict(cpu=None, tid=tid_i, proc=None, pid=None, timestamp=None), syscall, args, None))
    return rows


# ---------------------------------------------------------------------------
# 2019 — nested tar.gz per scenario inside the outer (stored, seekable) zip
# ---------------------------------------------------------------------------

def _list_2019_scenarios(z: zipfile.ZipFile) -> list[str]:
    return sorted(
        Path(n).stem.removesuffix(".tar")
        for n in z.namelist()
        if n.endswith(".tar.gz")
    )


def _load_2019_scenario(z: zipfile.ZipFile, scenario: str, stats: dict) -> list[pd.DataFrame]:
    member_name = f"LID-DS-2019/{scenario}.tar.gz"

    # Pass 1: stream forward until runs.csv is found (verified at ~94% through for
    # CVE-2014-0160 — not near the start, so this walks most of the archive; still fast
    # given ~590MB/s gzip throughput in this environment). Also records every .txt
    # member's byte SIZE along the way — cheap, read straight from each tar header, no
    # decompression of that member's payload needed (tar stores size in the header,
    # unlike gzip which has no such index — this is the tar equivalent of 2021's
    # zip-central-directory size peek). This turned out load-bearing: a first version
    # of this loader had no 2019 size cap at all (2019's Heartbleed/Bruteforce/
    # SQL-injection scenarios were all confirmed small during format verification, so it
    # seemed safe to assume) until ZipSlip — a file-archive-extraction scenario, i.e.
    # heavy filesystem I/O even in its "normal" runs — was measured still running after
    # 2:48 wall clock and 5.6GB RSS with no cap; the same MAX_SC_BYTES-style discipline
    # 2021 needed turned out to apply to 2019 too, just for a different (single)
    # scenario instead of being pervasive.
    runs_text = None
    sizes: dict[str, int] = {}
    with z.open(member_name) as f1:
        tf1 = tarfile.open(fileobj=f1, mode="r|gz")
        for member in tf1:
            if member.name.endswith(".txt"):
                sizes[Path(member.name).stem] = member.size
            elif member.name.endswith("runs.csv"):
                runs_text = tf1.extractfile(member).read().decode()
                break
    if runs_text is None:
        raise RuntimeError(f"lid_ds 2019 scenario {scenario}: runs.csv not found")

    reader = csv.reader(io.StringIO(runs_text), skipinitialspace=True)
    next(reader)  # header
    normal_names, exploit_names, image_name = [], [], None
    for row in reader:
        if len(row) < 3:
            continue
        image_name = image_name or row[0].strip()
        name = row[1].strip()
        is_exploit = row[2].strip() == "True"
        (exploit_names if is_exploit else normal_names).append(name)

    # runs.csv appears ~94% through the member list, so `sizes` is missing entries for
    # any recording that hasn't been streamed past yet at that point — those are
    # conservatively treated as over-cap (excluded) rather than silently assumed small.
    normal_ok = [n for n in normal_names if sizes.get(n, MAX_SC_BYTES_2019 + 1) <= MAX_SC_BYTES_2019]
    exploit_ok = [n for n in exploit_names if sizes.get(n, MAX_SC_BYTES_2019 + 1) <= MAX_SC_BYTES_2019]

    rng = random.Random(SAMPLE_SEED)
    sampled_normal = set(rng.sample(normal_ok, min(N_NORMAL_SAMPLE, len(normal_ok))))
    selected_exploit = set(rng.sample(exploit_ok, min(MAX_EXPLOIT_SAMPLE_2019, len(exploit_ok))))
    selected = sampled_normal | selected_exploit
    remaining = dict.fromkeys(selected)  # preserve for early-exit tracking

    stats[scenario] = {
        "runs_total": len(normal_names) + len(exploit_names),
        "normal_total": len(normal_names),
        "normal_under_cap": len(normal_ok),
        "exploit_total": len(exploit_names),
        "exploit_under_cap": len(exploit_ok),
        "normal_sampled": len(sampled_normal),
        "exploit_sampled": len(selected_exploit),
        "sizes_known_at_runs_csv": len(sizes),
    }

    rows: list[dict] = []
    frames: list[pd.DataFrame] = []

    def flush():
        nonlocal rows
        if rows:
            frames.append(pd.DataFrame(rows))
            rows = []

    with z.open(member_name) as f2:
        tf2 = tarfile.open(fileobj=f2, mode="r|gz")
        for member in tf2:
            if not member.name.endswith(".txt"):
                continue
            name = Path(member.name).stem
            if name not in remaining:
                continue
            del remaining[name]
            text = tf2.extractfile(member).read().decode(errors="replace")
            is_exploit = name in selected_exploit
            label = "other" if is_exploit else "benign"
            label_type = "generic_intrusion" if is_exploit else "real_execution"
            sample_id = f"{SOURCE_2019}/{scenario}/{name}"
            for ctx, syscall, entry_args, exit_args in _parse_trace_2019(text):
                rows.append(
                    _build_row(
                        sample_id=sample_id,
                        source_dataset=SOURCE_2019,
                        label=label,
                        label_type=label_type,
                        timestamp=ctx["timestamp"],
                        host_id=image_name,
                        pid=ctx["pid"],
                        tid=ctx["tid"] if ctx["tid"] is not None else -1,
                        cpu=ctx["cpu"] if ctx["cpu"] is not None else -1,
                        proc=ctx["proc"] or "",
                        syscall=syscall,
                        entry_args=entry_args,
                        exit_args=exit_args,
                        scenario=scenario,
                        recording_name=name,
                        split=None,
                    )
                )
            if len(rows) >= _FLUSH_EVERY_ROWS:
                flush()
            if not remaining:
                break
    flush()
    return frames


def load_2019() -> tuple[pd.DataFrame, dict]:
    z = zipfile.ZipFile(ZIP_2019)
    scenarios = _list_2019_scenarios(z)
    stats: dict = {}
    all_frames: list[pd.DataFrame] = []
    for scenario in scenarios:
        all_frames.extend(_load_2019_scenario(z, scenario, stats))
        print(f"[lid_ds-2019] {scenario}: {stats[scenario]}", flush=True)
    df = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame()
    return df, {"scenarios": stats}


# ---------------------------------------------------------------------------
# 2021 — nested per-scenario zip (random-access, no full decompression needed);
# recordings are either a directory of 4 loose files or a nested per-recording .zip
# ---------------------------------------------------------------------------

_SPLIT_RE = re.compile(r"^[^/]+/(training|validation|test/normal|test/normal_and_attack)/([^/]+)")


def _list_2021_scenarios(z: zipfile.ZipFile) -> list[str]:
    return sorted(Path(n).stem for n in z.namelist() if n.endswith(".zip"))


def _index_2021_recordings(inner: zipfile.ZipFile) -> dict[str, dict]:
    """Groups the scenario zip's flat member list into {recording_name: {split, kind,
    entries}}. `kind` is "dir" (loose .sc/.json members) or "zip" (one nested
    <name>.zip containing them) — verified both exist across different 2021 scenarios,
    not assumed uniform.

    A real bug hit here (not in the 5-scenario format verification, which inspected
    structure but never exhaustively ran the size-cap check over every candidate): macOS
    `.DS_Store` files are present directly inside `training/`, `validation/`,
    `test/normal/`, and `test/normal_and_attack/` in several scenarios (verified on
    CVE-2014-0160 and CVE-2012-2122) and `_SPLIT_RE` happily matches them as if
    `.DS_Store` were a recording name — since it doesn't end in `.zip`, it falls into the
    "dir" branch as a bogus recording with an empty `entries` dict (no `.sc`/`.json`
    member ever matches its own filename), which then KeyErrors in `_recording_sc_size`
    the first time it's checked. Explicitly excluded here, the same way `__MACOSX` and
    directory entries already are.
    """
    recordings: dict[str, dict] = {}
    for name in inner.namelist():
        if "__MACOSX" in name or name.endswith("/") or name.endswith(".DS_Store"):
            continue
        m = _SPLIT_RE.match(name)
        if not m:
            continue
        split, rec_part = m.group(1), m.group(2)
        if rec_part.endswith(".zip"):
            rec_name = rec_part[: -len(".zip")]
            recordings.setdefault(rec_name, {"split": split, "kind": "zip", "entries": {"zip": name}})
        else:
            rec_name = rec_part
            entry = recordings.setdefault(rec_name, {"split": split, "kind": "dir", "entries": {}})
            if name.endswith(".sc"):
                entry["entries"]["sc"] = name
            elif name.endswith(".json"):
                entry["entries"]["json"] = name
    # Defensive net beyond the .DS_Store exclusion above: any "dir" kind recording that
    # still ended up without a real .sc member (e.g. some other unforeseen non-.sc/.json
    # loose file matching the split pattern in a scenario not yet seen) is dropped here
    # rather than allowed to KeyError deeper in the pipeline — same "exclude, don't
    # crash or silently fabricate" discipline as the size-cap handling elsewhere in this
    # module.
    return {
        name: rec
        for name, rec in recordings.items()
        if rec["kind"] == "zip" or "sc" in rec["entries"]
    }


def _recording_sc_size(inner: zipfile.ZipFile, rec: dict) -> int:
    """Uncompressed .sc byte size WITHOUT decompressing the .sc payload itself — for
    "dir" kind it's a direct central-directory lookup on the scenario zip; for "zip"
    kind it still requires decompressing the (small, ~5-12MB) per-recording zip
    container, but not the (potentially 10-200MB) .sc member inside it, since the
    container's own central directory lists that member's size once it's open. This is
    the cheap check used to apply MAX_SC_BYTES_2021 before paying for the expensive
    part (decompressing + line-parsing the .sc content)."""
    if rec["kind"] == "zip":
        # Deliberately does NOT cache the decompressed container bytes: an earlier
        # version cached every candidate's ~5-12MB per-recording zip (checked for size
        # even on the ~90% of candidates that end up over-cap and never selected),
        # which retained gigabytes of dead weight for the whole scenario and was the
        # actual cause of the >12GB RSS incident this cap exists to prevent — the .sc
        # payload itself was never the problem, the *candidate-checking* bookkeeping
        # was. Re-decompressing this small container a second time for the ~1 in 10
        # candidates that get selected (see _read_recording_files) is cheap
        # (~0.03-0.2s measured) and worth it to keep peak memory bounded by the
        # selection, not the candidate pool.
        data = inner.read(rec["entries"]["zip"])
        rz = zipfile.ZipFile(io.BytesIO(data))
        sc_name = next(n for n in rz.namelist() if n.endswith(".sc"))
        return rz.getinfo(sc_name).file_size
    return inner.getinfo(rec["entries"]["sc"]).file_size


def _read_recording_files(inner: zipfile.ZipFile, rec: dict) -> tuple[str, dict]:
    """Returns (sc_text, json_dict) for one recording, transparently handling both
    packagings."""
    if rec["kind"] == "zip":
        data = inner.read(rec["entries"]["zip"])
        rz = zipfile.ZipFile(io.BytesIO(data))
        sc_name = next(n for n in rz.namelist() if n.endswith(".sc"))
        json_name = next(n for n in rz.namelist() if n.endswith(".json"))
        sc_text = rz.read(sc_name).decode(errors="replace")
        meta = json.loads(rz.read(json_name))
    else:
        sc_text = inner.read(rec["entries"]["sc"]).decode(errors="replace")
        meta = json.loads(inner.read(rec["entries"]["json"]))
    return sc_text, meta


_FLUSH_EVERY_ROWS = 200_000  # bounds peak Python-object memory per scenario


def _load_2021_scenario(z: zipfile.ZipFile, scenario: str, stats: dict) -> list[pd.DataFrame]:
    member_name = f"{scenario}.zip"
    frames: list[pd.DataFrame] = []
    rows: list[dict] = []

    def flush():
        nonlocal rows
        if rows:
            frames.append(pd.DataFrame(rows))
            rows = []

    with z.open(member_name) as f:
        inner = zipfile.ZipFile(f)
        recordings = _index_2021_recordings(inner)

        normal_pool = [n for n, r in recordings.items() if r["split"] != "test/normal_and_attack"]
        exploit_pool = [n for n, r in recordings.items() if r["split"] == "test/normal_and_attack"]

        # Cheap size peek (never decompresses the .sc payload itself — see
        # _recording_sc_size) BEFORE sampling, so oversized recordings never get a
        # chance to be selected in the first place — see MAX_SC_BYTES_2021's docstring
        # for why this cap exists (a real >12GB RSS incident on Juice-Shop, not a
        # theoretical concern).
        def under_cap(name: str) -> bool:
            return _recording_sc_size(inner, recordings[name]) <= MAX_SC_BYTES_2021

        normal_ok = [n for n in normal_pool if under_cap(n)]
        exploit_ok = [n for n in exploit_pool if under_cap(n)]

        rng = random.Random(SAMPLE_SEED)
        sampled_normal = set(rng.sample(normal_ok, min(N_NORMAL_SAMPLE_2021, len(normal_ok))))
        selected_exploit = set(
            rng.sample(exploit_ok, min(MAX_EXPLOIT_SAMPLE_2021, len(exploit_ok)))
        )

        stats[scenario] = {
            "recordings_total": len(recordings),
            "normal_total": len(normal_pool),
            "normal_under_cap": len(normal_ok),
            "exploit_total": len(exploit_pool),
            "exploit_under_cap": len(exploit_ok),
            "normal_sampled": len(sampled_normal),
            "exploit_sampled": len(selected_exploit),
        }

        for name in sampled_normal | selected_exploit:
            rec = recordings[name]
            sc_text, meta = _read_recording_files(inner, rec)
            json_exploit = bool(meta.get("exploit"))
            dir_says_exploit = name in selected_exploit
            if json_exploit != dir_says_exploit:
                stats.setdefault("label_mismatches", []).append(
                    f"{scenario}/{name}: dir={dir_says_exploit} json={json_exploit}"
                )
            is_exploit = dir_says_exploit  # directory convention used as ground truth (see docstring)
            label = "other" if is_exploit else "benign"
            label_type = "generic_intrusion" if is_exploit else "real_execution"
            image_name = meta.get("image")
            sample_id = f"{SOURCE_2021}/{scenario}/{name}"
            for ctx, syscall, entry_args, exit_args in _parse_trace_2021(sc_text):
                rows.append(
                    _build_row(
                        sample_id=sample_id,
                        source_dataset=SOURCE_2021,
                        label=label,
                        label_type=label_type,
                        timestamp=ctx["timestamp"],
                        host_id=image_name,
                        pid=ctx["pid"],
                        tid=ctx["tid"] if ctx["tid"] is not None else -1,
                        cpu=ctx["cpu"] if ctx["cpu"] is not None else -1,
                        proc=ctx["proc"] or "",
                        syscall=syscall,
                        entry_args=entry_args,
                        exit_args=exit_args,
                        scenario=scenario,
                        recording_name=name,
                        split=rec["split"],
                    )
                )
            if len(rows) >= _FLUSH_EVERY_ROWS:
                flush()
    flush()
    return frames


def load_2021() -> tuple[pd.DataFrame, dict]:
    z = zipfile.ZipFile(ZIP_2021)
    scenarios = _list_2021_scenarios(z)
    stats: dict = {}
    all_frames: list[pd.DataFrame] = []
    for scenario in scenarios:
        all_frames.extend(_load_2021_scenario(z, scenario, stats))
        print(f"[lid_ds-2021] {scenario}: {stats[scenario]}", flush=True)
    df = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame()
    return df, {"scenarios": stats}


def main() -> None:
    df19, stats19 = load_2019()
    validated19 = validate_tier1(df19)
    OUT_2019.parent.mkdir(parents=True, exist_ok=True)
    validated19.to_parquet(OUT_2019, index=False)
    print(f"[lid_ds-2019] stats: {json.dumps(stats19, indent=2, default=str)}")
    print(f"[lid_ds-2019] rows written: {len(validated19)}")
    print(f"[lid_ds-2019] label distribution:\n{validated19['label'].value_counts()}")
    print(f"[lid_ds-2019] wrote {OUT_2019}")

    df21, stats21 = load_2021()
    validated21 = validate_tier1(df21)
    OUT_2021.parent.mkdir(parents=True, exist_ok=True)
    validated21.to_parquet(OUT_2021, index=False)
    print(f"[lid_ds-2021] stats: {json.dumps(stats21, indent=2, default=str)}")
    print(f"[lid_ds-2021] rows written: {len(validated21)}")
    print(f"[lid_ds-2021] label distribution:\n{validated21['label'].value_counts()}")
    print(f"[lid_ds-2021] wrote {OUT_2021}")


if __name__ == "__main__":
    main()
