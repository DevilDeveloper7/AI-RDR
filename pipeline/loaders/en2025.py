"""Loader for the EN2025 dataset (Tier 1 — raw-event).

Source: https://zenodo.org/records/18218588 (Chen Ziqian, Jan 2026, MIT license).
  data/en2025/{benign,ransomware}.7z, each containing one folder per sample (folder
  name = the sample's SHA256), each with exactly two files:
    - report.json — a CAPE sandbox (Cuckoo-derived, v2.4-CAPE) dynamic-analysis report.
      **This is a Windows sandbox** ("win10" KVM guest, PE32 samples) — despite the rest
      of this repo's Linux-host focus, EN2025 itself is Windows telemetry.
    - dump.pcap — the raw network capture from the same run. **Not parsed here** (see
      "pcap parsing" note below) — CAPE's own `network.*` section in report.json already
      contains a parsed summary (tcp/udp/http/dns/smtp/irc) derived from this same pcap,
      so re-parsing the raw pcap bytes ourselves would mostly duplicate work CAPE already
      did, not add new signal. Most pcaps are empty anyway (797/919 benign samples have a
      24-byte/empty dump.pcap — "no network traffic" per the Zenodo description).

Structure inspected before writing any parsing logic (per planning/normalization-progress.md's
own stated method), across small/medium/large samples in both subsets:
  report.json top level: statistics, target, [detections], CAPE, info, behavior, debug,
  network, suricata, url_analysis, procmemory, signatures, malscore, ttps, malstatus,
  [capa_summary]. The two raw-event-shaped sources are:
    - behavior.processes[].calls[] — per-process, per-API-call trace (timestamp, thread,
      category, api, status, return, arguments, repeated-count). This is the "endpoint
      API call log" the Zenodo description refers to, and is what's normalized into rows
      here (one row per call) — directly analogous to ELFEN's fileops/procops/netops
      events, at a different (Windows API) granularity.
    - behavior.enhanced[] was inspected and NOT used — it turned out to be a *derived*,
      already-summarized subset of `calls` covering only file/registry/library events
      (checked on a sample: enhanced only ever contains event ∈ {load,read,write,delete},
      object ∈ {file,registry,library} — a strict subset of what `calls` already covers
      in more detail). Parsing both would double-count file/registry events, the same
      trap the ELFEN loader avoided with ProcOPS vs Reports. `calls` alone is used.
  `detections[].family` (present on some ransomware samples, via CAPE's own YARA
  matching) supplies `family` when available; it's frequently absent (only ~36% of a
  150-sample check had any `detections` at all) and, when present, sometimes internally
  inconsistent in casing ("Lockbit" vs "LockBit", "Gandcrab" vs "GandCrab") or genuinely
  conflicting across multiple YARA hits on the same sample (e.g. one sample detected as
  both "Cerber" and "BadRabbit") — the first-listed entry is used for `family` as-is (no
  case-normalization, no attempt to arbitrate conflicting hits), and the full
  `detections` list is preserved in `raw_fields` on that sample's process_spawn rows so
  the ambiguity isn't silently hidden.

SIZE — corrects a real discrepancy in prior scoping notes: `planning/normalization-progress.md`
and `analysis/dataset-plan.md` describe ransomware-set `report.json` files as "up to 75MB".
Verified false after extraction: actual max is **316MB** (79 of 733 files exceed 75MB, 6
exceed 150MB); median is ~25MB. Benign-set files were described as "2-5MB" — mostly true
(median 2.8MB) but a handful reach 132MB there too. **Streaming JSON parsing (ijson) is
used throughout, never json.load()**, specifically because of this. A single combined
`ijson.parse()` pass per file (not `ijson.items()`, which would still materialize each
whole process — including one process's full call list — as one Python object; measured
safe up to ~45K calls/process here, but a single-token-at-a-time parse is a strictly
tighter bound) extracts small sample-level metadata (info/target/malscore/detections/
network-summary counts) AND streams `calls` one call at a time via `ijson.common.ObjectBuilder`,
so peak memory is bounded by one call/one small metadata object, not by file size. This
was verified empirically: a full metadata-only scan and a full calls-count scan of all
733 ransomware files (24GB) each held RSS under ~200MB throughout — no repeat of the
Lifecycle loader's 41GB blowup risk.

A real bug was caught here too (same family as Lifecycle's): CAPE's `network.*` summary
uses `time` (relative, seconds since capture start) for tcp/udp entries but a
*different* field, `first_seen` (an absolute Unix epoch float), for http/dns/smtp
entries. A first version only checked for `time`, silently leaving `timestamp` null on
every http/dns/smtp/irc network row (550 rows). Caught by a post-run null-timestamp
check and fixed in `_net_entry_timestamp()` — see its docstring.

Output: data/normalized/en2025_raw_events.parquet
"""

from __future__ import annotations

import datetime
import glob
import json
import os
import shutil
import subprocess
from pathlib import Path

import ijson
import pandas as pd
import polars as pl
from ijson.common import ObjectBuilder

from pipeline.schema import validate_tier1

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "en2025"
EXTRACT_DIR = DATA_DIR / "extracted"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "en2025_raw_events.parquet"

SOURCE_DATASET = "en2025"

_ARCHIVES = {"benign": "benign.7z", "ransomware": "ransomware.7z"}
_NET_SECTIONS = ("tcp", "udp", "http", "dns", "smtp", "irc")

# --- event_type mapping -----------------------------------------------------
# API-level overrides where the category alone is too coarse to tell reads from
# writes/deletes (filesystem, registry) or spawns from generic manipulation
# (process/threading/services). Anything in a mapped category but not in this table
# (and anything in an unmapped category, e.g. system/misc/synchronization/hooking/com/
# device/__notification__) falls back to _CATEGORY_FALLBACK, then "syscall".
_API_EVENT_TYPE = {
    # filesystem
    "NtOpenFile": "file_access", "NtCreateFile": "file_access",
    "NtQueryAttributesFile": "file_access", "NtQueryFullAttributesFile": "file_access",
    "NtQueryInformationFile": "file_access", "NtOpenDirectoryObject": "file_access",
    "NtReadFile": "file_access", "GetFileVersionInfoSizeW": "file_access",
    "GetFileVersionInfoW": "file_access", "FindFirstFileExW": "file_access",
    "GetFileAttributesW": "file_access",
    "NtWriteFile": "file_modify", "NtSetInformationFile": "file_modify",
    "MoveFileWithProgressTransactedW": "file_modify", "MoveFileWithProgressW": "file_modify",
    "CopyFileW": "file_modify", "CopyFileA": "file_modify",
    "NtDeleteFile": "file_delete", "DeleteFileW": "file_delete", "DeleteFileA": "file_delete",
    "RemoveDirectoryA": "file_delete", "RemoveDirectoryW": "file_delete",
    # registry
    "NtQueryValueKey": "registry_access", "RegQueryValueExW": "registry_access",
    "RegQueryValueExA": "registry_access", "NtOpenKeyEx": "registry_access",
    "NtOpenKey": "registry_access", "RegOpenKeyExW": "registry_access",
    "RegOpenKeyExA": "registry_access", "NtQueryKey": "registry_access",
    "RegEnumValueW": "registry_access", "RegEnumKeyExW": "registry_access",
    "RegCloseKey": "registry_access", "NtEnumerateKey": "registry_access",
    "NtEnumerateValueKey": "registry_access", "RegQueryInfoKeyW": "registry_access",
    "RegCreateKeyExW": "registry_modify", "RegCreateKeyExA": "registry_modify",
    "NtCreateKey": "registry_modify", "RegSetValueExW": "registry_modify",
    "RegSetValueExA": "registry_modify", "NtSetValueKey": "registry_modify",
    "RegDeleteValueW": "registry_delete", "RegDeleteValueA": "registry_delete",
    "RegDeleteKeyW": "registry_delete", "RegDeleteKeyA": "registry_delete",
    "NtDeleteValueKey": "registry_delete", "NtDeleteKey": "registry_delete",
    # process
    "NtCreateUserProcess": "process_spawn", "CreateProcessInternalW": "process_spawn",
    "CreateProcessW": "process_spawn", "CreateProcessA": "process_spawn",
    "ShellExecuteExW": "process_spawn",
    "NtTerminateProcess": "process_terminate",
    # threading
    "NtCreateThreadEx": "process_spawn", "CreateThread": "process_spawn",
    "NtResumeThread": "thread_control", "NtTerminateThread": "thread_control",
    "NtOpenThread": "thread_control", "NtQueryInformationThread": "thread_control",
    "NtYieldExecution": "thread_control",
    # services
    "OpenSCManagerW": "service_control", "OpenSCManagerA": "service_control",
    "OpenServiceW": "service_control", "StartServiceW": "service_control",
    "ControlService": "service_control", "CreateServiceW": "service_control",
    "DeleteService": "service_control",
}
_CATEGORY_FALLBACK = {
    "filesystem": "file_access",
    "registry": "registry_access",
    "process": "process_manipulation",
    "threading": "thread_control",
    "network": "network_connection",
    "crypto": "crypto_operation",
    "services": "service_control",
}
_FS_PATH_ARGS = ("FileName", "NewFileName", "HandleName", "ExistingFileName", "DirectoryName")
_PROC_PATH_ARGS = ("ImagePathName", "ProcessFileName", "ModuleName")


def _event_type(category: str, api: str) -> str:
    return _API_EVENT_TYPE.get(api) or _CATEGORY_FALLBACK.get(category, "syscall")


def _extract_file_path(category: str, api: str, arguments: list) -> str | None:
    arg_map = {a.get("name"): a.get("value") for a in arguments if isinstance(a, dict)}
    if category == "filesystem":
        for key in _FS_PATH_ARGS:
            v = arg_map.get(key)
            if v:
                return v
    elif category == "process" and api in ("NtCreateUserProcess", "CreateProcessInternalW", "CreateProcessW", "CreateProcessA"):
        for key in _PROC_PATH_ARGS:
            v = arg_map.get(key)
            if v:
                return v
    return None


def _fmt_ts(raw: str | None) -> str | None:
    """'YYYY-MM-DD HH:MM:SS,fff' -> 'YYYY-MM-DDTHH:MM:SS.fff'. No timezone is stated
    anywhere in the source (sandbox host clock, not marked UTC like ELFEN's `ts` was) —
    kept as a naive local timestamp rather than fabricating a UTC/'Z' suffix."""
    if not raw:
        return None
    return raw.replace(" ", "T").replace(",", ".")


def _net_entry_timestamp(entry) -> str | None:
    """CAPE's network.* summary uses two different, incompatible timestamp fields
    depending on protocol: tcp/udp entries carry `time` (a float, seconds since the
    capture started — relative, no wall-clock meaning on its own), while http/dns/smtp
    entries carry `first_seen` (a *different* field — a Unix epoch float, an absolute
    wall-clock timestamp) instead. A first version of this loader only checked for
    `time`, which silently left `timestamp` null for every http/dns/smtp/irc network
    row (550 of 1652 samples' worth, ~0.002% of rows overall but 100% of those event
    types) — caught by a post-run null-timestamp check, the same kind of sanity check
    that caught the Lifecycle loader's header-row bug. Fixed by checking both fields
    and formatting them according to what they actually are: `time` stays a flagged
    relative offset (`REL:<seconds>`), `first_seen` is converted to a real absolute
    UTC ISO-8601 timestamp (it round-trips as a plain epoch float, not a relative one)."""
    if not isinstance(entry, dict):
        return None
    if "time" in entry:
        return f"REL:{entry['time']}"
    if "first_seen" in entry:
        try:
            return datetime.datetime.fromtimestamp(
                float(entry["first_seen"]), tz=datetime.timezone.utc
            ).isoformat()
        except (TypeError, ValueError):
            return None
    return None


def _ensure_extracted() -> None:
    for name, archive_name in _ARCHIVES.items():
        dest = EXTRACT_DIR / name
        if dest.exists() and any(dest.iterdir()):
            continue
        archive_path = DATA_DIR / archive_name
        if not archive_path.exists():
            raise FileNotFoundError(f"missing archive: {archive_path}")
        seven_zip = shutil.which("7z") or shutil.which("7za")
        if not seven_zip:
            raise RuntimeError("7z/7za not found on PATH; cannot extract EN2025 archives")
        EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [seven_zip, "x", str(archive_path), f"-o{EXTRACT_DIR}", "-y"],
            check=True,
            capture_output=True,
        )


def _parse_sample(path: Path, label: str, sample_id: str) -> tuple[list[dict], dict]:
    """Single streaming ijson.parse() pass: extracts small sample-level metadata and
    yields one row per behavior.processes[].calls[] entry, plus one synthetic
    'process_spawn' row per process (from its own first_seen — the process's own launch
    is never itself an API call CAPE hooked, only its *children*'s spawns are), plus one
    'network_connection' row per CAPE-parsed network.{tcp,udp,http,dns,smtp,irc} entry
    (CAPE's own pcap-derived summary — see module docstring on why dump.pcap itself is
    not re-parsed). Bounded memory: only one call/process/network-item is ever fully
    built at a time via ObjectBuilder; nothing whole-file-sized is materialized.
    """
    meta: dict = {"sha256": None, "detections": None}
    net_counts = {k: 0 for k in _NET_SECTIONS}

    rows: list[dict] = []
    process_start_row_indices: list[int] = []  # patched with sample-level meta after the fact

    det_builder: ObjectBuilder | None = None
    net_builder: ObjectBuilder | None = None
    net_key: str | None = None

    proc_meta: dict = {}
    call_builder: ObjectBuilder | None = None

    def base_row(timestamp, process_id, event_type, file_path, raw_fields: dict) -> dict:
        # raw_fields kept as a plain dict here (not yet JSON-serialized) — family and,
        # for process_start rows, sample-level metadata are only known once the whole
        # file has been parsed (detections can appear after behavior in the document),
        # so serializing once at the very end (in load()) avoids a wasteful
        # json.dumps-then-json.loads round trip per row just to patch two fields.
        return {
            "sample_id": sample_id,
            "source_dataset": SOURCE_DATASET,
            "label": label,
            "label_type": "real_execution",
            "label_confidence": 1.0,
            "family": None,  # filled in by load() after detections is fully known
            "timestamp": timestamp,
            "host_id": meta.get("host_id"),
            "process_id": process_id,
            "event_type": event_type,
            "file_path": file_path,
            "raw_fields": raw_fields,
        }

    with open(path, "rb") as f:
        for prefix, event, value in ijson.parse(f):
            if prefix == "info.id":
                meta["info_id"] = value
            elif prefix == "info.started":
                meta["started"] = value
            elif prefix == "info.ended":
                meta["ended"] = value
            elif prefix == "info.duration":
                meta["duration"] = value
            elif prefix == "info.machine.name":
                meta["host_id"] = value
            elif prefix == "target.file.sha256":
                meta["sha256"] = value
            elif prefix == "target.file.md5":
                meta["md5"] = value
            elif prefix == "target.file.name":
                meta["filename"] = value
            elif prefix == "target.file.size":
                meta["filesize"] = value
            elif prefix == "malscore":
                meta["malscore"] = value
            elif prefix == "malstatus":
                meta["malstatus"] = value
            elif prefix == "detections" and event == "start_array":
                det_builder = ObjectBuilder()
                det_builder.event(event, value)
            elif det_builder is not None:
                det_builder.event(event, value)
                if prefix == "detections" and event == "end_array":
                    meta["detections"] = det_builder.value
                    det_builder = None
            elif (
                net_builder is None
                and any(prefix == f"network.{k}" for k in _NET_SECTIONS)
                and event == "start_array"
            ):
                net_key = prefix.split(".")[1]
                net_builder = ObjectBuilder()
                net_builder.event(event, value)
            elif net_builder is not None and prefix.startswith(f"network.{net_key}"):
                net_builder.event(event, value)
                if prefix == f"network.{net_key}" and event == "end_array":
                    entries = net_builder.value
                    net_counts[net_key] = len(entries)
                    for entry in entries:
                        ts = _net_entry_timestamp(entry)
                        rows.append(
                            base_row(
                                ts,
                                None,
                                "network_connection",
                                None,
                                {"source": "pcap_summary", "proto": net_key, **(entry if isinstance(entry, dict) else {"value": entry})},
                            )
                        )
                    net_builder = None
                    net_key = None
            elif prefix == "behavior.processes.item" and event == "start_map":
                proc_meta = {}
            elif prefix == "behavior.processes.item.process_id":
                proc_meta["process_id"] = value
            elif prefix == "behavior.processes.item.process_name":
                proc_meta["process_name"] = value
            elif prefix == "behavior.processes.item.parent_id":
                proc_meta["parent_id"] = value
            elif prefix == "behavior.processes.item.module_path":
                proc_meta["module_path"] = value
            elif prefix == "behavior.processes.item.first_seen":
                proc_meta["first_seen"] = value
                # emit the process's own launch as a synthetic process_spawn row —
                # CAPE never hooks a process's OWN creation (only children it spawns),
                # so without this the initial launch of every sample would be invisible
                process_start_row_indices.append(len(rows))
                rows.append(
                    base_row(
                        _fmt_ts(value),
                        proc_meta.get("process_id"),
                        "process_spawn",
                        proc_meta.get("module_path"),
                        {
                            "source": "process_start",
                            "process_name": proc_meta.get("process_name"),
                            "parent_id": proc_meta.get("parent_id"),
                        },
                    )
                )
            elif prefix == "behavior.processes.item.calls.item" and event == "start_map":
                call_builder = ObjectBuilder()
                call_builder.event(event, value)
            elif call_builder is not None:
                call_builder.event(event, value)
                if prefix == "behavior.processes.item.calls.item" and event == "end_map":
                    call = call_builder.value
                    call_builder = None
                    category = call.get("category", "")
                    api = call.get("api", "")
                    arguments = call.get("arguments") or []
                    rows.append(
                        base_row(
                            _fmt_ts(call.get("timestamp")),
                            proc_meta.get("process_id"),
                            _event_type(category, api),
                            _extract_file_path(category, api, arguments),
                            {
                                "category": category,
                                "api": api,
                                "status": call.get("status"),
                                "return": call.get("return"),
                                "arguments": arguments,
                                "repeated": call.get("repeated"),
                                "thread_id": call.get("thread_id"),
                                "caller": call.get("caller"),
                                "parentcaller": call.get("parentcaller"),
                            },
                        )
                    )

    meta["net_counts"] = net_counts
    return rows, meta, process_start_row_indices


def load() -> tuple[pd.DataFrame, dict]:
    _ensure_extracted()

    stats = {"benign": {"samples": 0, "rows": 0}, "ransomware": {"samples": 0, "rows": 0}}
    family_hash_mismatches = []
    frames: list[pl.DataFrame] = []

    for subset, label in (("benign", "benign"), ("ransomware", "ransomware")):
        sample_dirs = sorted(glob.glob(str(EXTRACT_DIR / subset / "*")))
        for d in sample_dirs:
            sample_id = os.path.basename(d)
            report_path = Path(d) / "report.json"
            if not report_path.is_file():
                continue
            rows, meta, process_start_row_indices = _parse_sample(report_path, label, sample_id)
            if meta.get("sha256") and meta["sha256"] != sample_id:
                family_hash_mismatches.append((sample_id, meta.get("sha256")))

            family = None
            detections = meta.get("detections")
            if detections:
                family = detections[0].get("family")

            # sample-level facts (malscore/malstatus/filesize/md5/duration/detections/
            # net_counts) are attached once per process (via each process's synthetic
            # process_start row), not once per call — bounded by process count
            # (~1-100/sample), not event count (~15k+/sample), to avoid bloating
            # raw_fields with the same sample-level facts repeated on every single row.
            extra_meta = {
                "sample_md5": meta.get("md5"),
                "sample_filename": meta.get("filename"),
                "sample_filesize": meta.get("filesize"),
                "info_id": meta.get("info_id"),
                "duration": meta.get("duration"),
                "malscore": meta.get("malscore"),
                "malstatus": meta.get("malstatus"),
                "detections": detections,
                "net_counts": meta.get("net_counts"),
            }
            for idx in process_start_row_indices:
                rows[idx]["raw_fields"].update(extra_meta)
            for row in rows:
                row["family"] = family
                row["raw_fields"] = json.dumps(row["raw_fields"], default=str)

            if rows:
                frames.append(pl.DataFrame(rows))
            stats[subset]["samples"] += 1
            stats[subset]["rows"] += len(rows)

    combined = pl.concat(frames, how="diagonal_relaxed") if frames else pl.DataFrame()
    stats["sha256_mismatches"] = family_hash_mismatches
    return combined.to_pandas(), stats


def main() -> None:
    df, stats = load()
    validated = validate_tier1(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[en2025] per-subset stats: {stats}")
    print(f"[en2025] rows written: {len(validated)}")
    print(f"[en2025] label distribution:\n{validated['label'].value_counts()}")
    print(f"[en2025] event_type distribution:\n{validated['event_type'].value_counts()}")
    print(f"[en2025] family (non-null) distribution:\n{validated['family'].value_counts()}")
    print(f"[en2025] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
