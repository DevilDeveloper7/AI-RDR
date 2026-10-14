"""Loader for the ELFEN Linux Ransomware Analysis Reports (Tier 1 — raw-event).

Source: data/linux-ransomware-elfen/Linux Ransomware Analysis/<Family>/Reports/*.json
  - Each Reports/*.json is one ELFEN sandbox execution report for one sample.
  - report.data.dynamic.{fileops,procops,netops}.data are lists of raw syscall-level
    events (ts/pid/procname/func/args/ret) — these ARE the raw events we normalize.
  - The separate ProcOPS/*.json files were checked and are byte-for-byte identical to
    report.data.dynamic.procops.data for the same sample (verified on a Babuk sample),
    so they are NOT parsed separately here — that would just double-count events.
  - `ts` inside each event is a time-of-day only (e.g. "11:32:25.771310 UTC"), no date;
    combined here with the date portion of the report's own `task_start_time` to get a
    real absolute UTC timestamp (rolled forward a day if the time-of-day would otherwise
    be earlier than the run's start time, to handle a midnight-crossing run).

Output: data/normalized/elfen_raw_events.parquet
"""

from __future__ import annotations

import glob
import json
import re
from datetime import timedelta
from pathlib import Path

import pandas as pd

from pipeline.schema import validate_tier1

DATA_DIR = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "linux-ransomware-elfen"
    / "Linux Ransomware Analysis"
)
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "elfen_raw_events.parquet"

SOURCE_DATASET = "linux_ransomware_elfen"

_PATH_KEYS = ["newfile_path", "file_path", "exec_path", "oldfile_path", "path"]
_PATH_RE = {key: re.compile(rf"{key}:\s*b'([^']*)'") for key in _PATH_KEYS}

_FILEOPS_EVENT_TYPE = {
    "open": "file_access",
    "read": "file_access",
    "readlink": "file_access",
    "fcntl": "file_access",
    "write": "file_modify",
    "rename": "file_modify",
    "unlink": "file_delete",
}
_PROCOPS_EVENT_TYPE = {
    "execve": "process_spawn",
    "fork": "process_spawn",
    "clone": "process_spawn",
    "prctl": "process_config",
    "getpid": "process_info",
    "getppid": "process_info",
}


def _extract_path(args: str) -> str | None:
    if not args:
        return None
    for key in _PATH_KEYS:
        m = _PATH_RE[key].search(args)
        if m and m.group(1):
            return m.group(1)
    return None


def _resolve_timestamp(ts: str, start_dt: pd.Timestamp) -> str | None:
    """Combine an event's time-of-day ('HH:MM:SS.ffffff UTC') with the report's start date."""
    if not ts:
        return None
    time_part = ts.replace(" UTC", "").strip()
    try:
        candidate = pd.Timestamp(f"{start_dt.date()}T{time_part}Z")
    except (ValueError, TypeError):
        return None
    # a short sandbox run should never see an event more than ~1h "before" its own
    # start time-of-day; if that happens, the run crossed midnight — roll forward a day
    if candidate < start_dt - pd.Timedelta(hours=1):
        candidate = candidate + timedelta(days=1)
    return candidate.isoformat()


def _events_from_report(report: dict, family: str, sample_id: str, host_id: str) -> list[dict]:
    task_status = report.get("task_status")
    try:
        start_dt = pd.Timestamp(report["task_start_time"]).tz_localize("UTC")
    except (KeyError, ValueError, TypeError):
        start_dt = None

    dyn = report.get("data", {}).get("dynamic", {}) or {}
    events = []
    for category, func_map in (
        ("fileops", _FILEOPS_EVENT_TYPE),
        ("procops", _PROCOPS_EVENT_TYPE),
        ("netops", {}),
    ):
        for e in (dyn.get(category, {}) or {}).get("data") or []:
            func = e.get("func")
            event_type = func_map.get(func) if category != "netops" else "network_connection"
            if event_type is None:
                event_type = "syscall"
            timestamp = _resolve_timestamp(e.get("ts"), start_dt) if start_dt is not None else None
            events.append(
                {
                    "sample_id": sample_id,
                    "source_dataset": SOURCE_DATASET,
                    "label": "ransomware",
                    "label_type": "real_execution",
                    "label_confidence": 1.0,
                    "family": family,
                    "timestamp": timestamp,
                    "host_id": host_id,
                    "process_id": e.get("pid"),
                    "event_type": event_type,
                    "file_path": _extract_path(e.get("args", "")),
                    "raw_fields": json.dumps(
                        {
                            "category": category,
                            "func": func,
                            "procname": e.get("procname"),
                            "args": e.get("args"),
                            "ret": e.get("ret"),
                            "task_status": task_status,
                        },
                        default=str,
                    ),
                }
            )
    return events


def load() -> pd.DataFrame:
    report_paths = sorted(glob.glob(str(DATA_DIR / "*" / "Reports" / "*.json")))
    if not report_paths:
        raise FileNotFoundError(f"no Reports/*.json found under {DATA_DIR}")

    all_events = []
    n_reports = 0
    n_incomplete = 0
    for path in report_paths:
        n_reports += 1
        family = Path(path).parent.parent.name
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        report = doc.get("report", {})
        if report.get("task_status") != "Complete":
            n_incomplete += 1
        sample_id = report.get("sample_metadata", {}).get("sha256") or Path(path).stem
        host_id = doc.get("submission_uuid")
        all_events.extend(_events_from_report(report, family, sample_id, host_id))

    df = pd.DataFrame.from_records(all_events)
    return df, n_reports, n_incomplete


def main() -> None:
    df, n_reports, n_incomplete = load()
    validated = validate_tier1(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[elfen] report files parsed: {n_reports} ({n_incomplete} not task_status=Complete)")
    print(f"[elfen] raw event rows written: {len(validated)}")
    print(f"[elfen] family distribution:\n{validated['family'].value_counts()}")
    print(f"[elfen] event_type distribution:\n{validated['event_type'].value_counts()}")
    print(f"[elfen] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
