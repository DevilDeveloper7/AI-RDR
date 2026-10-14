from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "1.0"

ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "ts", "@timestamp", "datetime", "event_time"),
    "run_id": ("run_id", "trace_id", "scenario_id", "execution_id", "sample_id"),
    "label": ("label", "class", "target", "category", "is_ransomware"),
    "event_type": (
        "event_type",
        "syscall",
        "syscall_name",
        "auditd.data.syscall",
        "data.audit.syscall",
        "event",
        "type",
        "name",
    ),
    "operation": (
        "operation",
        "op",
        "action",
        "event.action",
        "syscall",
        "auditd.data.syscall",
        "data.audit.syscall",
    ),
    "pid": ("pid", "process_id", "process.pid", "auditd.data.pid"),
    "ppid": ("ppid", "parent_pid", "process.parent.pid", "auditd.data.ppid"),
    "process_name": (
        "process_name",
        "process",
        "comm",
        "exe",
        "process.name",
        "auditd.data.comm",
    ),
    "path": ("path", "file", "filename", "file.path", "auditd.data.name"),
    "bytes": ("bytes", "size", "byte_count", "io_bytes"),
}

BENIGN_WORDS = {"0", "benign", "normal", "goodware", "clean", "false"}
RANSOMWARE_WORDS = {"1", "ransomware", "malicious", "malware", "attack", "true"}


def _lookup(row: Mapping[str, Any], field: str) -> Any:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for alias in ALIASES[field]:
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    return None


def _parse_timestamp(value: Any, fallback: float) -> float:
    if value in (None, ""):
        return fallback
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        try:
            number = float(text)
        except ValueError:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
    # Normalize common epoch units to seconds.
    if number > 1e17:
        return number / 1e9
    if number > 1e14:
        return number / 1e6
    if number > 1e11:
        return number / 1e3
    return number


def normalize_label(value: Any, source_path: Path | None = None) -> str:
    text = "" if value is None else str(value).strip().lower()
    if text in BENIGN_WORDS:
        return "benign"
    if text in RANSOMWARE_WORDS:
        return "ransomware"

    path_text = str(source_path or "").lower()
    if any(word in path_text for word in ("benign", "normal", "goodware", "clean")):
        return "benign"
    if any(word in path_text for word in ("ransom", "malware", "attack")):
        return "ransomware"
    return "unknown"


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    timestamp: float
    run_id: str
    label: str
    event_type: str
    operation: str
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    path: str | None = None
    bytes: int | None = None
    source: str = "unknown"
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_mapping(
        cls,
        row: Mapping[str, Any],
        *,
        source_path: Path | None = None,
        row_number: int = 0,
        run_id: str | None = None,
        label: str | None = None,
        source: str = "lifecycle",
    ) -> "NormalizedEvent":
        event_type = str(_lookup(row, "event_type") or "unknown").strip().lower()
        operation = str(_lookup(row, "operation") or event_type).strip().lower()
        resolved_run = str(
            _lookup(row, "run_id")
            or run_id
            or (source_path.stem if source_path else "unknown-run")
        )
        resolved_label = normalize_label(label or _lookup(row, "label"), source_path)

        return cls(
            timestamp=_parse_timestamp(_lookup(row, "timestamp"), float(row_number)),
            run_id=resolved_run,
            label=resolved_label,
            event_type=event_type,
            operation=operation,
            pid=_optional_int(_lookup(row, "pid")),
            ppid=_optional_int(_lookup(row, "ppid")),
            process_name=_string_or_none(_lookup(row, "process_name")),
            path=_string_or_none(_lookup(row, "path")),
            bytes=_optional_int(_lookup(row, "bytes")),
            source=source,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)
