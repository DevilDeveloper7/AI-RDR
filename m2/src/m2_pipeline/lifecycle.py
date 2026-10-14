from __future__ import annotations

import io
import re
import tarfile
from collections.abc import Iterator
from pathlib import Path

from .schema import NormalizedEvent

TRACE_LINE = re.compile(
    r"^\s*(?P<process>.+)-(?P<pid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+"
    r"(?:[A-Za-z.]+\s+)?"
    r"(?P<timestamp>\d+(?:\.\d+)?):\s+"
    r"sys_enter_(?P<syscall>[A-Za-z0-9_]+):\s*(?P<args>.*)$"
)
COUNT_ARG = re.compile(r"(?:^|,\s*)count:\s*(0x[0-9a-fA-F]+|\d+)")


def is_lifecycle_archive(path: Path) -> bool:
    name = path.name.lower()
    if not name.endswith(".tar.gz"):
        return False
    if "ransomware_data" in str(path):
        return name == "ftrace_results.tar.gz"
    if "benignware_data" in str(path):
        return True
    return False


def iter_lifecycle_archive(
    archive: Path,
) -> Iterator[tuple[str, str, Iterator[NormalizedEvent]]]:
    label = "ransomware" if "ransomware_data" in str(archive) else "benign"
    with tarfile.open(archive, mode="r:gz") as bundle:
        for member in bundle:
            if not member.isfile() or not _include_member(member.name, label):
                continue
            raw = bundle.extractfile(member)
            if raw is None:
                continue
            run_id = f"{_archive_stem(archive)}__{member.name.replace('/', '__')}"
            text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
            yield run_id, label, _iter_trace_lines(
                text,
                run_id=run_id,
                label=label,
            )


def parse_trace_line(
    line: str,
    *,
    run_id: str,
    label: str,
) -> NormalizedEvent | None:
    match = TRACE_LINE.match(line)
    if not match:
        return None
    syscall = match.group("syscall").lower()
    count_match = COUNT_ARG.search(match.group("args"))
    byte_count = int(count_match.group(1), 0) if count_match else None
    return NormalizedEvent(
        timestamp=float(match.group("timestamp")),
        run_id=run_id,
        label=label,
        event_type=syscall,
        operation=syscall,
        pid=int(match.group("pid")),
        process_name=match.group("process").strip(),
        bytes=byte_count,
        source="lifecycle-ftrace",
    )


def _iter_trace_lines(
    lines: Iterator[str],
    *,
    run_id: str,
    label: str,
) -> Iterator[NormalizedEvent]:
    for line in lines:
        event = parse_trace_line(line, run_id=run_id, label=label)
        if event is not None:
            yield event


def _include_member(name: str, label: str) -> bool:
    lowered = name.lower()
    if ".ds_store" in lowered:
        return False
    if label == "ransomware":
        # The approved M2 path detects encryption behaviour. Recon/exfiltration
        # are deferred and would turn common admin/network activity positive.
        return "/out_exec_parsed/" in lowered
    return "syscall" in lowered


def _archive_stem(path: Path) -> str:
    name = path.name
    return name[:-7] if name.lower().endswith(".tar.gz") else path.stem
