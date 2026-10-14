from __future__ import annotations

import csv
import gzip
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, TextIO

from .schema import NormalizedEvent

SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}


def discover_trace_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and (
            _logical_suffix(path) in SUPPORTED_SUFFIXES
            or path.name.lower().endswith(".tar.gz")
        )
    ]
    return sorted(files)


def iter_normalized_runs(
    root: Path,
    *,
    source: str = "lifecycle",
) -> Iterator[tuple[str, str, Iterator[NormalizedEvent]]]:
    from .lifecycle import is_lifecycle_archive, iter_lifecycle_archive

    for path in discover_trace_files(root):
        if path.name.lower().endswith(".tar.gz"):
            if is_lifecycle_archive(path):
                yield from iter_lifecycle_archive(path)
            continue

        grouped: dict[str, list[NormalizedEvent]] = {}
        for event in iter_normalized_file(path, root=root, source=source):
            grouped.setdefault(event.run_id, []).append(event)
        for run_id, events in grouped.items():
            label = events[0].label if events else "unknown"
            yield run_id, label, iter(events)


def infer_run_id(path: Path, root: Path) -> str:
    if root.is_file():
        root = root.parent
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path.name
    text = str(relative)
    if text.endswith(".gz"):
        text = text[:-3]
    return str(Path(text).with_suffix("")).replace("/", "__")


def iter_normalized_file(
    path: Path,
    *,
    root: Path | None = None,
    source: str = "lifecycle",
) -> Iterator[NormalizedEvent]:
    run_id = infer_run_id(path, root or path.parent)
    for row_number, row in enumerate(iter_rows(path)):
        yield NormalizedEvent.from_mapping(
            row,
            source_path=path,
            row_number=row_number,
            run_id=run_id,
            source=source,
        )


def iter_rows(path: Path) -> Iterator[Mapping[str, Any]]:
    suffix = _logical_suffix(path)
    with _open_text(path) as handle:
        if suffix == ".csv":
            yield from csv.DictReader(handle)
        elif suffix in {".jsonl", ".ndjson"}:
            for line in handle:
                if line.strip():
                    value = json.loads(line)
                    if isinstance(value, Mapping):
                        yield flatten_mapping(value)
        elif suffix == ".json":
            value = json.load(handle)
            yield from _rows_from_json(value)
        else:
            raise ValueError(f"Unsupported trace format: {path}")


def flatten_mapping(
    value: Mapping[str, Any],
    *,
    prefix: str = "",
) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, child in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, Mapping):
            flattened.update(flatten_mapping(child, prefix=name))
        else:
            flattened[name] = child
            # Keep leaf names too: Wazuh/IRDP wrappers vary between integrations.
            flattened.setdefault(str(key), child)
    return flattened


def _rows_from_json(value: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, list):
        for row in value:
            if isinstance(row, Mapping):
                yield flatten_mapping(row)
        return
    if not isinstance(value, Mapping):
        return
    for key in ("events", "records", "results", "data", "items"):
        rows = value.get(key)
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, Mapping):
                    yield flatten_mapping(row)
            return
    yield flatten_mapping(value)


def _open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return path.open(mode="r", encoding="utf-8", errors="replace", newline="")


def _logical_suffix(path: Path) -> str:
    if path.suffix.lower() == ".gz":
        return Path(path.stem).suffix.lower()
    return path.suffix.lower()
