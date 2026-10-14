from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import iter_normalized_runs
from .windowing import SlidingWindowConfig, WindowRecord, iter_run_windows

FEATURE_VERSION = "1.0"

READ_SYSCALLS = {"read", "readv", "pread64", "preadv", "recvfrom", "recvmsg"}
WRITE_SYSCALLS = {"write", "writev", "pwrite64", "pwritev", "sendto", "sendmsg"}
OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
CLOSE_SYSCALLS = {"close"}
RENAME_SYSCALLS = {"rename", "renameat", "renameat2"}
DELETE_SYSCALLS = {"unlink", "unlinkat", "rmdir"}
SYNC_SYSCALLS = {"fsync", "fdatasync", "sync", "syncfs"}
METADATA_SYSCALLS = {
    "stat",
    "fstat",
    "lstat",
    "newfstatat",
    "statx",
    "getdents",
    "getdents64",
    "access",
    "faccessat",
}
MEMORY_SYSCALLS = {"mmap", "mmap2", "mprotect", "madvise", "munmap", "brk"}
NETWORK_SYSCALLS = {
    "socket",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "sendmsg",
    "recvfrom",
    "recvmsg",
}
PROCESS_SYSCALLS = {"clone", "clone3", "fork", "vfork", "execve", "execveat"}


@dataclass(frozen=True, slots=True)
class FeatureGenerationConfig:
    window: SlidingWindowConfig
    max_windows_per_run: int = 200
    seed: int = 321

    def __post_init__(self) -> None:
        if self.max_windows_per_run < 1:
            raise ValueError("max_windows_per_run must be positive")


def extract_window_features(window: WindowRecord) -> dict[str, Any]:
    syscall_counts = Counter(event.event_type for event in window.events)
    pid_counts = Counter(event.pid for event in window.events if event.pid is not None)
    processes = {
        event.process_name for event in window.events if event.process_name is not None
    }
    total = window.event_count
    duration = max(window.end - window.start, 1e-9)

    def count(names: set[str]) -> int:
        return sum(syscall_counts[name] for name in names)

    read_count = count(READ_SYSCALLS)
    write_count = count(WRITE_SYSCALLS)
    open_count = count(OPEN_SYSCALLS)
    close_count = count(CLOSE_SYSCALLS)
    rename_count = count(RENAME_SYSCALLS)
    delete_count = count(DELETE_SYSCALLS)
    sync_count = count(SYNC_SYSCALLS)
    metadata_count = count(METADATA_SYSCALLS)
    memory_count = count(MEMORY_SYSCALLS)
    network_count = count(NETWORK_SYSCALLS)
    process_count = count(PROCESS_SYSCALLS)

    transitions = Counter(
        (left.event_type, right.event_type)
        for left, right in zip(window.events, window.events[1:])
    )
    entropy = 0.0
    for frequency in syscall_counts.values():
        probability = frequency / total
        entropy -= probability * math.log2(probability)

    row: dict[str, Any] = {
        "feature_version": FEATURE_VERSION,
        "window_id": window.window_id,
        "run_id": window.run_id,
        "label": window.label,
        "start": window.start,
        "end": window.end,
        "event_count": total,
        "event_rate": total / duration,
        "unique_syscalls": len(syscall_counts),
        "syscall_entropy": entropy,
        "unique_pids": len(pid_counts),
        "unique_processes": len(processes),
        "max_pid_share": max(pid_counts.values(), default=0) / total,
        "read_count": read_count,
        "write_count": write_count,
        "open_count": open_count,
        "close_count": close_count,
        "rename_count": rename_count,
        "delete_count": delete_count,
        "sync_count": sync_count,
        "metadata_count": metadata_count,
        "memory_count": memory_count,
        "network_count": network_count,
        "process_count": process_count,
        "read_ratio": read_count / total,
        "write_ratio": write_count / total,
        "open_ratio": open_count / total,
        "rename_delete_ratio": (rename_count + delete_count) / total,
        "sync_ratio": sync_count / total,
        "metadata_ratio": metadata_count / total,
        "memory_ratio": memory_count / total,
        "network_ratio": network_count / total,
        "read_bytes_requested": sum(
            event.bytes or 0
            for event in window.events
            if event.event_type in READ_SYSCALLS
        ),
        "write_bytes_requested": sum(
            event.bytes or 0
            for event in window.events
            if event.event_type in WRITE_SYSCALLS
        ),
        "open_to_read": transitions[("openat", "read")]
        + transitions[("open", "read")],
        "read_to_write": sum(
            frequency
            for (left, right), frequency in transitions.items()
            if left in READ_SYSCALLS and right in WRITE_SYSCALLS
        ),
        "write_to_sync": sum(
            frequency
            for (left, right), frequency in transitions.items()
            if left in WRITE_SYSCALLS and right in SYNC_SYSCALLS
        ),
    }
    return row


def generate_feature_file(
    input_path: Path,
    output_path: Path,
    config: FeatureGenerationConfig,
    *,
    source: str = "lifecycle",
    max_runs: int | None = None,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    label_counts: Counter[str] = Counter()
    run_counts: Counter[str] = Counter()
    generated_windows = 0
    retained_windows = 0

    try:
        with temporary.open("w", encoding="utf-8") as output:
            for run_index, (run_id, label, events) in enumerate(
                iter_normalized_runs(input_path, source=source)
            ):
                if max_runs is not None and run_index >= max_runs:
                    break
                if label not in {"benign", "ransomware"}:
                    continue
                rng = random.Random(_run_seed(run_id, config.seed))
                reservoir: list[dict[str, Any]] = []
                seen = 0
                for window in iter_run_windows(events, config.window):
                    row = extract_window_features(window)
                    if seen < config.max_windows_per_run:
                        reservoir.append(row)
                    else:
                        replacement = rng.randint(0, seen)
                        if replacement < config.max_windows_per_run:
                            reservoir[replacement] = row
                    seen += 1

                generated_windows += seen
                reservoir.sort(key=lambda row: (row["start"], row["window_id"]))
                for row in reservoir:
                    output.write(json.dumps(row, separators=(",", ":")) + "\n")
                retained_windows += len(reservoir)
                label_counts[label] += len(reservoir)
                run_counts[label] += 1
        temporary.replace(output_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    report = {
        "input": str(input_path),
        "output": str(output_path),
        "feature_version": FEATURE_VERSION,
        "runs": dict(run_counts),
        "generated_windows": generated_windows,
        "retained_windows": retained_windows,
        "retained_labels": dict(label_counts),
        "max_windows_per_run": config.max_windows_per_run,
        "sampling": "deterministic per-run reservoir sampling",
        "window_config": {
            "mode": config.window.mode,
            "size": config.window.size,
            "stride": config.window.stride,
            "min_events": config.window.min_events,
        },
        "max_runs": max_runs,
    }
    report_path = output_path.with_suffix(output_path.suffix + ".report.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def feature_names(row: dict[str, Any]) -> list[str]:
    metadata = {
        "feature_version",
        "window_id",
        "run_id",
        "label",
        "start",
        "end",
    }
    return [name for name in row if name not in metadata]


def _run_seed(run_id: str, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{run_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big")
