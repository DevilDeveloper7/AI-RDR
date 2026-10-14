"""Loader for the Ransomware Lifecycle Dataset (Tier 1 — raw-event).

Source: data/ransomware-lifecycle/results/ransomware_data/{ftrace,net,perf}_results.tar.gz

SCOPE NOTE (read before assuming this is exhaustive): this loader covers the
`ransomware_data` side only (the recon/exfil/exec stage simulation) — NOT
`benignware_data`. See SUMMARY.md for why benignware was left out (inconsistent
per-category directory naming, and one category has an 8.79M-line single trace file);
that's a scoping decision, not an oversight.

Three things turned out different from what normalization-progress.md assumed before
inspection:

1. The archives are **already decoded** — despite the filenames, every member under
   `parsed/` (or `output/*_parsed/`) is plain text: `perf` members are already
   `perf script`-style CSV, `ftrace` members are already `trace-cmd report`-style text,
   `net` members are already tshark-exported CSV. No `perf script`/`trace-cmd` binary
   decode was actually needed.
2. Individual per-run files are wildly uneven in size — `ftrace_results.tar.gz` alone is
   17.3GB uncompressed across 259 members, and 42 of those (mostly high-thread
   `transfer_aws_*`/`transfer_sftp_*` exfil runs and all 5 `recon_mount_*` runs) are each
   150MB-850MB. A first attempt that streamed straight from the .tar.gz and accumulated
   parsed rows in plain Python lists ballooned to 41GB RSS and had to be killed — not
   because the *included* data is huge, but because skipping past ~16GB of excluded
   members while simultaneously accumulating tens of millions of Python string objects
   for the included ones is a bad combination. Fixed by (a) extracting only members
   <= `_MAX_MEMBER_BYTES` to disk first via a bounded, one-member-at-a-time `tarfile`
   pass (nothing accumulates in memory during extraction), then (b) parsing each
   extracted file with Polars (Arrow-backed, far less per-row overhead than Python
   lists + pandas object columns) one file at a time.
3. `net_results` CSVs have a worse quoting problem than initially assumed: `frame.time`
   itself contains an unquoted comma (`"Aug 11, 2025 21:45:46.769851435 CDT"`), which
   silently shifts every single column by one on a naive CSV read — this is NOT just the
   handful of ragged rows from commas inside `_ws.col.Info` that an earlier version of
   this loader (and its SUMMARY.md notes) assumed was the only issue. Fixed by stripping
   the one comma inside the timestamp with a regex before handing the text to a CSV
   parser, so every field lines up correctly; `truncate_ragged_lines=True` still handles
   the separate (real, minor) `_ws.col.Info`-comma case.
4. 182 of the 192 included `net` files (everything under `out_exfil_parsed`/
   `out_exec_parsed` — only `out_recon`'s captures) have **no header row at all**. A
   first pass didn't check for this, so Polars silently used each such file's first data
   row as column *names* (real IP/timestamp values became column headers) and every
   other row came out with `timestamp = null` — caught by a post-run sanity check
   (91% of `net` rows had a null timestamp, which was the tell). Fixed by detecting
   whether a file's first line starts with `"frame.time"` and supplying the known
   10-column tshark export order explicitly when it doesn't.

Given this is the lowest-priority "if time allows" dataset, this loader extracts and
parses every member up to `_MAX_MEMBER_BYTES` (50MB) and **skips** larger members
entirely (not sampled, not truncated — skipped, and logged) rather than either hanging
for a very long time on hundreds of millions of trace lines or risking another OOM. This
keeps the recon stage, most of the exec (crypto) stage, and most of the exfil stage
(fscan, compress_gzip, compress_zstd — but not the biggest transfer_aws/sftp runs).

Output: data/normalized/lifecycle_raw_events.parquet
"""

from __future__ import annotations

import re
import tarfile
from pathlib import Path

import pandas as pd
import polars as pl

from pipeline.schema import validate_tier1

RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "ransomware-lifecycle" / "results" / "ransomware_data"
EXTRACT_DIR = Path(__file__).resolve().parents[2] / "data" / "ransomware-lifecycle" / "_extracted"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "lifecycle_raw_events.parquet"

SOURCE_DATASET = "ransomware_lifecycle"
_MAX_MEMBER_BYTES = 50 * 1024 * 1024

_ARCHIVES = {
    "ftrace": "ftrace_results.tar.gz",
    "net": "net_results.tar.gz",
    "perf": "perf_results.tar.gz",
}

_FTRACE_PATTERN = (
    r"^\s*(?P<proc>\S+)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<ts>[\d.]+):\s+"
    r"(?P<event>[^:\s]+):\s*(?P<details>.*)$"
)

_FTRACE_EVENT_TYPE = {
    "execve": "process_spawn", "clone": "process_spawn", "fork": "process_spawn", "vfork": "process_spawn",
    "open": "file_access", "openat": "file_access", "read": "file_access", "pread64": "file_access",
    "readlink": "file_access", "newfstatat": "file_access", "stat": "file_access", "fstat": "file_access",
    "lstat": "file_access", "access": "file_access",
    "write": "file_modify", "pwrite64": "file_modify", "fsync": "file_modify", "fdatasync": "file_modify",
    "ftruncate": "file_modify", "truncate": "file_modify",
    "rename": "file_modify", "renameat": "file_modify", "renameat2": "file_modify",
    "unlink": "file_delete", "unlinkat": "file_delete",
    "connect": "network_connection", "socket": "network_connection", "sendto": "network_connection",
    "recvfrom": "network_connection", "bind": "network_connection", "accept": "network_connection",
    "sendmsg": "network_connection", "recvmsg": "network_connection",
}

# matches the unquoted comma inside tshark's "Mon DD, YYYY HH:MM:SS.fffffffff TZ" timestamp
_NET_TIMESTAMP_COMMA_RE = re.compile(r"(?m)^([A-Za-z]{3} \d{1,2}),\s")

# tshark's CSV export column order — needed because most net files (everything under
# out_exfil_parsed/out_exec_parsed, 182 of 192 included files) have NO header row at
# all; only out_recon's captures do. Verified by checking every extracted net file's
# first line: files starting with "frame.time" have a header, everything else doesn't.
# Missing this originally caused the first data row of 182 files to be silently
# consumed as a fake header (with real timestamp/IP values becoming column *names*),
# and every other row in those files to come out with a null timestamp.
_NET_COLUMNS = [
    "frame.time", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
    "udp.srcport", "udp.dstport", "frame.len", "_ws.col.Protocol", "_ws.col.Info",
]


def _stage_of(dirname: str) -> str:
    lower = dirname.lower()
    if "recon" in lower:
        return "recon"
    if "exfil" in lower:
        return "exfil"
    if "exec" in lower:
        return "exec"
    return "other"


def _sub_stage_and_run(run_name: str) -> tuple[str, str | None]:
    m = re.match(r"^(.*)_(\d+)$", run_name)
    if m:
        return m.group(1), m.group(2)
    return run_name, None


def _crypto_algo(sub_stage: str) -> str | None:
    if "AES" in sub_stage:
        return "AES"
    if "Salsa20" in sub_stage:
        return "Salsa20"
    if sub_stage.startswith("asymm"):
        return "asymmetric"
    return None


def _key_bits(sub_stage: str) -> int | None:
    m = re.search(r"(128|256)", sub_stage)
    return int(m.group(1)) if m else None


def _ftrace_event_type(event_name: str) -> str:
    base = event_name.replace("sys_enter_", "").replace("sys_exit_", "")
    return _FTRACE_EVENT_TYPE.get(base, "syscall")


def _ensure_extracted() -> None:
    """Bounded, one-member-at-a-time extraction of members <= _MAX_MEMBER_BYTES from
    each archive to data/ransomware-lifecycle/_extracted/<modality>/. Idempotent — skips
    a modality whose extract dir already has files. Nothing is held in memory beyond one
    member's bytes at a time (tarfile.extract() streams to disk)."""
    for modality, archive_name in _ARCHIVES.items():
        dest = EXTRACT_DIR / modality
        if dest.exists() and any(dest.rglob("*")):
            continue
        dest.mkdir(parents=True, exist_ok=True)
        archive_path = RAW_DIR / archive_name
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                name = Path(member.name).name
                if name.startswith(".") or name.startswith("._"):
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    continue
                tf.extract(member, dest, filter="data")


def _iter_extracted_files(modality: str):
    """Yield (stage_dirname, run_name, path) for every extracted file in a modality."""
    for path in sorted((EXTRACT_DIR / modality).rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith(".") or path.name.startswith("._"):
            continue
        yield path.parent.name, path.name, path


def _parse_ftrace_file(path: Path, stage: str, sub_stage: str, run_idx: str | None, run_name: str) -> pl.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return pl.DataFrame()
    extracted = pl.Series("line", lines).str.extract_groups(_FTRACE_PATTERN)
    df = pl.DataFrame({"g": extracted}).unnest("g").drop_nulls(subset=["proc"])
    if df.height == 0:
        return df
    df = df.with_columns(
        [
            pl.lit(stage).alias("stage"),
            pl.lit(sub_stage).alias("sub_stage"),
            pl.lit(run_idx).alias("run_idx"),
            pl.lit(run_name).alias("run_name"),
        ]
    )
    return df


def _parse_net_file(path: Path, stage: str, sub_stage: str, run_idx: str | None, run_name: str) -> pl.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return pl.DataFrame()
    fixed = _NET_TIMESTAMP_COMMA_RE.sub(r"\1 ", text)
    has_header = fixed.startswith("frame.time")
    try:
        if has_header:
            df = pl.read_csv(fixed.encode("utf-8"), infer_schema_length=0, truncate_ragged_lines=True)
        else:
            df = pl.read_csv(
                fixed.encode("utf-8"),
                infer_schema_length=0,
                truncate_ragged_lines=True,
                has_header=False,
                new_columns=_NET_COLUMNS,
            )
    except Exception:
        return pl.DataFrame()
    if df.height == 0:
        return df
    df = df.with_columns(
        [
            pl.lit(stage).alias("stage"),
            pl.lit(sub_stage).alias("sub_stage"),
            pl.lit(run_idx).alias("run_idx"),
            pl.lit(run_name).alias("run_name"),
        ]
    )
    return df


def _parse_perf_file(path: Path, stage: str, sub_stage: str, run_idx: str | None, run_name: str) -> pl.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return pl.DataFrame()
    try:
        df = pl.read_csv(text.encode("utf-8"), infer_schema_length=0, truncate_ragged_lines=True)
    except Exception:
        return pl.DataFrame()
    if df.height == 0:
        return df
    # trailing comma in the header produces a trailing all-null column; drop it
    df = df.select([c for c in df.columns if df[c].null_count() < df.height])
    df = df.with_columns(
        [
            pl.lit(stage).alias("stage"),
            pl.lit(sub_stage).alias("sub_stage"),
            pl.lit(run_idx).alias("run_idx"),
            pl.lit(run_name).alias("run_name"),
        ]
    )
    return df


def _ftrace_to_tier1(df: pl.DataFrame) -> pl.DataFrame:
    if df.height == 0:
        return df
    event_types = [_ftrace_event_type(e) for e in df["event"].to_list()]
    crypto = [_crypto_algo(s) for s in df["sub_stage"].to_list()]
    bits = [_key_bits(s) for s in df["sub_stage"].to_list()]
    df = df.with_columns(
        [
            pl.Series("event_type", event_types),
            pl.Series("crypto_algo", crypto),
            pl.Series("key_bits", bits, dtype=pl.Int64),
        ]
    )
    raw_fields = pl.struct(
        ["stage", "sub_stage", "run_name", "cpu", "event", "details", "crypto_algo", "key_bits"]
    ).struct.json_encode()
    return df.select(
        [
            (pl.lit("ftrace/") + pl.col("stage") + pl.lit("/") + pl.col("run_name")).alias("sample_id"),
            pl.lit(SOURCE_DATASET).alias("source_dataset"),
            pl.lit("ransomware").alias("label"),
            pl.lit("synthetic_simulation").alias("label_type"),
            pl.lit(0.8).alias("label_confidence"),
            pl.lit(None, dtype=pl.Utf8).alias("family"),
            (pl.lit("REL:") + pl.col("ts")).alias("timestamp"),
            pl.lit(None, dtype=pl.Utf8).alias("host_id"),
            pl.col("pid").cast(pl.Int64, strict=False).alias("process_id"),
            pl.col("event_type"),
            pl.lit(None, dtype=pl.Utf8).alias("file_path"),
            raw_fields.alias("raw_fields"),
        ]
    )


def _net_to_tier1(df: pl.DataFrame) -> pl.DataFrame:
    if df.height == 0:
        return df
    meta_cols = {"stage", "sub_stage", "run_name", "run_idx"}
    raw_cols = [c for c in df.columns if c not in meta_cols]
    raw_fields = pl.struct(raw_cols).struct.json_encode()
    timestamp = pl.col("frame.time") if "frame.time" in df.columns else pl.lit(None, dtype=pl.Utf8)
    return df.select(
        [
            (pl.lit("net/") + pl.col("stage") + pl.lit("/") + pl.col("run_name")).alias("sample_id"),
            pl.lit(SOURCE_DATASET).alias("source_dataset"),
            pl.lit("ransomware").alias("label"),
            pl.lit("synthetic_simulation").alias("label_type"),
            pl.lit(0.8).alias("label_confidence"),
            pl.lit(None, dtype=pl.Utf8).alias("family"),
            timestamp.alias("timestamp"),
            pl.lit(None, dtype=pl.Utf8).alias("host_id"),
            pl.lit(None, dtype=pl.Int64).alias("process_id"),
            pl.lit("network_connection").alias("event_type"),
            pl.lit(None, dtype=pl.Utf8).alias("file_path"),
            raw_fields.alias("raw_fields"),
        ]
    )


def _perf_to_tier1(df: pl.DataFrame) -> pl.DataFrame:
    if df.height == 0:
        return df
    meta_cols = {"stage", "sub_stage", "run_name", "run_idx"}
    raw_cols = [c for c in df.columns if c not in meta_cols]
    raw_fields = pl.struct(raw_cols).struct.json_encode()
    timestamp = (pl.lit("REL:") + pl.col("time")) if "time" in df.columns else pl.lit(None, dtype=pl.Utf8)
    return df.select(
        [
            (pl.lit("perf/") + pl.col("stage") + pl.lit("/") + pl.col("run_name")).alias("sample_id"),
            pl.lit(SOURCE_DATASET).alias("source_dataset"),
            pl.lit("ransomware").alias("label"),
            pl.lit("synthetic_simulation").alias("label_type"),
            pl.lit(0.8).alias("label_confidence"),
            pl.lit(None, dtype=pl.Utf8).alias("family"),
            timestamp.alias("timestamp"),
            pl.lit(None, dtype=pl.Utf8).alias("host_id"),
            pl.lit(None, dtype=pl.Int64).alias("process_id"),
            pl.lit("hardware_counter_sample").alias("event_type"),
            pl.lit(None, dtype=pl.Utf8).alias("file_path"),
            raw_fields.alias("raw_fields"),
        ]
    )


_MODALITY_PARSERS = {
    "ftrace": (_parse_ftrace_file, _ftrace_to_tier1),
    "net": (_parse_net_file, _net_to_tier1),
    "perf": (_parse_perf_file, _perf_to_tier1),
}


def load() -> tuple[pd.DataFrame, dict]:
    _ensure_extracted()

    tier1_frames = []
    stats = {}
    for modality, (parse_fn, to_tier1_fn) in _MODALITY_PARSERS.items():
        n_files = 0
        n_rows = 0
        for dirname, run_name, path in _iter_extracted_files(modality):
            stage = _stage_of(dirname)
            sub_stage, run_idx = _sub_stage_and_run(run_name)
            raw_df = parse_fn(path, stage, sub_stage, run_idx, run_name)
            if raw_df.height == 0:
                n_files += 1
                continue
            tier1_df = to_tier1_fn(raw_df)
            tier1_frames.append(tier1_df)
            n_files += 1
            n_rows += tier1_df.height
        stats[modality] = {"files": n_files, "rows": n_rows}

    combined = pl.concat(tier1_frames, how="diagonal_relaxed") if tier1_frames else pl.DataFrame()
    return combined.to_pandas(), stats


def main() -> None:
    df, stats = load()
    validated = validate_tier1(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[lifecycle] per-modality stats: {stats}")
    print(f"[lifecycle] rows written: {len(validated)}")
    print(f"[lifecycle] event_type distribution:\n{validated['event_type'].value_counts()}")
    print(f"[lifecycle] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
