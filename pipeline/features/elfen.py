"""Feature module for ELFEN (Tier 1) — task 3.2.

Source: data/normalized/elfen_raw_events.parquet (34,687 rows, one row per ELFEN
sandbox syscall event — see data/normalized/SUMMARY.md for the full normalization
history, including the ProcOPS-duplicate and IceFire-family-skew findings).

entropy_score — RESOLVED, computed from real byte content, not a proxy or a null:
inspected ELFEN's `fileops` `write` syscall `args` string before assuming anything, and
found a literal `buffer: b'...'` fragment on every `write` event — this is Python's own
`repr()` of the bytes the ELFEN sandbox actually captured for that write call (truncated
by the sandbox well below the syscall's own declared `size`; e.g. a write with
`size: 512000` typically has only 40-250 bytes of `buffer` text). That's genuine, if
small and truncated, sampled byte content — real signal, not fabricated. Decoded back to
raw bytes via `pipeline.features.entropy.decode_bytes_repr` (an `ast.literal_eval` of the
repr fragment). Coverage is inherently sparse: only 314 `write` events exist in the
entire 34,687-row corpus (ELFEN's fileops mostly captures `open`/`read`/`rename`/`unlink`,
not `write`), of which 268 decode cleanly (46 fail — usually a stray unescaped quote/
backslash inside the sandbox's own capture that `ast.literal_eval` can't round-trip; these
are logged and left null, never coerced to a guessed value). Every window without a
decodable `write` event in it gets `entropy_score = null`, which is the large majority of
windows — documented here rather than silently masked by a window-level `n_events` count
that would look fine either way.

is_write/is_read/is_rename: ELFEN's own `_FILEOPS_EVENT_TYPE` mapping folds `open`,
`read`, `readlink`, `fcntl` all into the single `file_access` event_type, and `write`
plus `rename` both into `file_modify` — too coarse to derive write_read_ratio/rename_rate
from event_type alone, so these three flags are derived directly from `raw_fields.func`
instead: is_write := func=="write", is_read := func=="read" (not "open" — an open() call
is a path resolution, not a data read), is_rename := func=="rename".

Output: data/features/elfen_features.parquet, training_eligible=true throughout.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import polars as pl

from pipeline.features.entropy import entropy_from_repr
from pipeline.features.schema import validate_features
from pipeline.features.windowing import build_feature_windows

IN_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "elfen_raw_events.parquet"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "features" / "elfen_features.parquet"

SOURCE_DATASET = "linux_ransomware_elfen"
WINDOW_SEC = 30

_BUFFER_RE = re.compile(r"buffer:\s*b'(.*)'\s*\nsize:", re.S)


def _parse_row(raw_fields: str) -> dict:
    d = json.loads(raw_fields)
    func = d.get("func")
    is_write = func == "write"
    entropy_bits = None
    if is_write:
        m = _BUFFER_RE.search(d.get("args") or "")
        if m:
            entropy_bits = entropy_from_repr(m.group(1))
    return {
        "is_write": is_write,
        "is_read": func == "read",
        "is_rename": func == "rename",
        "entropy_bits": entropy_bits,
    }


def load() -> tuple[pl.DataFrame, dict]:
    df = pl.read_parquet(IN_PATH)
    n_in = df.height

    parsed = pl.DataFrame([_parse_row(rf) for rf in df["raw_fields"].to_list()])
    df = pl.concat([df, parsed], how="horizontal_extend")

    n_write = int(df["is_write"].sum())
    n_write_with_entropy = int(df["entropy_bits"].is_not_null().sum())

    df = df.with_columns(
        [
            (
                pl.col("timestamp")
                .str.to_datetime(format="%Y-%m-%dT%H:%M:%S%.f%:z", strict=False)
                .dt.epoch(time_unit="ms")
                / 1000.0
            ).alias("t_seconds"),
            pl.col("file_path")
            .str.to_lowercase()
            .str.extract(r"(\.[a-z0-9]+)$", 1)
            .alias("extension"),
        ]
    )
    n_null_ts = int(df["t_seconds"].is_null().sum())
    if n_null_ts:
        df = df.filter(pl.col("t_seconds").is_not_null())

    windows = build_feature_windows(
        df, window_sec=WINDOW_SEC, source_dataset=SOURCE_DATASET, training_eligible=True
    )
    stats = {
        "rows_in": n_in,
        "rows_dropped_unparseable_timestamp": n_null_ts,
        "windows_out": windows.height,
        "write_events": n_write,
        "write_events_with_entropy": n_write_with_entropy,
    }
    return windows, stats


def main() -> None:
    windows, stats = load()
    validated = validate_features(windows.to_pandas())
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[elfen-features] {stats}")
    print(f"[elfen-features] windows written: {len(validated)}")
    print(
        f"[elfen-features] entropy_score non-null windows: "
        f"{validated['entropy_score'].notna().sum()} / {len(validated)}"
    )
    print(f"[elfen-features] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
