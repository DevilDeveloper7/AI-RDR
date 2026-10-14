"""Feature module for EN2025 (Tier 1) — task 3.2.

Source: data/normalized/en2025_raw_events.parquet (25,259,931 rows — CAPE sandbox API
call traces on Windows PE32 samples, 3,918,998 benign / 21,340,933 ransomware rows; see
data/normalized/SUMMARY.md for the full normalization history). training_eligible=true
throughout — **both** benign and ransomware rows, per the label-scope decision (this is
the only Tier-1 source with a genuine benign class).

entropy_score — RESOLVED, computed from real byte content, not a proxy or a null:
inspected `raw_fields.arguments` on `NtWriteFile` calls (the tracker doc's own
suggestion) before assuming anything, and found a `Buffer` argument holding literal
escaped byte text (e.g. `"\\xff\\xfe"`, or printable text mixed with `\\x00` for
UTF-16LE strings) — CAPE's own per-call capture, independently truncated from the call's
real `Length` (verified: many `Length: 512000`-scale declared sizes have only a
tens-to-hundreds-of-bytes captured `Buffer`). Genuine sampled byte content, decoded via
the same `ast.literal_eval`-based `decode_bytes_repr` used for ELFEN. Full-dataset run:
775,395 `NtWriteFile` rows out of 25,259,931 (~3%) are entropy-eligible, of which 746,868
(96.3%) decode cleanly (the rest fail on a stray backslash/quote edge case in CAPE's own
capture and are left null, logged, never guessed) — 3,114 of the resulting 16,454 windows
end up with a non-null `entropy_score`; every other window gets `entropy_score = null`.

is_write/is_read/is_rename: EN2025's own `_API_EVENT_TYPE` mapping folds many distinct
Windows APIs into the same `file_access`/`file_modify` event_type buckets (e.g.
`file_access` covers `NtOpenFile`, `NtReadFile`, `NtQueryAttributesFile`, ... all at
once) — too coarse for write_read_ratio/rename_rate, so these three flags are derived
directly from `raw_fields.api` instead: is_write := api=="NtWriteFile", is_read :=
api=="NtReadFile", is_rename := api in {"MoveFileWithProgressW",
"MoveFileWithProgressTransactedW"} (deliberately excluding `CopyFileW`/`CopyFileA` — a
copy duplicates a file, it doesn't rename one, even though the Tier-1 event_type mapping
lumps both under `file_modify`).

**Scale**: 25.26M rows is the largest source. `is_write`/`is_read`/`is_rename` are
detected with vectorized `str.contains` over the full `raw_fields` column (fast — no
per-row JSON parsing at that scale). Entropy, which genuinely needs to parse each
candidate row's `arguments` list, is computed only on the ~775K rows already known to be
`NtWriteFile` calls (filtered first via the same vectorized flag, then joined back on a
row index) rather than a 25M-row Python loop.

**A real bug caught before trusting any of this**: the first version matched the
compact `"api":"NtWriteFile"` (no space) — the pattern that works for the Lifecycle
dataset, whose `raw_fields` is serialized with Polars' `struct.json_encode()` (always
compact). EN2025's loader instead serializes each row's `raw_fields` dict with plain
`json.dumps(..., default=str)`, whose *default* separators include a space after every
colon (`"api": "NtWriteFile"`). The no-space pattern matched zero rows and silently
produced `write_events: 0` on the first run — caught by that exact sanity-check number
looking wrong (775,461 `NtWriteFile` rows are known to exist from the manual inspection
in this docstring), not by inspection alone. Fixed by matching the actual observed
spacing (verified once more directly against a raw string, not assumed) rather than
copying the Lifecycle module's pattern.

Output: data/features/en2025_features.parquet, training_eligible=true throughout (both
benign and ransomware rows).
"""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from pipeline.features.entropy import entropy_from_repr
from pipeline.features.schema import validate_features
from pipeline.features.windowing import build_feature_windows

IN_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "en2025_raw_events.parquet"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "features" / "en2025_features.parquet"

SOURCE_DATASET = "en2025"
WINDOW_SEC = 30


def _write_entropy(raw_fields: str) -> float | None:
    d = json.loads(raw_fields)
    if d.get("api") != "NtWriteFile":
        return None
    for a in d.get("arguments") or []:
        if isinstance(a, dict) and a.get("name") == "Buffer":
            return entropy_from_repr(a.get("value"))
    return None


def load() -> tuple[pl.DataFrame, dict]:
    df = pl.read_parquet(IN_PATH)
    n_in = df.height

    is_rel = pl.col("timestamp").str.starts_with("REL:")
    rel_seconds = pl.col("timestamp").str.slice(4).cast(pl.Float64, strict=False)
    offset_seconds = (
        pl.col("timestamp")
        .str.to_datetime(format="%Y-%m-%dT%H:%M:%S%.f%:z", strict=False)
        .dt.epoch(time_unit="ms")
        / 1000.0
    )
    naive_seconds = (
        pl.col("timestamp")
        .str.to_datetime(format="%Y-%m-%dT%H:%M:%S%.f", strict=False)
        .dt.epoch(time_unit="ms")
        / 1000.0
    )

    df = df.with_columns(
        [
            pl.when(is_rel)
            .then(rel_seconds)
            .otherwise(pl.coalesce([offset_seconds, naive_seconds]))
            .alias("t_seconds"),
            pl.col("raw_fields").str.contains('"api": "NtWriteFile"').alias("is_write"),
            pl.col("raw_fields").str.contains('"api": "NtReadFile"').alias("is_read"),
            pl.col("raw_fields")
            .str.contains('"api": "(MoveFileWithProgressW|MoveFileWithProgressTransactedW)"')
            .alias("is_rename"),
            pl.col("file_path")
            .str.to_lowercase()
            .str.extract(r"(\.[a-z0-9]+)$", 1)
            .alias("extension"),
        ]
    )
    n_null_ts = int(df.select(pl.col("t_seconds").is_null().sum()).item())
    if n_null_ts:
        df = df.filter(pl.col("t_seconds").is_not_null())

    # entropy: only parse the ~3% of rows already known to be NtWriteFile calls,
    # computed on the filtered subset and joined back — see module docstring.
    df = df.with_row_index("_row_id")
    write_subset = df.filter(pl.col("is_write")).select(["_row_id", "raw_fields"])
    n_write = write_subset.height
    entropy_values = [_write_entropy(rf) for rf in write_subset["raw_fields"].to_list()]
    n_write_with_entropy = sum(1 for v in entropy_values if v is not None)
    write_subset = write_subset.with_columns(
        pl.Series("entropy_bits", entropy_values, dtype=pl.Float64)
    ).select(["_row_id", "entropy_bits"])
    df = df.join(write_subset, on="_row_id", how="left").drop("_row_id")

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

    print(f"[en2025-features] {stats}")
    print(f"[en2025-features] windows written: {len(validated)}")
    print(f"[en2025-features] label distribution:\n{validated['label'].value_counts()}")
    print(f"[en2025-features] entropy_score non-null windows: {validated['entropy_score'].notna().sum()}")
    print(f"[en2025-features] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
