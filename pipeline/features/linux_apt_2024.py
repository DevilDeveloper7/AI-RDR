"""Feature module for Linux-APT Dataset 2024 (Tier 1) — task 3.2.

Source: data/normalized/linux_apt_2024_raw_events.parquet (122,563 rows — mostly
built-in Wazuh alert noise, not ransomware; see data/normalized/SUMMARY.md).
training_eligible=false throughout — validation-only per the 2026-09-22 label-scope
decision in planning/task-breakdown.md §3.3 (this is APT/generic-intrusion data, never
merged into the ransomware-positive training set).

entropy_score — RESOLVED as a documented null, no proxy applied: inspected every
syscheck-derived row's `raw_fields` for content/size signal. Found `size_before`/
`size_after` (integers) and `md5_before`/`sha1_before`/`sha256_before`/`*_after` (hashes)
on FIM rows, but never literal byte content — a size delta alone says nothing about byte
distribution, and a cryptographic hash is one-way by construction, so neither is usable
toward a real entropy value. The tracker's suggested "renamed to a known ransomware
extension" proxy was deliberately NOT applied here: this dataset is APT/generic-intrusion
telemetry, not ransomware, so flagging on ransomware extensions would be a category
error (it would either never fire, or fire on a coincidental extension match with no
ransomware behind it) rather than a genuine substitute signal. `encryption_rate` is
therefore also null throughout (it's derived from entropy_score in the schema and there's
nothing to derive it from).

Two more things found while building the features that are worth being honest about,
neither a bug in this module:
- `process_id` is null for every single row (already known from normalization — the
  exported CSV columns never included a PID field at all), so this dataset windows as
  one process_id=null group per sample_id (= per source CSV file), spanning that CSV's
  full time range cut into 30s windows.
- `_source.syscheck.event` only ever takes the values {"added", "modified", "deleted"}
  in this download (checked all 122,563 rows) — there is no "renamed" variant anywhere,
  so `rename_rate` is genuinely 0.0 for every window, not a null/gap. There is also no
  raw "read" telemetry captured by this source at all (Wazuh FIM reports file-integrity
  add/modify/delete events, not read syscalls) — `is_read` is therefore always False and
  `write_read_ratio` falls back to reporting the raw write count per
  pipeline/features/windowing.py's documented zero-read fallback.

Output: data/features/linux_apt_2024_features.parquet, training_eligible=false throughout.
"""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from pipeline.features.schema import validate_features
from pipeline.features.windowing import build_feature_windows

IN_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "normalized" / "linux_apt_2024_raw_events.parquet"
)
OUT_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "features" / "linux_apt_2024_features.parquet"
)

SOURCE_DATASET = "linux_apt_2024"
WINDOW_SEC = 30


def _parse_row(raw_fields: str) -> dict:
    d = json.loads(raw_fields)
    syscheck_event = d.get("_source.syscheck.event")
    return {"is_write": syscheck_event == "modified"}


def load() -> tuple[pl.DataFrame, dict]:
    df = pl.read_parquet(IN_PATH)
    n_in = df.height

    parsed = pl.DataFrame([_parse_row(rf) for rf in df["raw_fields"].to_list()])
    df = pl.concat([df, parsed], how="horizontal_extend")
    df = df.with_columns(
        [
            pl.lit(False).alias("is_read"),
            pl.lit(False).alias("is_rename"),
            pl.lit(None, dtype=pl.Float64).alias("entropy_bits"),
        ]
    )

    df = df.with_columns(
        [
            (
                pl.col("timestamp")
                .str.to_datetime(format="%b %d, %Y @ %H:%M:%S%.f", strict=False)
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
        df, window_sec=WINDOW_SEC, source_dataset=SOURCE_DATASET, training_eligible=False
    )
    stats = {
        "rows_in": n_in,
        "rows_dropped_unparseable_timestamp": n_null_ts,
        "windows_out": windows.height,
        "write_events (syscheck modified)": int(df["is_write"].sum()),
    }
    return windows, stats


def main() -> None:
    windows, stats = load()
    validated = validate_features(windows.to_pandas())
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[linux_apt_2024-features] {stats}")
    print(f"[linux_apt_2024-features] windows written: {len(validated)}")
    print(f"[linux_apt_2024-features] entropy_score non-null windows: {validated['entropy_score'].notna().sum()}")
    print(f"[linux_apt_2024-features] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
