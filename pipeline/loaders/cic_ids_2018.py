"""Loader for CIC-IDS-2018 (Tier 2 — feature passthrough).

Source: data/cic-ids-2018/ — 10 CICFlowMeter CSVs. Uses Polars, not pandas, per
task-breakdown.md 3.1 (the Tuesday file alone is 3.8GB).

Known quirks in this dataset (verified by inspection, not assumed) that this loader
works around:
  - The Tuesday file has 4 extra leading columns (Flow ID, Src IP, Src Port, Dst IP)
    that no other file has. Handled with a union schema: those 4 columns are added
    as null for the other 9 files rather than dropped from Tuesday's — preserving
    Tuesday's data instead of discarding it to match the smaller files.
  - 59 rows across two files (Thursday-01-03 and Wednesday-28-02) are duplicate
    embedded header rows (Label == "Label", a known CIC-IDS-2018 CSV-concatenation
    artifact) — dropped, since they are not real flow records.
  - `Flow Byts/s` and `Flow Pkts/s` contain literal "Infinity" strings for
    divide-by-zero flows. Every column is read as Utf8 first, then cast to Float64
    with strict=False, which Polars maps "Infinity"/"-Infinity"/"NaN" to
    inf/-inf/NaN and empty strings to null — no manual string replacement needed.

Output: data/normalized/cic_ids_2018_features.parquet
"""

from __future__ import annotations

import glob
from pathlib import Path

import polars as pl

from pipeline.schema import validate_tier2_polars

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "cic-ids-2018"
OUT_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "normalized" / "cic_ids_2018_features.parquet"
)

SOURCE_DATASET = "cic_ids_2018"

# columns that must stay as strings (identifiers / free text), everything else in the
# native CICFlowMeter column set is a numeric feature
_STRING_COLS = {"Flow ID", "Src IP", "Dst IP", "Timestamp", "Label"}
_EXTRA_ID_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP"]  # only present in Tuesday's file


def _process_file(path: str) -> pl.DataFrame:
    lf = pl.scan_csv(path, infer_schema_length=0)  # force Utf8 everywhere, see module docstring
    schema_cols = lf.collect_schema().names()

    # drop duplicate embedded header rows
    lf = lf.filter(pl.col("Label") != "Label")

    # add the Tuesday-only ID columns as null Utf8 for files that lack them
    missing_id_cols = [c for c in _EXTRA_ID_COLS if c not in schema_cols]
    if missing_id_cols:
        lf = lf.with_columns([pl.lit(None, dtype=pl.Utf8).alias(c) for c in missing_id_cols])

    numeric_cols = [c for c in schema_cols if c not in _STRING_COLS]
    lf = lf.with_columns([pl.col(c).cast(pl.Float64, strict=False) for c in numeric_cols])

    source_stem = Path(path).stem
    lf = lf.with_row_index("_row_idx").with_columns(
        [
            (pl.lit(f"{source_stem}_") + pl.col("_row_idx").cast(pl.Utf8)).alias("sample_id"),
            pl.lit(SOURCE_DATASET).alias("source_dataset"),
            pl.when(pl.col("Label") == "Benign")
            .then(pl.lit("benign"))
            .otherwise(pl.lit("other"))
            .alias("label"),
            pl.when(pl.col("Label") == "Benign")
            .then(pl.lit("benign_baseline"))
            .otherwise(pl.lit("generic_intrusion"))
            .alias("label_type"),
            pl.lit(1.0).alias("label_confidence"),
            pl.lit(None, dtype=pl.Utf8).alias("family"),
            pl.lit(source_stem).alias("source_csv"),
        ]
    ).drop("_row_idx")

    return lf.collect()


def load() -> tuple[pl.DataFrame, dict[str, int]]:
    paths = sorted(glob.glob(str(DATA_DIR / "*.csv")))
    if not paths:
        raise FileNotFoundError(f"no CSVs found under {DATA_DIR}")

    per_file_counts: dict[str, int] = {}
    frames = []
    for path in paths:
        df = _process_file(path)
        per_file_counts[Path(path).stem] = df.height
        frames.append(df)

    provenance_cols = ["sample_id", "source_dataset", "label", "label_type", "label_confidence", "family"]
    combined = pl.concat(frames, how="diagonal_relaxed")
    other_cols = [c for c in combined.columns if c not in provenance_cols]
    combined = combined.select(provenance_cols + other_cols)
    return combined, per_file_counts


def main() -> None:
    df, per_file_counts = load()
    validated = validate_tier2_polars(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.write_parquet(OUT_PATH)

    print("[cic_ids_2018] rows per source file:")
    for name, n in per_file_counts.items():
        print(f"  {name}: {n}")
    print(f"[cic_ids_2018] total rows written: {validated.height}")
    print(f"[cic_ids_2018] label distribution:\n{validated['label'].value_counts()}")
    print(f"[cic_ids_2018] native Label distribution:\n{validated['Label'].value_counts()}")
    print(f"[cic_ids_2018] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
