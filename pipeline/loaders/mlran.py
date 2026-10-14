"""Loader for the MLRan feature-selected dataset (Tier 2 — feature passthrough).

Source: data/mlran-features/
  - MLRan_X_train_RFE.csv / MLRan_X_test_RFE.csv: 483 RFE-selected Cuckoo-sandbox
    features per sample, plus sample_id/sample_type/family_label/type_label.
  - mlran_dataset_metadata.csv: per-sample hash/family/source metadata — used here
    only to recover the human-readable family name (ransomware_family), since the
    RFE CSVs only carry the numeric family_label code.
  - type_train_sampleids.csv / type_test_sampleids.csv: not used directly — the RFE
    CSVs already carry sample_id per row, so the split is derived from which RFE
    file a row came from (equivalent to what these id lists would give us).

Output: data/normalized/mlran_features.parquet
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from pipeline.schema import validate_tier2_pandas

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "mlran-features"
OUT_PATH = Path(__file__).resolve().parents[2] / "data" / "normalized" / "mlran_features.parquet"

SOURCE_DATASET = "mlran_features"


def load() -> pd.DataFrame:
    train = pd.read_csv(DATA_DIR / "MLRan_X_train_RFE.csv", dtype={"sample_id": str})
    train["split"] = "train"
    test = pd.read_csv(DATA_DIR / "MLRan_X_test_RFE.csv", dtype={"sample_id": str})
    test["split"] = "test"

    combined = pd.concat([train, test], ignore_index=True).copy()
    n_before = len(combined)

    metadata = pd.read_csv(DATA_DIR / "mlran_dataset_metadata.csv", dtype={"sample_id": str})
    metadata = metadata[["sample_id", "ransomware_family"]].drop_duplicates("sample_id")

    merged = combined.merge(metadata, on="sample_id", how="left", validate="many_to_one").copy()
    if len(merged) != n_before:
        raise ValueError(
            f"row count changed on metadata join: {n_before} -> {len(merged)} "
            "(duplicate sample_id in metadata?)"
        )
    n_unmatched = merged["ransomware_family"].isna().sum()
    if n_unmatched:
        print(f"[mlran] WARNING: {n_unmatched} rows had no metadata match for family name")

    merged["source_dataset"] = SOURCE_DATASET
    merged["label"] = merged["sample_type"].map({0: "benign", 1: "ransomware"})
    if merged["label"].isna().any():
        raise ValueError("unexpected sample_type value outside {0,1}")
    merged["label_type"] = "real_execution"
    merged["label_confidence"] = 1.0
    # goodware rows carry ransomware_family == "goodware" in the metadata; normalize
    # to a real null so downstream consumers can tell "no family" from a literal name.
    merged["family"] = merged["ransomware_family"].where(
        (merged["ransomware_family"].notna()) & (merged["ransomware_family"] != "goodware"),
        other=pd.NA,
    )
    merged = merged.drop(columns=["ransomware_family"])

    # reorder: provenance + split columns first, then native feature columns
    provenance_cols = ["sample_id", "source_dataset", "label", "label_type", "label_confidence", "family", "split"]
    other_cols = [c for c in merged.columns if c not in provenance_cols]
    merged = merged[provenance_cols + other_cols]

    return merged, n_before


def main() -> None:
    df, n_before = load()
    validated = validate_tier2_pandas(df)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    validated.to_parquet(OUT_PATH, index=False)

    print(f"[mlran] rows in (train+test RFE CSVs): {n_before}")
    print(f"[mlran] rows written: {len(validated)}")
    print(f"[mlran] label distribution:\n{validated['label'].value_counts()}")
    print(f"[mlran] split distribution:\n{validated['split'].value_counts()}")
    print(f"[mlran] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
