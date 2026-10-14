"""Shared Pandera schema for the windowed feature vectors task 3.2 produces (SDD Table
5.1a), analogous in style/rigor to pipeline/schema.py's Tier-1 raw-event schema.

One row per (sample_id, process_id, window_index) — the entity/window granularity task
3.3's RF/XGBoost ensemble trains on. `entropy_score`/`encryption_rate` are nullable
Float64 throughout: per planning/feature-engineering-progress.md's explicit warning, a
null here is the honest answer wherever a source has no real byte content to compute
entropy from (see pipeline/features/entropy.py and each dataset module's docstring for
which sources that is) — never a fabricated plausible-looking number.
"""

from __future__ import annotations

import pandera.pandas as pa
from pandera.pandas import Column, DataFrameSchema, Check

from pipeline.schema import VALID_LABEL_TYPES

VALID_LABELS = {"ransomware", "benign", "apt", "other"}

feature_vector_schema = DataFrameSchema(
    {
        "sample_id": Column(str, nullable=False),
        "process_id": Column("Int64", nullable=True, coerce=True),
        "window_index": Column("Int64", nullable=False, coerce=True),
        "window_sec": Column("Int64", nullable=False, coerce=True),
        "n_events": Column("Int64", nullable=False, coerce=True),
        # --- SDD Table 5.1a features ---
        "file_mod_rate": Column(float, Check.ge(0.0), nullable=False, coerce=True),
        "write_read_ratio": Column(float, Check.ge(0.0), nullable=False, coerce=True),
        "rename_rate": Column(float, Check.ge(0.0), nullable=False, coerce=True),
        "unique_extensions_touched": Column("Int64", Check.ge(0), nullable=False, coerce=True),
        "event_mask": Column("Int64", Check.ge(0), nullable=False, coerce=True),
        "entropy_score": Column(
            float, Check.in_range(0.0, 8.0), nullable=True, coerce=True
        ),
        "encryption_rate": Column(
            float, Check.in_range(0.0, 1.0), nullable=True, coerce=True
        ),
        # --- provenance (majority/first value from the window's constituent rows) ---
        "source_dataset": Column(str, nullable=False),
        "label": Column(str, Check.isin(VALID_LABELS), nullable=False),
        "label_type": Column(str, Check.isin(VALID_LABEL_TYPES), nullable=False),
        "label_confidence": Column(float, Check.in_range(0.0, 1.0), nullable=False, coerce=True),
        "family": Column(str, nullable=True),
        "training_eligible": Column(bool, nullable=False, coerce=True),
    },
    strict=False,  # allow dataset-specific bonus columns (e.g. Lifecycle's crypto_op_rate
    # proxy — see pipeline/features/lifecycle.py) rather than dropping them silently
    coerce=True,
)


def validate_features(df):
    """Validate a windowed feature-vector pandas DataFrame; returns the validated df."""
    return feature_vector_schema.validate(df, lazy=True)
