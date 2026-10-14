"""Shared Pandera schema definitions for the AI-RDR dataset normalization pipeline.

Two target shapes, per planning/normalization-progress.md:

- Tier 1 (raw-event): one row per raw event/log line, common schema across sources
  that need windowing before features exist (ELFEN, Linux-APT-2024, Lifecycle, EN2025).
- Tier 2 (feature passthrough): native feature columns preserved as-is, with a fixed
  set of provenance columns prepended (MLRan, CIC-IDS-2018, CTU-13).

Two dataframe engines are in play (pandas for the small/medium sources, Polars for the
large CIC-IDS-2018 file), so each tier has a pandas schema and Tier 2 also has a Polars
variant used specifically for the big CSV where materializing a full pandas copy just to
validate would defeat the point of using Polars in the first place.
"""

from __future__ import annotations

import pandera.pandas as pa
from pandera.pandas import Column, DataFrameSchema, Check
import pandera.polars as pa_pl

VALID_LABELS = {"ransomware", "benign", "apt", "other"}
VALID_LABEL_TYPES = {
    "real_execution",
    "synthetic_simulation",
    "generic_intrusion",
    "benign_baseline",
}

# ---------------------------------------------------------------------------
# Tier 1 — raw-event schema (pandas)
# ---------------------------------------------------------------------------

tier1_raw_event_schema = DataFrameSchema(
    {
        "sample_id": Column(str, nullable=False),
        "source_dataset": Column(str, nullable=False),
        "label": Column(str, Check.isin(VALID_LABELS), nullable=False),
        "label_type": Column(str, Check.isin(VALID_LABEL_TYPES), nullable=False),
        "label_confidence": Column(
            float, Check.in_range(0.0, 1.0), nullable=False, coerce=True
        ),
        "family": Column(str, nullable=True),
        # best-effort timestamp; some sources only have relative offsets, so we keep
        # this as a nullable string (ISO-8601 when real, raw offset text when not) —
        # a strict datetime dtype would force us to fabricate wall-clock times for
        # sources that don't have any, which is worse than being honest about it.
        "timestamp": Column(str, nullable=True),
        "host_id": Column(str, nullable=True),
        "process_id": Column("Int64", nullable=True, coerce=True),
        "event_type": Column(str, nullable=False),
        "file_path": Column(str, nullable=True),
        "raw_fields": Column(str, nullable=False),  # JSON string, "{}" if empty
    },
    strict=False,  # allow incidental extra columns rather than dropping data silently
    coerce=True,
)

# ---------------------------------------------------------------------------
# Tier 2 — feature-passthrough provenance columns (pandas)
# ---------------------------------------------------------------------------

TIER2_PROVENANCE_COLUMNS_PANDAS = DataFrameSchema(
    {
        "sample_id": Column(str, nullable=False),
        "source_dataset": Column(str, nullable=False),
        "label": Column(str, nullable=False),
        "label_type": Column(str, Check.isin(VALID_LABEL_TYPES), nullable=False),
        "label_confidence": Column(
            float, Check.in_range(0.0, 1.0), nullable=False, coerce=True
        ),
        "family": Column(str, nullable=True),
    },
    strict=False,  # native feature columns pass through untouched
    coerce=True,
)

# ---------------------------------------------------------------------------
# Tier 2 — same provenance check, Polars variant (for the large CIC-IDS-2018 file,
# where we don't want to materialize a pandas copy just to validate)
# ---------------------------------------------------------------------------

tier2_provenance_schema_polars = pa_pl.DataFrameSchema(
    {
        "sample_id": pa_pl.Column(str, nullable=False),
        "source_dataset": pa_pl.Column(str, nullable=False),
        "label": pa_pl.Column(str, nullable=False),
        "label_type": pa_pl.Column(
            str, pa_pl.Check.isin(list(VALID_LABEL_TYPES)), nullable=False
        ),
        "label_confidence": pa_pl.Column(
            float, pa_pl.Check.in_range(0.0, 1.0), nullable=False
        ),
        "family": pa_pl.Column(str, nullable=True),
    },
    strict=False,
)


def validate_tier1(df):
    """Validate a Tier-1 raw-event pandas DataFrame; returns the validated df."""
    return tier1_raw_event_schema.validate(df, lazy=True)


def validate_tier2_pandas(df):
    """Validate provenance columns of a Tier-2 pandas DataFrame; returns validated df."""
    return TIER2_PROVENANCE_COLUMNS_PANDAS.validate(df, lazy=True)


def validate_tier2_polars(df):
    """Validate provenance columns of a Tier-2 Polars DataFrame; returns validated df."""
    return tier2_provenance_schema_polars.validate(df, lazy=True)
