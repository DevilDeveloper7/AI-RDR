"""Shared 30-second (default) windowing/feature-aggregation utility used by all 4
Tier-1 dataset feature modules (elfen.py, lifecycle.py, en2025.py, linux_apt_2024.py).

Design: window per `(sample_id, process_id)` entity, never across unrelated
processes/samples (per planning/feature-engineering-progress.md), using a *relative*
time axis (`t_seconds` - the group's own minimum `t_seconds`) rather than trying to align
every source onto one true wall-clock. This is deliberate, not a shortcut: the 4 sources
have 5 different timestamp shapes between them (ELFEN: absolute UTC ISO; EN2025: mostly
naive local-clock ISO but `REL:<sec>`/absolute-UTC for two different network-summary
sub-cases; Lifecycle ftrace/perf: `REL:<sec>` monotonic-since-arbitrary-start; Lifecycle
net: wall-clock text with a `CDT`/`CST` abbreviation pandas/polars can't parse a strict
dtype from). Windowing relative to each entity's own first observed event is correct
for a per-entity rolling-window design regardless of what each source's absolute clock
means, and sidesteps having to fabricate a shared absolute timeline across sources that
were never running at the same wall-clock time anyway.

Caller contract — the input DataFrame must already have these columns before calling
`build_feature_windows`:
    sample_id           Utf8, non-null
    process_id          Int64, nullable (nulls form their own group — correct, e.g.
                         Linux-APT-2024 never has a process_id at all, so every row for
                         one CSV file's worth of alerts group together instead of being
                         silently dropped)
    t_seconds           Float64, non-null (caller has already resolved whatever this
                         source's raw `timestamp` string means into a per-entity-relative
                         numeric seconds axis, and dropped/logged unparseable rows)
    event_type          Utf8 (normalized Tier-1 vocabulary; used for file_mod_rate and
                         event_mask via event_categories.canonical_bit_expr)
    extension           Utf8, nullable (lower-cased file extension incl. leading '.',
                         or null when file_path was null/extensionless)
    is_write / is_read / is_rename   Boolean (dataset-specific detection — see each
                         dataset module's docstring for exactly which raw func/api/event
                         values map to each; event_type alone is too coarse for these
                         three, e.g. ELFEN's file_access bucket covers open+read+readlink
                         +fcntl indiscriminately)
    entropy_bits        Float64, nullable — per-row Shannon entropy already computed
                         where real byte content existed for that row, else null. Pass
                         an all-null column when a source has no byte content at all
                         (documented per-dataset, never fabricated).
    label / label_type / label_confidence / family   already-normalized Tier-1 columns.

`extra_aggs` lets a dataset module fold in one extra dataset-specific aggregation (e.g.
Lifecycle's crypto_op_rate proxy) in the same group_by pass instead of a second join.
"""

from __future__ import annotations

import polars as pl

from pipeline.features.entropy import HIGH_ENTROPY_THRESHOLD
from pipeline.features.event_categories import canonical_bit_expr

_GROUP_COLS = ["sample_id", "process_id"]
_WINDOW_COLS = ["sample_id", "process_id", "window_index"]


def build_feature_windows(
    df: pl.DataFrame,
    *,
    window_sec: int,
    source_dataset: str,
    training_eligible: bool,
    extra_aggs: list[pl.Expr] | None = None,
) -> pl.DataFrame:
    minutes = window_sec / 60.0

    df = df.with_columns(
        [
            canonical_bit_expr("event_type").alias("_bit"),
            pl.col("t_seconds").min().over(_GROUP_COLS).alias("_t_min"),
            pl.col("event_type").is_in(["file_modify", "file_delete"]).alias("_is_filemod"),
        ]
    )
    df = df.with_columns(
        (((pl.col("t_seconds") - pl.col("_t_min")) / window_sec).floor().cast(pl.Int64)).alias(
            "window_index"
        )
    )

    agg = df.group_by(_WINDOW_COLS).agg(
        [
            pl.len().alias("n_events"),
            pl.col("is_write").sum().alias("_n_write"),
            pl.col("is_read").sum().alias("_n_read"),
            pl.col("is_rename").sum().alias("_n_rename"),
            pl.col("_is_filemod").sum().alias("_n_filemod"),
            pl.col("extension").drop_nulls().n_unique().alias("unique_extensions_touched"),
            pl.col("_bit").unique().alias("_bits"),
            pl.col("entropy_bits").drop_nulls().alias("_entropy_list"),
            pl.col("label").first().alias("label"),
            pl.col("label_type").first().alias("label_type"),
            pl.col("label_confidence").first().alias("label_confidence"),
            pl.col("family").drop_nulls().mode().first().alias("family"),
        ]
        + (extra_aggs or [])
    )

    agg = agg.with_columns(
        [
            pl.lit(window_sec, dtype=pl.Int64).alias("window_sec"),
            (pl.col("_n_filemod") / minutes).alias("file_mod_rate"),
            (pl.col("_n_rename") / minutes).alias("rename_rate"),
            # write_read_ratio: writes / reads, with reads floored at 1 to avoid
            # division by zero — a source with zero captured reads in the window (e.g.
            # Linux-APT-2024, which never captures raw file reads at all, only FIM
            # add/modify/delete — see linux_apt_2024.py) then reports the ratio as
            # exactly its write count, which is documented as the intended fallback
            # reading ("writes with no reads observed"), not silently coerced to 0/null.
            (pl.col("_n_write") / pl.when(pl.col("_n_read") > 0).then(pl.col("_n_read")).otherwise(1)).alias(
                "write_read_ratio"
            ),
            pl.col("_bits").list.sum().alias("event_mask"),
            pl.col("_entropy_list").list.mean().alias("entropy_score"),
            pl.when(pl.col("_entropy_list").list.len() > 0)
            .then(
                pl.col("_entropy_list").list.eval(pl.element() > HIGH_ENTROPY_THRESHOLD).list.sum()
                / pl.col("_entropy_list").list.len()
            )
            .otherwise(None)
            .alias("encryption_rate"),
            pl.lit(source_dataset).alias("source_dataset"),
            pl.lit(training_eligible).alias("training_eligible"),
        ]
    )

    drop_cols = [c for c in agg.columns if c.startswith("_")]
    return agg.drop(drop_cols)
