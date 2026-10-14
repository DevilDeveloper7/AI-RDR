"""Loads the 3 original training-eligible windowed feature parquets plus the LID-DS
2019/2021 benign rows (task 3.3 + the LID-DS integration task), the Linux-APT-2024
validation-only parquet, and the LID-DS exploit validation-only rows, and builds the
per-source train/test split task 3.3 requires (per planning/model-training-progress.md's
explicit caveat: a global shuffle across sources would let the model memorize one
source's quirks and still look fine in an aggregate metric — a per-source split,
evaluated per-source, is the only way to tell whether the model actually generalizes).

Scope, per planning/task-breakdown.md §3.3's correction note (read before touching this
module): ONLY the SDD-native 8-feature windowed parquets are training data. MLRan
(483-feature RFE schema), CIC-IDS-2018, and CTU-13 are excluded entirely — not loaded,
not inspected, not referenced anywhere in this package.

LID-DS is a **mixed** source, unlike the other Tier-1 parquets: `lidds2019_features.parquet`
and `lidds2021_features.parquet` each contain BOTH `training_eligible=True` rows (normal
recordings from real production services — new benign training data, per
planning/lid-ds-integration-progress.md's scoping correction) AND `training_eligible=False`
rows (CVE-exploit recordings — a second, independent generic-attack validation set, never
ransomware-labeled, never merged into the ransomware positive class) in the SAME file.
`load_all()` splits each of these two files in two before doing anything else with them:
the `True` half joins the training pool exactly like ELFEN/Lifecycle/EN2025's already-pure
files; the `False` half is concatenated into `lidds_exploit_validation_df` and evaluated
completely separately from Linux-APT-2024 in train.py — the two are different attack
categories (Wazuh-alert-driven APT/generic-intrusion telemetry vs. real CVE exploits
against real services) and reporting one averaged number would hide which one the model
actually struggles with, per the tracker's explicit instruction.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from pipeline.features.schema import validate_features

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "features"

# The 3 original training-eligible sources (all training_eligible=true, per
# data/features/SUMMARY.md).
TRAIN_SOURCES = {
    "elfen": DATA_DIR / "elfen_features.parquet",
    "lifecycle": DATA_DIR / "lifecycle_features.parquet",
    "en2025": DATA_DIR / "en2025_features.parquet",
}

# LID-DS — mixed files (see module docstring): split into a training-eligible (benign)
# half and a validation-only (exploit) half by load_all(), rather than being a pure
# training or pure validation source like everything else in this module.
LIDDS_SOURCES = {
    "lidds2019": DATA_DIR / "lidds2019_features.parquet",
    "lidds2021": DATA_DIR / "lidds2021_features.parquet",
}
LIDDS_VALIDATION_SOURCE_NAME = "lidds_exploit"

# Validation-only — training_eligible=false in the file itself; never enters the split.
VALIDATION_SOURCE_NAME = "linux_apt_2024"
VALIDATION_SOURCE_PATH = DATA_DIR / "linux_apt_2024_features.parquet"

# The SDD Table 5.1a windowed feature set (n_events + the 7 named features = the "8-feature
# windowed schema" planning/task-breakdown.md §3.3 refers to). Deliberately excludes
# lifecycle.py's bonus `crypto_op_rate` column: that column only exists for one of the
# three training sources (see data/features/SUMMARY.md's entropy section), so including it
# would silently make it a Lifecycle-identifying feature (always null elsewhere) rather
# than a genuine cross-source behavioral signal — the exact anti-pattern
# event_categories.py's own docstring warns against for event_mask.
FEATURE_COLUMNS = [
    "n_events",
    "file_mod_rate",
    "write_read_ratio",
    "rename_rate",
    "unique_extensions_touched",
    "event_mask",
    "entropy_score",
    "encryption_rate",
]

RANDOM_STATE = 42
TEST_SIZE = 0.2


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]


def load_source(name: str, path: Path) -> pd.DataFrame:
    """Read + re-validate one windowed feature parquet. Re-running validate_features here
    (cheap at this row count) rather than trusting the file was never touched since task
    3.2 wrote it — matches this codebase's habit of verifying rather than assuming
    (data/features/SUMMARY.md's own EN2025 write_events bug was caught exactly this way)."""
    df = pd.read_parquet(path)
    df = validate_features(df)
    if name != VALIDATION_SOURCE_NAME:
        assert df["training_eligible"].all(), (
            f"{name}: expected training_eligible=true for all rows, found "
            f"{(~df['training_eligible']).sum()} false"
        )
        assert (df["source_dataset"] != "linux_apt_2024").all()
    return df


def load_lidds_source(name: str, path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Reads + validates one LID-DS features parquet and splits it into (benign_train_df,
    exploit_validation_df) by its own per-row `training_eligible` column — the one place
    in this module where a single input file legitimately contains both training and
    validation-only rows (see module docstring)."""
    df = pd.read_parquet(path)
    df = validate_features(df)
    benign_df = df[df["training_eligible"]].reset_index(drop=True)
    exploit_df = df[~df["training_eligible"]].reset_index(drop=True)
    assert (benign_df["label"] == "benign").all(), (
        f"{name}: every training_eligible=True row must be label=benign"
    )
    assert (exploit_df["label"] == "other").all(), (
        f"{name}: every training_eligible=False row must be label=other (CVE exploit, "
        "not ransomware, not apt) — see planning/lid-ds-integration-progress.md's "
        "scoping correction"
    )
    return benign_df, exploit_df


def load_all() -> tuple[dict[str, pd.DataFrame], pd.DataFrame, pd.DataFrame, dict]:
    """Returns (train_sources dict, validation_df, lidds_exploit_validation_df,
    dataset_metadata). `dataset_metadata` records the sha256 (truncated) + row count of
    every input parquet, for ModelRegistry's reproducibility record."""
    train_dfs = {}
    metadata = {"sources": {}}
    for name, path in TRAIN_SOURCES.items():
        df = load_source(name, path)
        train_dfs[name] = df
        metadata["sources"][name] = {
            "path": str(path.relative_to(path.parents[2])),
            "rows": int(len(df)),
            "sha256_16": _sha256(path),
        }

    original_3_rows = sum(len(df) for df in train_dfs.values())
    assert original_3_rows == 23_544, (
        f"expected 23,544 total windows across the original 3 training sources "
        f"(183 + 6,907 + 16,454), got {original_3_rows} — data/features/ parquets have "
        "drifted from planning/model-training-progress.md's recorded counts, investigate "
        "before training on them"
    )

    lidds_exploit_frames = []
    for name, path in LIDDS_SOURCES.items():
        benign_df, exploit_df = load_lidds_source(name, path)
        train_dfs[name] = benign_df
        lidds_exploit_frames.append(exploit_df)
        metadata["sources"][name] = {
            "path": str(path.relative_to(path.parents[2])),
            "rows_total": int(len(benign_df) + len(exploit_df)),
            "rows_training_eligible_benign": int(len(benign_df)),
            "rows_validation_exploit": int(len(exploit_df)),
            "sha256_16": _sha256(path),
        }

    lidds_exploit_validation_df = (
        pd.concat(lidds_exploit_frames, ignore_index=True)
        if lidds_exploit_frames
        else pd.DataFrame()
    )
    metadata["sources"][LIDDS_VALIDATION_SOURCE_NAME] = {
        "rows": int(len(lidds_exploit_validation_df)),
        "role": "validation_only",
        "note": "concatenation of lidds2019+lidds2021 training_eligible=false rows",
    }

    validation_df = load_source(VALIDATION_SOURCE_NAME, VALIDATION_SOURCE_PATH)
    assert not validation_df["training_eligible"].any(), (
        "Linux-APT-2024 must never be training_eligible — refusing to proceed"
    )
    metadata["sources"][VALIDATION_SOURCE_NAME] = {
        "path": str(VALIDATION_SOURCE_PATH.relative_to(VALIDATION_SOURCE_PATH.parents[2])),
        "rows": int(len(validation_df)),
        "sha256_16": _sha256(VALIDATION_SOURCE_PATH),
        "role": "validation_only",
    }
    assert len(validation_df) == 2_040, (
        f"expected 2,040 Linux-APT-2024 validation windows, got {len(validation_df)}"
    )

    return train_dfs, validation_df, lidds_exploit_validation_df, metadata


def to_label(df: pd.DataFrame) -> pd.Series:
    """Binary label: 1 = ransomware (the positive class per the SDD/task-breakdown label
    scope decision), 0 = benign. Only meaningful for the 3 training sources — Linux-APT-2024
    rows are label='apt', never 'benign' or 'ransomware', and are handled separately in
    evaluate.py as a pure false-positive check, not as labeled binary examples."""
    assert df["label"].isin(["ransomware", "benign"]).all(), (
        "to_label() called on a frame with a non-ransomware/benign label — "
        "did you pass the Linux-APT-2024 validation frame by mistake?"
    )
    return (df["label"] == "ransomware").astype(int)


def to_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """The 8-column SDD feature matrix as plain float64, preserving real NaNs
    (entropy_score/encryption_rate) for RF/XGBoost's native missing-value handling —
    deliberately NOT calling .fillna(0), which would fabricate a false "no encryption
    detected" reading for windows that simply have no decodable byte content (Lifecycle:
    100% null; ELFEN: 84.7% null; EN2025: 81.1% null — see data/features/SUMMARY.md)."""
    # pandas nullable Int64 -> float64 via an explicit Float64 intermediate so pd.NA
    # (not just np.nan) round-trips correctly; none of these 8 columns actually contain
    # nulls except entropy_score/encryption_rate (already float64), but this keeps the
    # conversion correct even if that ever changes.
    return df[FEATURE_COLUMNS].astype("Float64").to_numpy(dtype="float64", na_value=np.nan)


def per_source_split(
    df: pd.DataFrame, *, test_size: float = TEST_SIZE, random_state: int = RANDOM_STATE
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified train/test split within one source's dataframe. Stratifying on `label`
    is a no-op for ELFEN/Lifecycle (single class, ransomware-only) and preserves the
    benign:ransomware ratio in both halves for EN2025 (the only source where it matters)."""
    y = df["label"]
    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=y, shuffle=True
    )
    return train_df, test_df


def build_splits(
    train_sources: dict[str, pd.DataFrame],
) -> tuple[dict[str, pd.DataFrame], dict[str, pd.DataFrame]]:
    """Splits each of the 3 training sources independently, returning
    ({source: train_df}, {source: test_df}). The pooled training set used to actually fit
    RF/XGBoost is the concatenation of the 3 train_df values; the pooled test set is the
    concatenation of the 3 test_df values — but per-source test_df's are also kept
    separate for the per-source evaluation task 3.3 requires."""
    train_splits, test_splits = {}, {}
    for name, df in train_sources.items():
        train_df, test_df = per_source_split(df)
        train_splits[name] = train_df
        test_splits[name] = test_df
    return train_splits, test_splits


def subsample_lidds_benign(
    train_sources: dict[str, pd.DataFrame],
    target_benign_share: float,
    random_state: int = RANDOM_STATE,
) -> tuple[dict[str, pd.DataFrame], pd.DataFrame]:
    """Fixes the v2 class-imbalance regression (see
    planning/class-imbalance-fix-progress.md — read that doc before touching this
    function) by bounding how large LID-DS-2019/2021's benign contribution is allowed to
    be, *before* it ever reaches `build_splits()` or either of `model.py`'s two
    class-imbalance mechanisms (`compute_scale_pos_weight`, RF's
    `class_weight="balanced"`). Both of those mechanisms react automatically to whatever
    row counts the pooled training pool happens to have — patching one of them
    (`scale_pos_weight`) would leave the other (RF) still reacting to the raw,
    LID-DS-dominated pool, so the fix has to happen upstream of both, on the actual row
    counts.

    `target_benign_share` is LID-DS's target share of the FULL pooled training pool
    (non-LID-DS training sources + the LID-DS benign rows that survive subsampling),
    e.g. 0.25 means "subsample LID-DS-2019/2021 benign rows down until they're ~25% of
    the pooled training set" (down from v2's raw, unbounded 83.5%). Solved directly from
    the non-LID-DS row count so the requested share holds after subsampling:

        k / (non_lidds_total + k) = target_benign_share
        k = target_benign_share * non_lidds_total / (1 - target_benign_share)

    This is called on the full per-source frames `load_all()` returns (i.e. before the
    80/20 train/test split), so the achieved share is preserved through
    `build_splits()`'s per-source split (an 80/20 split applied uniformly to every
    source doesn't change the relative proportions between sources) — meaning the
    train **and** each LID-DS source's own held-out test slice both shrink
    proportionally to the same subsampling fraction. That's a real, reported side effect
    of subsampling upstream of the split rather than only trimming the train half, not
    something masked here.

    Sampling is real rows only: `np.random.RandomState(random_state).permutation`, no
    replacement, no synthesis, no duplication — matching this project's project-wide
    rejection of SMOTE/synthetic oversampling (see `model.py`'s module docstring). The
    reduction is split proportionally across lidds2019/lidds2021 so neither source is
    made to disappear or dominate the kept subsample relative to the other.

    Rows that don't make the cut are never discarded: they're returned as a second
    "excess" frame (all real, all `label="benign"`) for a new reported "LID-DS excess
    benign" evaluation slice, exactly mirroring how the LID-DS *exploit* rows already get
    used as a validation set instead of being dropped.

    Returns (new_train_sources dict with lidds2019/lidds2021 replaced by their
    subsampled frames, concatenated_excess_benign_df).
    """
    assert 0.0 < target_benign_share < 1.0, (
        f"target_benign_share must be in (0, 1), got {target_benign_share}"
    )
    lidds_names = [name for name in train_sources if name in LIDDS_SOURCES]
    non_lidds_total = sum(
        len(df) for name, df in train_sources.items() if name not in LIDDS_SOURCES
    )
    lidds_total = sum(len(train_sources[name]) for name in lidds_names)

    if not lidds_names or lidds_total == 0 or non_lidds_total == 0:
        return dict(train_sources), pd.DataFrame()

    target_lidds_total = int(round(target_benign_share * non_lidds_total / (1 - target_benign_share)))
    # Never upsample — if the requested share is already at or above LID-DS's raw share,
    # keep everything and report an empty excess frame rather than fabricating rows.
    target_lidds_total = min(target_lidds_total, lidds_total)

    rng = np.random.RandomState(random_state)
    new_sources = dict(train_sources)
    excess_frames = []
    running_keep_total = 0
    for i, name in enumerate(lidds_names):
        df = train_sources[name]
        if i == len(lidds_names) - 1:
            # last source absorbs the rounding remainder so the achieved total matches
            # target_lidds_total exactly (up to the min() cap per-source below)
            n_keep = target_lidds_total - running_keep_total
        else:
            share_of_lidds = len(df) / lidds_total
            n_keep = int(round(target_lidds_total * share_of_lidds))
        n_keep = max(0, min(n_keep, len(df)))
        running_keep_total += n_keep

        idx = rng.permutation(len(df))
        keep_idx, excess_idx = idx[:n_keep], idx[n_keep:]
        new_sources[name] = df.iloc[keep_idx].reset_index(drop=True)
        excess_frames.append(df.iloc[excess_idx].reset_index(drop=True))

    excess_df = (
        pd.concat(excess_frames, ignore_index=True) if excess_frames else pd.DataFrame()
    )
    assert (excess_df.empty) or (excess_df["label"] == "benign").all(), (
        "LID-DS excess frame must be entirely label=benign — every row here came from "
        "load_lidds_source()'s training_eligible=True half"
    )
    return new_sources, excess_df
