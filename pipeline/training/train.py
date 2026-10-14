"""Task 3.3 entry point (extended by the LID-DS integration task, then by the
class-imbalance-fix task): `python -m pipeline.training.train`.

Loads the 3 original training-eligible windowed feature parquets plus the LID-DS
2019/2021 benign rows, holds out a per-source test split, trains the SDD §6.2.5
RF/XGBoost ensemble with class-imbalance-aware weighting, evaluates overall and
per-source, runs the trained ensemble against **two independent** validation-only
sources as pure false-positive checks — Linux-APT-2024 (Wazuh-alert-driven APT/generic-
intrusion telemetry) and the LID-DS exploit recordings (real CVE exploits against real
services) — reported **separately, never averaged**, per
planning/lid-ds-integration-progress.md's explicit instruction (they are different
attack categories and a combined number would hide which one the model struggles with).

Class-imbalance fix (planning/class-imbalance-fix-progress.md — read before touching
this module): the LID-DS integration retrain (v2) flipped the pooled training set's
class ratio from 85.9% ransomware-majority (v1) to 16.5% ransomware-minority (v2)
because LID-DS's 79,198 real benign training windows outnumber the original 3 sources'
23,544 rows nearly 3.4x. Both `model.py` class-imbalance mechanisms
(`compute_scale_pos_weight`, RF's `class_weight="balanced"`) reacted uncapped to that
flip and made Linux-APT-2024's FPR *worse* (98.38% -> 100.00%), not better. The fix
bounds LID-DS's benign share of the pooled training pool via `dataset.subsample_lidds_benign`
*before* either weighting mechanism ever sees the row counts, rather than patching either
mechanism individually. This module now runs a small sweep over candidate target shares
(`CANDIDATE_LIDDS_BENIGN_SHARES`), prints every one of the 5 tracker-required metrics per
candidate (Linux-APT-2024 FPR, EN2025 benign FPR, Lifecycle recall, LID-DS exploit FPR,
LID-DS excess-benign FPR), then does one final full run at `CHOSEN_LIDDS_BENIGN_SHARE`
(picked after inspecting the sweep — see `models/SUMMARY.md`'s "Class-Imbalance Fix
Retrain (v3)" section for the full table and justification) that actually saves to the
registry as a new version.

Every number this prints is also what `models/SUMMARY.md` is written from — nothing in
that file is estimated separately from what this script actually measured.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from pipeline.training import dataset, model
from pipeline.training.registry import ModelRegistry

WINDOW_SEC = 30  # matches pipeline/features/windowing.py's default, used by all 4 sources

# Candidate target shares of the pooled training set that LID-DS-2019/2021 benign rows
# are subsampled down to, from v2's raw/unbounded 83.5%. The tracker's own example range
# (~25%/40%/50%) was tried first and, measured, none of the three came close to fixing
# anything (see models/SUMMARY.md's "Class-Imbalance Fix Retrain (v3)" section) — all
# three left Linux-APT-2024 FPR at 99.9-100.0% (no better than v2) and pushed EN2025
# benign FPR to 18-40% (far worse than v1's 5.74%). That result is what motivated probing
# much smaller shares too; the full swept range below is what's actually reported.
CANDIDATE_LIDDS_BENIGN_SHARES = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.40, 0.50]

# Picked after running the sweep above and comparing all 5 metrics against the v1/v2
# baselines (models/SUMMARY.md's "Class-Imbalance Fix Retrain (v3)" section has the full
# sweep table, a 5-random-state robustness check at 1%/2%, and the reasoning in full):
# 1% is the only candidate whose Linux-APT-2024 FPR (91.23% at this random_state) lands
# meaningfully below v1's 98.38% baseline, while EN2025 benign FPR (5.59%) and Lifecycle
# recall (89.44%) both land at-or-within-1pp of their v1 baselines too — every candidate
# from 2% upward is consistently *worse* than v1 on Linux-APT-2024 FPR (98.9-100.0%), and
# every candidate above ~10% is also clearly worse on EN2025 FPR and Lifecycle recall.
# The accepted tradeoff: LID-DS's own exploit/excess-benign FPR are both markedly worse
# than v2's (the model barely trains on LID-DS-shaped data at 1%) — stated explicitly in
# SUMMARY.md, not hidden. A 5-seed check at 1%/2% found real run-to-run variance (1%'s
# Linux-APT-2024 FPR ranged 91.2-98.5% across 5 seeds, 3 of 5 below v1's baseline; 2%'s
# stayed a consistent 98.9-99.2%, always above it) — reported honestly rather than
# treating the single random_state=42 number as guaranteed, but 1% is still the
# candidate whose *typical* behavior, not just its best draw, sits at or below v1.
CHOSEN_LIDDS_BENIGN_SHARE = 0.01


def run_one(
    label: str,
    train_sources: dict[str, pd.DataFrame],
    validation_df: pd.DataFrame,
    lidds_exploit_validation_df: pd.DataFrame,
    target_benign_share: float,
) -> dict:
    """Subsamples LID-DS benign rows to `target_benign_share` of the pooled training
    pool, trains one fresh RF+XGB ensemble on the result, and evaluates it against every
    metric the class-imbalance-fix tracker requires. Returns a dict carrying both the
    printable numbers and everything `main()` needs to save the chosen candidate to the
    registry, so the sweep and the final saved run share one code path end to end."""
    subsampled_sources, lidds_excess_benign_df = dataset.subsample_lidds_benign(
        train_sources, target_benign_share
    )
    kept_counts = {
        name: len(subsampled_sources[name])
        for name in dataset.LIDDS_SOURCES
        if name in subsampled_sources
    }
    excess_counts = {
        name: len(train_sources[name]) - kept_counts.get(name, 0)
        for name in dataset.LIDDS_SOURCES
        if name in train_sources
    }

    train_splits, test_splits = dataset.build_splits(subsampled_sources)

    pooled_train = pd.concat(train_splits.values(), ignore_index=True)
    pooled_test = pd.concat(test_splits.values(), ignore_index=True)

    X_train = dataset.to_feature_matrix(pooled_train)
    y_train = dataset.to_label(pooled_train).to_numpy()
    X_test = dataset.to_feature_matrix(pooled_test)
    y_test = dataset.to_label(pooled_test).to_numpy()

    lidds_rows_total = sum(kept_counts.values())
    pool_rows_total = len(pooled_train) + len(pooled_test)
    achieved_share = lidds_rows_total / pool_rows_total if pool_rows_total else 0.0

    print(
        f"[train] [{label}] LID-DS benign target share={target_benign_share:.0%} "
        f"achieved={achieved_share:.1%} (kept {kept_counts}, excluded as excess "
        f"{excess_counts})"
    )
    print(
        f"[train] [{label}] pooled training set: {len(y_train)} rows, "
        f"{int(y_train.sum())} ransomware / {int((y_train == 0).sum())} benign "
        f"({y_train.mean():.1%} positive)"
    )

    scale_pos_weight = model.compute_scale_pos_weight(y_train)
    print(f"[train] [{label}] scale_pos_weight (n_benign/n_ransomware on pooled train) = {scale_pos_weight:.4f}")

    rf = model.train_rf(X_train, y_train)
    xgb = model.train_xgb(X_train, y_train, scale_pos_weight)

    # --- overall pooled test evaluation ---
    overall_score = model.ensemble_proba(rf, xgb, X_test)
    overall_eval = model.evaluate(y_test, overall_score)
    print(f"[train] [{label}] overall pooled test evaluation: {overall_eval}")

    # --- per-source test evaluation ---
    per_source_eval = {}
    for name, te_df in test_splits.items():
        X_te = dataset.to_feature_matrix(te_df)
        y_te = dataset.to_label(te_df).to_numpy()
        score = model.ensemble_proba(rf, xgb, X_te)
        per_source_eval[name] = model.evaluate(y_te, score)
        print(f"[train] [{label}] {name} test evaluation: {per_source_eval[name]}")

    # --- Linux-APT-2024 validation: never trained on, ground truth is always "apt" (not
    # ransomware, not benign) so any predicted-ransomware row is a false positive by
    # definition, not a scored classification against a real negative label ---
    X_val = dataset.to_feature_matrix(validation_df)
    val_score = model.ensemble_proba(rf, xgb, X_val)
    val_pred_ransomware = (val_score >= model.DEFAULT_THRESHOLD).astype(int)
    apt_fpr = float(val_pred_ransomware.mean())
    print(
        f"[train] [{label}] Linux-APT-2024 validation ({len(validation_df)} windows, "
        f"never trained on): {int(val_pred_ransomware.sum())} flagged as ransomware "
        f"-> false-positive rate = {apt_fpr:.4f}"
    )

    # --- LID-DS exploit validation: a SECOND, INDEPENDENT false-positive check, never
    # averaged with Linux-APT-2024's (see module docstring / dataset.py's). ---
    lidds_exploit_fpr = None
    if len(lidds_exploit_validation_df):
        X_lidds = dataset.to_feature_matrix(lidds_exploit_validation_df)
        lidds_score = model.ensemble_proba(rf, xgb, X_lidds)
        lidds_pred_ransomware = (lidds_score >= model.DEFAULT_THRESHOLD).astype(int)
        lidds_exploit_fpr = float(lidds_pred_ransomware.mean())
        print(
            f"[train] [{label}] LID-DS exploit validation ({len(lidds_exploit_validation_df)} "
            f"windows, never trained on): {int(lidds_pred_ransomware.sum())} flagged as "
            f"ransomware -> false-positive rate = {lidds_exploit_fpr:.4f}"
        )
    else:
        print(f"[train] [{label}] LID-DS exploit validation: 0 windows available, skipped")

    # --- LID-DS excess-benign evaluation: the rows subsample_lidds_benign() excluded
    # from training so LID-DS's share stays bounded. Real, unmodified, label=benign rows
    # that never entered training or the per-source test split — reported here, per the
    # tracker's explicit instruction, rather than silently discarded. ---
    lidds_excess_benign_fpr = None
    lidds_excess_benign_n = len(lidds_excess_benign_df)
    if lidds_excess_benign_n:
        X_excess = dataset.to_feature_matrix(lidds_excess_benign_df)
        y_excess = dataset.to_label(lidds_excess_benign_df).to_numpy()
        excess_score = model.ensemble_proba(rf, xgb, X_excess)
        excess_eval = model.evaluate(y_excess, excess_score)
        lidds_excess_benign_fpr = excess_eval["false_positive_rate"]
        print(
            f"[train] [{label}] LID-DS excess-benign evaluation ({lidds_excess_benign_n} "
            f"windows, excluded from training by subsampling, never trained on): "
            f"false-positive rate = {lidds_excess_benign_fpr:.4f}"
        )
    else:
        print(f"[train] [{label}] LID-DS excess-benign evaluation: 0 windows excluded, skipped")

    # --- feature importance ---
    rf_importance = model.feature_importance(rf, dataset.FEATURE_COLUMNS)
    xgb_importance = model.xgb_feature_importance(xgb, dataset.FEATURE_COLUMNS)

    return {
        "label": label,
        "target_benign_share": target_benign_share,
        "achieved_benign_share": achieved_share,
        "kept_counts": kept_counts,
        "excess_counts": excess_counts,
        "rf": rf,
        "xgb": xgb,
        "scale_pos_weight": scale_pos_weight,
        "train_splits": train_splits,
        "test_splits": test_splits,
        "overall_eval": overall_eval,
        "per_source_eval": per_source_eval,
        "apt_fpr": apt_fpr,
        "apt_n": len(validation_df),
        "lidds_exploit_fpr": lidds_exploit_fpr,
        "lidds_exploit_n": len(lidds_exploit_validation_df),
        "lidds_excess_benign_fpr": lidds_excess_benign_fpr,
        "lidds_excess_benign_n": lidds_excess_benign_n,
        "rf_importance": rf_importance,
        "xgb_importance": xgb_importance,
    }


def _fmt(x) -> str:
    return f"{x:.4f}" if isinstance(x, float) else "N/A"


def print_sweep_summary(results: list[dict]) -> None:
    print("[train] === class-imbalance-fix sweep summary ===")
    print(
        f"{'target':>8} {'achieved':>9} {'APT FPR':>9} {'EN2025 FPR':>11} "
        f"{'Lifecycle recall':>17} {'LIDDS exploit FPR':>18} {'LIDDS excess FPR':>17}"
    )
    for r in results:
        print(
            f"{r['target_benign_share']:>8.0%} {r['achieved_benign_share']:>9.1%} "
            f"{_fmt(r['apt_fpr']):>9} {_fmt(r['per_source_eval']['en2025']['false_positive_rate']):>11} "
            f"{_fmt(r['per_source_eval']['lifecycle']['recall']):>17} "
            f"{_fmt(r['lidds_exploit_fpr']):>18} {_fmt(r['lidds_excess_benign_fpr']):>17}"
        )


def main() -> None:
    model.assert_native_missing_support()

    train_sources, validation_df, lidds_exploit_validation_df, dataset_metadata = dataset.load_all()

    print(f"[train] === class-imbalance-fix sweep: {len(CANDIDATE_LIDDS_BENIGN_SHARES)} candidates ===")
    sweep_results = []
    for share in CANDIDATE_LIDDS_BENIGN_SHARES:
        result = run_one(
            f"sweep target={share:.0%}", train_sources, validation_df, lidds_exploit_validation_df, share
        )
        sweep_results.append(result)
    print_sweep_summary(sweep_results)

    print(
        f"[train] === final full run at chosen ratio {CHOSEN_LIDDS_BENIGN_SHARE:.0%} "
        "-- this one is saved to the registry ==="
    )
    final = run_one(
        "final (saved)", train_sources, validation_df, lidds_exploit_validation_df, CHOSEN_LIDDS_BENIGN_SHARE
    )

    # --- registry ---
    registry = ModelRegistry()
    ensemble_config = {
        "rf_weight": model.RF_WEIGHT,
        "xgb_weight": model.XGB_WEIGHT,
        "default_threshold": model.DEFAULT_THRESHOLD,
        "feature_columns": dataset.FEATURE_COLUMNS,
    }
    hyperparameters = {
        "rf_params": model.RF_PARAMS,
        "xgb_params": {**model.XGB_BASE_PARAMS, "scale_pos_weight": final["scale_pos_weight"]},
    }
    window_params = {"window_sec": WINDOW_SEC, "window_group_cols": ["sample_id", "process_id"]}

    dataset_metadata["split"] = {
        "test_size": dataset.TEST_SIZE,
        "random_state": dataset.RANDOM_STATE,
        "per_source_train_test_counts": {
            name: {"train": len(final["train_splits"][name]), "test": len(final["test_splits"][name])}
            for name in final["train_splits"]
        },
    }
    dataset_metadata["class_imbalance_fix"] = {
        "tracker": "planning/class-imbalance-fix-progress.md",
        "method": "subsample_lidds_benign: bound LID-DS-2019/2021 benign rows' share of "
        "the pooled training pool via random (fixed random_state), proportional-across-"
        "sources subsampling, upstream of both compute_scale_pos_weight and RF's "
        "class_weight=balanced; excluded rows kept as a reported evaluation slice, not discarded",
        "candidate_shares_swept": CANDIDATE_LIDDS_BENIGN_SHARES,
        "chosen_share": CHOSEN_LIDDS_BENIGN_SHARE,
        "achieved_share": final["achieved_benign_share"],
        "lidds_kept_counts": final["kept_counts"],
        "lidds_excess_counts": final["excess_counts"],
        "sweep_summary": [
            {
                "target_benign_share": r["target_benign_share"],
                "achieved_benign_share": r["achieved_benign_share"],
                "apt_fpr": r["apt_fpr"],
                "en2025_benign_fpr": r["per_source_eval"]["en2025"]["false_positive_rate"],
                "lifecycle_recall": r["per_source_eval"]["lifecycle"]["recall"],
                "lidds_exploit_fpr": r["lidds_exploit_fpr"],
                "lidds_excess_benign_fpr": r["lidds_excess_benign_fpr"],
            }
            for r in sweep_results
        ],
    }
    dataset_metadata["evaluation"] = {
        "overall_pooled_test": final["overall_eval"],
        "per_source_test": final["per_source_eval"],
        "linux_apt_2024_validation_fpr": final["apt_fpr"],
        "linux_apt_2024_validation_n": final["apt_n"],
        "lidds_exploit_validation_fpr": final["lidds_exploit_fpr"],
        "lidds_exploit_validation_n": final["lidds_exploit_n"],
        "lidds_excess_benign_validation_fpr": final["lidds_excess_benign_fpr"],
        "lidds_excess_benign_validation_n": final["lidds_excess_benign_n"],
        "rf_feature_importance": final["rf_importance"],
        "xgb_feature_importance": final["xgb_importance"],
    }

    version = registry.save(
        rf_model=final["rf"],
        xgb_model=final["xgb"],
        ensemble_config=ensemble_config,
        dataset_metadata=dataset_metadata,
        window_params=window_params,
        hyperparameters=hyperparameters,
    )
    print(f"[train] saved model registry version {version} under {registry.root / version}")
    print(f"[train] full run metadata:\n{json.dumps(dataset_metadata, indent=2, default=str)}")


if __name__ == "__main__":
    main()
