from __future__ import annotations

import hashlib
import json
import math
import platform
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from .features import feature_names
from .training import (
    CANDIDATE_MODELS,
    _load_rows,
    _select_threshold,
    _workload_from_run_id,
    assign_run_splits,
    build_candidate_model,
)

CONFIDENCE = 0.95
SECONDS_PER_DAY = 86_400.0
VALIDATION_SHARE = 0.15
INCIDENT_GAP_SECONDS = 60.0
PROCESS_CONCENTRATION_FEATURES = ("max_pid_share", "unique_processes", "unique_pids")
ENCRYPTION_SCENARIOS = ("asymmetric", "aes", "salsa20")
ILLUSTRATIVE_PREVALENCES = (0.01, 0.001, 0.0001)


def exact_proportion_bounds(
    successes: int,
    trials: int,
    confidence: float = CONFIDENCE,
) -> dict[str, float | None]:
    """One-sided exact (Clopper-Pearson) lower and upper bounds of a proportion."""
    if trials <= 0:
        return {"lower": None, "upper": None}
    if not 0 <= successes <= trials:
        raise ValueError("successes must lie between 0 and trials")
    from scipy.stats import beta

    alpha = 1.0 - confidence
    lower = (
        0.0
        if successes == 0
        else float(beta.ppf(alpha, successes, trials - successes + 1))
    )
    upper = (
        1.0
        if successes == trials
        else float(beta.ppf(confidence, successes + 1, trials - successes))
    )
    return {"lower": lower, "upper": upper}


def poisson_rate_upper(
    events: int,
    exposure: float,
    confidence: float = CONFIDENCE,
) -> float | None:
    """One-sided exact upper bound of an event rate per unit of exposure."""
    if exposure <= 0:
        return None
    from scipy.stats import chi2

    return float(chi2.ppf(confidence, 2 * (events + 1)) / 2.0 / exposure)


def zero_event_exposure(rate: float, confidence: float = CONFIDENCE) -> float:
    """Exposure after which zero observed events bound the rate by ``rate``."""
    if rate <= 0:
        raise ValueError("rate must be positive")
    return -math.log(1.0 - confidence) / rate


def assign_cv_folds(
    run_labels: dict[str, str],
    *,
    folds: int = 5,
    repetition: int = 0,
    seed: int = 321,
) -> dict[str, int]:
    """Assign every run to one class-stratified fold for one CV repetition."""
    if folds < 2:
        raise ValueError("At least two folds are required")
    grouped: dict[str, list[str]] = defaultdict(list)
    for run_id, label in run_labels.items():
        grouped[label].append(run_id)
    assignments: dict[str, int] = {}
    for label, run_ids in sorted(grouped.items()):
        if len(run_ids) < folds:
            raise ValueError(f"Class {label!r} has fewer runs than folds")
        ordered = sorted(run_ids)
        random.Random(f"{seed}:cv:{repetition}:{label}").shuffle(ordered)
        for index, run_id in enumerate(ordered):
            assignments[run_id] = index % folds
    return assignments


def encryption_scenario(run_id: str) -> str | None:
    """Encryption scenario encoded in a Lifecycle ransomware trace name."""
    name = run_id.rsplit("__", 1)[-1].lower()
    if name.startswith("asymm"):
        return "asymmetric"
    if name.startswith("symm_aes"):
        return "aes"
    if name.startswith("symm_salsa20"):
        return "salsa20"
    return None


def count_incidents(
    windows: Sequence[dict[str, Any]],
    gap_seconds: float = INCIDENT_GAP_SECONDS,
) -> int:
    """Count alert groups; alerts at most ``gap_seconds`` apart form one incident."""
    incidents = 0
    last_alert_end: float | None = None
    for window in sorted(windows, key=lambda item: item["start"]):
        if not _is_alert(window):
            continue
        if last_alert_end is None or window["start"] - last_alert_end > gap_seconds:
            incidents += 1
        last_alert_end = window["end"]
    return incidents


def select_margin_threshold(y_true: Any, probabilities: Any) -> float:
    """Apply the validation rule, but take the median of tied best thresholds.

    The primary rule keeps the lowest tied threshold, which on perfectly
    separated validation data sits just above the highest benign probability.
    """
    import numpy as np

    y_true = np.asarray(y_true)
    probabilities = np.asarray(probabilities, dtype=float)
    candidates = np.asarray(
        sorted(
            set(np.linspace(0.01, 0.99, 99).tolist())
            | set(float(value) for value in probabilities)
        )
    )
    predicted = probabilities[None, :] >= candidates[:, None]
    positive = y_true[None, :] == 1
    tp = (predicted & positive).sum(axis=1)
    fp = (predicted & ~positive).sum(axis=1)
    fn = (~predicted & positive).sum(axis=1)
    tn = (~predicted & ~positive).sum(axis=1)
    precision = np.where(tp + fp > 0, tp / np.maximum(tp + fp, 1), 0.0)
    recall = np.where(tp + fn > 0, tp / np.maximum(tp + fn, 1), 0.0)
    total = precision + recall
    f1 = np.where(total > 0, 2 * precision * recall / np.where(total > 0, total, 1), 0.0)
    fpr = fp / np.maximum(fp + tn, 1)
    feasible = (precision >= 0.90) & (fpr < 0.02)
    pool = np.flatnonzero(feasible) if feasible.any() else np.arange(len(candidates))
    keys = [(f1[i], recall[i], precision[i], -fpr[i]) for i in pool]
    best = max(keys)
    tied = [index for index, key in zip(pool, keys) if key == best]
    return float(np.median(candidates[tied]))


def precision_at_prevalence(
    recall: float,
    false_positive_rate: float,
    prevalence: float,
) -> float | None:
    detected = recall * prevalence
    denominator = detected + false_positive_rate * (1.0 - prevalence)
    return detected / denominator if denominator else None


def cross_validate(
    rows: list[dict[str, Any]],
    names: Sequence[str],
    *,
    repetitions: int = 10,
    folds: int = 5,
    seed: int = 321,
    model_names: Sequence[str] = CANDIDATE_MODELS,
    incident_gap_seconds: float = INCIDENT_GAP_SECONDS,
    explain_errors_of: str | None = None,
) -> dict[str, Any]:
    """Repeated class-stratified CV in which no run crosses train/validation/test."""
    from sklearn.metrics import average_precision_score, brier_score_loss

    if repetitions < 1:
        raise ValueError("At least one repetition is required")
    run_labels = _run_labels(rows)
    validation_fraction = VALIDATION_SHARE / (1.0 - 1.0 / folds)
    rules = {"primary": "threshold", "margin": "margin_threshold"}
    repetition_reports: dict[tuple[str, str], list[dict[str, Any]]] = {
        (name, rule): [] for name in model_names for rule in rules
    }
    error_examples: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        fold_of = assign_cv_folds(
            run_labels, folds=folds, repetition=repetition, seed=seed
        )
        scored: dict[tuple[str, str], list[dict[str, Any]]] = {
            key: [] for key in repetition_reports
        }
        fold_details: dict[tuple[str, str], list[dict[str, Any]]] = {
            key: [] for key in repetition_reports
        }
        for fold in range(folds):
            test_runs = {run_id for run_id, value in fold_of.items() if value == fold}
            validation_runs = _stratified_sample(
                run_labels,
                sorted(set(run_labels) - test_runs),
                fraction=validation_fraction,
                salt=f"{seed}:cv:{repetition}:{fold}",
            )
            split_rows: dict[str, list[dict[str, Any]]] = {
                "train": [],
                "validation": [],
                "test": [],
            }
            for row in rows:
                run_id = str(row["run_id"])
                if run_id in test_runs:
                    split_rows["test"].append(row)
                elif run_id in validation_runs:
                    split_rows["validation"].append(row)
                else:
                    split_rows["train"].append(row)
            fitted = _fit_candidates(split_rows, names, model_names, seed)
            y_test = _labels(split_rows["test"])
            for name, result in fitted.items():
                probabilities = result["scores"]["test"]
                pr_auc = float(average_precision_score(y_test, probabilities))
                brier = float(brier_score_loss(y_test, probabilities))
                for rule, field in rules.items():
                    scored[(name, rule)].extend(
                        _scored_windows(split_rows["test"], probabilities, result[field])
                    )
                    fold_details[(name, rule)].append(
                        {
                            "fold": fold,
                            "threshold": result[field],
                            "pr_auc": pr_auc,
                            "brier_score": brier,
                        }
                    )
                if repetition == 0 and name == explain_errors_of:
                    error_examples.extend(
                        _explain_errors(
                            result["model"],
                            split_rows["test"],
                            probabilities,
                            result["threshold"],
                            names,
                            fold,
                        )
                    )
        for key, reports in repetition_reports.items():
            reports.append(
                _summarise_repetition(
                    scored[key], fold_details[key], incident_gap_seconds
                )
            )
    report: dict[str, Any] = {
        "method": (
            f"{repetitions} repetitions of {folds}-fold class-stratified "
            "cross-validation by run_id. In each fold the test fold is held out, "
            "about 15% of all runs are drawn from the remainder for validation "
            "and threshold selection, and the rest is used for training. Every "
            "run is tested exactly once per repetition."
        ),
        "threshold_rules": {
            "primary": "validation rule used for the served model (lowest tied threshold)",
            "margin": "same validation rule, median of tied thresholds (comparison only)",
        },
        "features": list(names),
        "repetitions": repetitions,
        "folds": folds,
        "seed": seed,
        "incident_gap_seconds": incident_gap_seconds,
        "models": {
            name: {
                "summary": _aggregate(repetition_reports[(name, "primary")]),
                "per_repetition": [
                    _compact(report) for report in repetition_reports[(name, "primary")]
                ],
                "margin_threshold_rule": {
                    "summary": _aggregate(repetition_reports[(name, "margin")]),
                    "per_repetition": [
                        _compact(report)
                        for report in repetition_reports[(name, "margin")]
                    ],
                },
            }
            for name in model_names
        },
    }
    if explain_errors_of is not None:
        report["error_explanations"] = {
            "model": explain_errors_of,
            "repetition": 0,
            "threshold_rule": "primary",
            "leading_features": _leading_error_features(error_examples),
            "examples": error_examples,
        }
    return report


def leave_one_scenario_out(
    rows: list[dict[str, Any]],
    names: Sequence[str],
    *,
    seed: int = 321,
    model_names: Sequence[str] = CANDIDATE_MODELS,
) -> dict[str, Any]:
    """Train without one encryption scenario and test detection of that scenario."""
    run_labels = _run_labels(rows)
    assignments = assign_run_splits(run_labels, seed=seed)
    scenarios: dict[str, Any] = {}
    for scenario in ENCRYPTION_SCENARIOS:
        held_out = {
            run_id
            for run_id, label in run_labels.items()
            if label == "ransomware" and encryption_scenario(run_id) == scenario
        }
        if not held_out:
            continue
        split_rows: dict[str, list[dict[str, Any]]] = {
            "train": [],
            "validation": [],
            "test": [],
            "unseen": [],
        }
        for row in rows:
            run_id = str(row["run_id"])
            split_rows["unseen" if run_id in held_out else assignments[run_id]].append(
                row
            )
        fitted = _fit_candidates(split_rows, names, model_names, seed)
        models: dict[str, Any] = {}
        for name, result in fitted.items():
            models[name] = {
                **_scenario_result(split_rows, result, result["threshold"]),
                "margin_threshold_rule": _scenario_result(
                    split_rows, result, result["margin_threshold"]
                ),
            }
        scenarios[scenario] = {
            "held_out_runs": len(held_out),
            "held_out_windows": len(split_rows["unseen"]),
            "training_ransomware_runs": _count_runs(split_rows["train"], "ransomware"),
            "validation_ransomware_runs": _count_runs(
                split_rows["validation"], "ransomware"
            ),
            "models": models,
        }
    return {
        "method": (
            "Primary seed-321 run split; every run of the held-out encryption "
            "scenario is removed from training and validation and scored as "
            "unseen. Scenarios come from trace names: asymm, symm_AES_* and "
            "symm_Salsa20_*. The dataset does not identify ransomware families."
        ),
        "features": list(names),
        "scenarios": scenarios,
    }


def explanation_quality(
    artifact: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    seed: int = 321,
    top_ks: Sequence[int] = (1, 3, 5),
    random_draws: int = 20,
    timing_repeats: int = 5,
) -> dict[str, Any]:
    """Faithfulness, sparsity, stability and cost of TreeSHAP alert explanations."""
    import numpy as np
    import shap
    from scipy.stats import spearmanr

    names = list(artifact["feature_names"])
    model = artifact["model"]
    threshold = float(artifact["threshold"])
    assignments = assign_run_splits(_run_labels(rows), seed=seed)
    train_benign = [
        row
        for row in rows
        if assignments[str(row["run_id"])] == "train" and row["label"] == "benign"
    ]
    reference = np.median(_matrix(train_benign, names), axis=0)
    test_rows = [row for row in rows if assignments[str(row["run_id"])] == "test"]
    values = _matrix(test_rows, names)
    probabilities = model.predict_proba(values)[:, 1]

    explainer = shap.TreeExplainer(model)
    explanation = explainer(values)
    contributions = np.asarray(explanation.values)
    base_values = np.asarray(explanation.base_values)
    if contributions.ndim == 3:
        contributions = contributions[:, :, 1]
    if base_values.ndim == 2:
        base_values = base_values[:, 1]
    additivity_error = float(
        np.max(np.abs(base_values + contributions.sum(axis=1) - probabilities))
    )
    alerts = np.flatnonzero(probabilities >= threshold)
    if len(alerts) == 0:
        raise ValueError("The model raises no alert on the test split")

    rng = np.random.default_rng(seed)
    deletion: dict[str, Any] = {}
    for k in top_ks:
        explained_drops: list[float] = []
        explained_cleared = 0
        random_drops: list[float] = []
        random_cleared: list[float] = []
        for index in alerts:
            original = values[index]
            masked = original.copy()
            top = np.argsort(-contributions[index])[:k]
            masked[top] = reference[top]
            probability = float(model.predict_proba(masked[None, :])[0, 1])
            explained_drops.append(float(probabilities[index] - probability))
            explained_cleared += int(probability < threshold)
            controls = np.repeat(original[None, :], random_draws, axis=0)
            for control in controls:
                columns = rng.choice(len(names), size=k, replace=False)
                control[columns] = reference[columns]
            control_probabilities = model.predict_proba(controls)[:, 1]
            random_drops.append(
                float(np.mean(probabilities[index] - control_probabilities))
            )
            random_cleared.append(float(np.mean(control_probabilities < threshold)))
        deletion[f"top_{k}"] = {
            "mean_probability_drop_shap": float(np.mean(explained_drops)),
            "mean_probability_drop_random": float(np.mean(random_drops)),
            "alerts_cleared_shap": explained_cleared / len(alerts),
            "alerts_cleared_random": float(np.mean(random_cleared)),
        }

    magnitudes = -np.sort(-np.abs(contributions[alerts]), axis=1)
    totals = magnitudes.sum(axis=1)
    cumulative = np.cumsum(magnitudes, axis=1) / totals[:, None]
    features_for_80 = (cumulative < 0.8).sum(axis=1) + 1

    jaccard: list[float] = []
    rank_correlation: list[float] = []
    by_run: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(test_rows):
        by_run[str(row["run_id"])].append(index)
    for indices in by_run.values():
        ordered = sorted(indices, key=lambda index: float(test_rows[index]["start"]))
        for left, right in zip(ordered, ordered[1:]):
            left_top = set(np.argsort(-np.abs(contributions[left]))[:5].tolist())
            right_top = set(np.argsort(-np.abs(contributions[right]))[:5].tolist())
            jaccard.append(len(left_top & right_top) / len(left_top | right_top))
            rho = float(spearmanr(contributions[left], contributions[right])[0])
            if not math.isnan(rho):
                rank_correlation.append(rho)

    prediction_ms: list[float] = []
    shap_ms: list[float] = []
    model.predict_proba(values[alerts[:1]])
    explainer(values[alerts[:1]])
    for index in alerts:
        vector = values[index : index + 1]
        for _ in range(timing_repeats):
            started = time.perf_counter()
            model.predict_proba(vector)
            predicted = time.perf_counter()
            explainer(vector)
            finished = time.perf_counter()
            prediction_ms.append((predicted - started) * 1000)
            shap_ms.append((finished - predicted) * 1000)

    return {
        "method": (
            "Served artifact on the seed-321 test split. Deletion test: the k "
            "features with the largest positive SHAP value are set to the median "
            "of training benign windows; the control sets k random features. A "
            "faithful explanation lowers the probability more than the control."
        ),
        "threshold": threshold,
        "test_windows": len(test_rows),
        "alerts": int(len(alerts)),
        "additivity_max_error": additivity_error,
        "deletion": deletion,
        "random_draws_per_alert": random_draws,
        "sparsity": {
            **{
                f"top{k}_share_of_abs_shap": _spread(cumulative[:, k - 1].tolist())
                for k in (3, 5, 8)
                if k <= len(names)
            },
            "features_for_80_percent_of_abs_shap": _spread(
                features_for_80.astype(float).tolist()
            ),
        },
        "stability_adjacent_windows": {
            "pairs": len(jaccard),
            "top5_jaccard": _spread(jaccard),
            "spearman_rank_correlation": _spread(rank_correlation),
        },
        "timing_ms_per_alert": {
            "prediction": _quantiles(prediction_ms),
            "shap": _quantiles(shap_ms),
            "repeats_per_alert": timing_repeats,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }


def false_alarm_projection(
    cross_validation: dict[str, Any],
    *,
    window_seconds: float = 5.0,
    target_incidents_per_day: float = 1.0,
    fpr_target: float = 0.02,
) -> dict[str, Any]:
    """Translate window FPR and incident rates into alerts per host-day."""
    windows_per_day = SECONDS_PER_DAY / window_seconds
    models = {
        name: {
            **_project_false_alarms(report["summary"], windows_per_day),
            "margin_threshold_rule": _project_false_alarms(
                report["margin_threshold_rule"]["summary"], windows_per_day
            ),
        }
        for name, report in cross_validation["models"].items()
    }
    return {
        "assumption": (
            f"one host scored on consecutive {window_seconds:g}-second windows "
            "for 24 hours; prevalences are illustrative shares of ransomware windows"
        ),
        "windows_per_host_day": windows_per_day,
        "alerts_per_host_day_allowed_by_fpr_target": fpr_target * windows_per_day,
        "target_false_incidents_per_host_day": target_incidents_per_day,
        "zero_incident_benign_hours_needed_for_target": zero_event_exposure(
            target_incidents_per_day / 24.0
        ),
        "models": models,
    }


def _project_false_alarms(
    summary: dict[str, Any], windows_per_day: float
) -> dict[str, Any]:
    recall = summary["window_level"]["recall"]["mean"]
    fpr = summary["window_level"]["false_positive_rate"]["mean"]
    fpr_upper = summary["least_favourable_bounds"]["window_false_positive_rate_upper"]
    return {
        "window_alerts_per_host_day": fpr * windows_per_day,
        "window_alerts_per_host_day_upper_bound": fpr_upper * windows_per_day,
        "false_incidents_per_host_day": summary["false_incidents_per_host_day"]["mean"],
        "false_incidents_per_host_day_upper_bound": summary[
            "false_incidents_per_host_day_upper_bound"
        ],
        "precision_at_prevalence": {
            str(prevalence): {
                "observed_fpr": precision_at_prevalence(recall, fpr, prevalence),
                "fpr_upper_bound": precision_at_prevalence(
                    recall, fpr_upper, prevalence
                ),
            }
            for prevalence in ILLUSTRATIVE_PREVALENCES
        },
    }


def evaluate_robustness(
    feature_path: Path,
    model_path: Path,
    output_directory: Path,
    *,
    seed: int = 321,
    repetitions: int = 10,
    folds: int = 5,
) -> dict[str, Any]:
    try:
        import joblib
    except ImportError as error:
        raise RuntimeError(
            "ML dependencies are missing; install with: pip install -e '.[ml]'"
        ) from error

    rows = _load_rows(feature_path)
    if not rows:
        raise ValueError(f"No feature rows found in {feature_path}")
    artifact = joblib.load(model_path)
    names = list(artifact["feature_names"])
    missing = sorted(set(names) - set(feature_names(rows[0])))
    if missing:
        raise ValueError(f"Feature file lacks model features: {missing}")
    reduced = [name for name in names if name not in PROCESS_CONCENTRATION_FEATURES]
    run_labels = _run_labels(rows)
    cross_validation = {
        "all_features": cross_validate(
            rows,
            names,
            repetitions=repetitions,
            folds=folds,
            seed=seed,
            explain_errors_of="random_forest",
        ),
        "without_process_concentration": cross_validate(
            rows,
            reduced,
            repetitions=repetitions,
            folds=folds,
            seed=seed,
            model_names=("random_forest",),
        ),
    }
    report = {
        "feature_file": str(feature_path),
        "rows": len(rows),
        "runs": {
            label: sum(value == label for value in run_labels.values())
            for label in sorted(set(run_labels.values()))
        },
        "model_artifact": str(model_path),
        "model_artifact_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "seed": seed,
        "confidence": CONFIDENCE,
        "bounds": (
            "One-sided exact bounds at the stated confidence: Clopper-Pearson for "
            "proportions, Poisson for incident rates. Windows of one run are "
            "correlated, so window-level bounds are optimistic; run-level bounds "
            "are the conservative reading."
        ),
        "excluded_process_concentration_features": list(
            PROCESS_CONCENTRATION_FEATURES
        ),
        "cross_validation": cross_validation,
        "leave_one_scenario_out": {
            "all_features": leave_one_scenario_out(rows, names, seed=seed),
            "without_process_concentration": leave_one_scenario_out(
                rows, reduced, seed=seed, model_names=("random_forest",)
            ),
        },
        "explanation_quality": explanation_quality(artifact, rows, seed=seed),
        "false_alarm_projection": false_alarm_projection(
            cross_validation["all_features"]
        ),
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    report_path = output_directory / "robustness.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _run_labels(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    return {str(row["run_id"]): str(row["label"]) for row in rows}


def _stratified_sample(
    run_labels: dict[str, str],
    run_ids: Sequence[str],
    *,
    fraction: float,
    salt: str,
) -> set[str]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for run_id in run_ids:
        grouped[run_labels[run_id]].append(run_id)
    selected: set[str] = set()
    for label, members in sorted(grouped.items()):
        ordered = sorted(members)
        random.Random(f"{salt}:{label}").shuffle(ordered)
        count = min(len(ordered) - 1, max(1, round(len(ordered) * fraction)))
        selected.update(ordered[:count])
    return selected


def _matrix(rows: Sequence[dict[str, Any]], names: Sequence[str]) -> Any:
    import numpy as np

    return np.asarray(
        [[float(row[name]) for name in names] for row in rows], dtype=float
    ).reshape(len(rows), len(names))


def _labels(rows: Sequence[dict[str, Any]]) -> Any:
    import numpy as np

    return np.asarray([1 if row["label"] == "ransomware" else 0 for row in rows])


def _fit_candidates(
    split_rows: dict[str, list[dict[str, Any]]],
    names: Sequence[str],
    model_names: Sequence[str],
    seed: int,
) -> dict[str, dict[str, Any]]:
    """Fit on train, select the threshold on validation and score other splits."""
    x_train = _matrix(split_rows["train"], names)
    y_train = _labels(split_rows["train"])
    positives = int(y_train.sum())
    scale_pos_weight = (len(y_train) - positives) / max(positives, 1)
    x_validation = _matrix(split_rows["validation"], names)
    y_validation = _labels(split_rows["validation"])
    fitted: dict[str, dict[str, Any]] = {}
    for name in model_names:
        model = build_candidate_model(
            name, seed=seed, scale_pos_weight=scale_pos_weight
        )
        model.fit(x_train, y_train)
        validation_probabilities = model.predict_proba(x_validation)[:, 1]
        fitted[name] = {
            "model": model,
            "threshold": float(
                _select_threshold(y_validation, validation_probabilities)["threshold"]
            ),
            "margin_threshold": select_margin_threshold(
                y_validation, validation_probabilities
            ),
            "scores": {
                split: (
                    [float(value) for value in model.predict_proba(_matrix(rows, names))[:, 1]]
                    if rows
                    else []
                )
                for split, rows in split_rows.items()
                if split not in ("train", "validation")
            },
        }
    return fitted


def _scored_windows(
    rows: Sequence[dict[str, Any]],
    probabilities: Sequence[float],
    threshold: float,
) -> list[dict[str, Any]]:
    return [
        {
            "run_id": str(row["run_id"]),
            "label": str(row["label"]),
            "start": float(row["start"]),
            "end": float(row["end"]),
            "probability": float(probability),
            "threshold": float(threshold),
        }
        for row, probability in zip(rows, probabilities)
    ]


def _is_alert(window: dict[str, Any]) -> bool:
    return window["probability"] >= window["threshold"]


def _group_runs(windows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for window in windows:
        runs[window["run_id"]].append(window)
    for members in runs.values():
        members.sort(key=lambda item: item["start"])
    return dict(runs)


def _count_runs(rows: Iterable[dict[str, Any]], label: str) -> int:
    return len({str(row["run_id"]) for row in rows if row["label"] == label})


def _rates(counts: dict[str, int]) -> dict[str, Any]:
    tn, fp, fn, tp = counts["tn"], counts["fp"], counts["fn"], counts["tp"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "mcc": (tp * tn - fp * fn) / denominator if denominator else 0.0,
        "precision_lower_bound": exact_proportion_bounds(tp, tp + fp)["lower"],
        "recall_lower_bound": exact_proportion_bounds(tp, tp + fn)["lower"],
        "false_positive_rate_upper_bound": exact_proportion_bounds(fp, fp + tn)[
            "upper"
        ],
        "confusion_matrix": dict(counts),
    }


def _summarise_repetition(
    scored: list[dict[str, Any]],
    fold_details: list[dict[str, Any]],
    incident_gap_seconds: float,
) -> dict[str, Any]:
    window_counts = {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
    for window in scored:
        alert = _is_alert(window)
        if window["label"] == "ransomware":
            window_counts["tp" if alert else "fn"] += 1
        else:
            window_counts["fp" if alert else "tn"] += 1

    run_counts = {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
    workloads: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "runs": 0,
            "runs_with_alert": 0,
            "windows": 0,
            "false_positives": 0,
            "false_incidents": 0,
        }
    )
    first_alert_seconds: list[float] = []
    first_window_detections = 0
    benign_seconds = 0.0
    false_incidents = 0
    alerted_benign_runs: list[str] = []
    missed_ransomware_runs: list[str] = []
    for run_id, windows in sorted(_group_runs(scored).items()):
        alerts = [window for window in windows if _is_alert(window)]
        if windows[0]["label"] == "ransomware":
            if alerts:
                run_counts["tp"] += 1
                first_alert_seconds.append(alerts[0]["end"] - windows[0]["start"])
                first_window_detections += int(_is_alert(windows[0]))
            else:
                run_counts["fn"] += 1
                missed_ransomware_runs.append(run_id)
            continue
        run_counts["fp" if alerts else "tn"] += 1
        if alerts:
            alerted_benign_runs.append(run_id)
        incidents = count_incidents(windows, incident_gap_seconds)
        workload = workloads[_workload_from_run_id(run_id)]
        workload["runs"] += 1
        workload["runs_with_alert"] += int(bool(alerts))
        workload["windows"] += len(windows)
        workload["false_positives"] += len(alerts)
        workload["false_incidents"] += incidents
        false_incidents += incidents
        benign_seconds += sum(window["end"] - window["start"] for window in windows)

    ransomware_runs = run_counts["tp"] + run_counts["fn"]
    incident_upper = poisson_rate_upper(false_incidents, benign_seconds)
    return {
        "window_level": _rates(window_counts),
        "run_level": _rates(run_counts),
        "benign_workloads": {
            name: {
                **values,
                "false_positive_rate": values["false_positives"] / values["windows"],
                "false_positive_rate_upper_bound": exact_proportion_bounds(
                    values["false_positives"], values["windows"]
                )["upper"],
                "run_false_positive_rate": values["runs_with_alert"] / values["runs"],
            }
            for name, values in sorted(workloads.items())
        },
        "false_incidents": {
            "count": false_incidents,
            "benign_hours": benign_seconds / 3600.0,
            "per_host_day": (
                false_incidents / benign_seconds * SECONDS_PER_DAY
                if benign_seconds
                else None
            ),
            "per_host_day_upper_bound": (
                incident_upper * SECONDS_PER_DAY if incident_upper is not None else None
            ),
        },
        "time_to_first_alert": {
            "ransomware_runs": ransomware_runs,
            "detected_in_first_window": first_window_detections,
            "max_seconds": max(first_alert_seconds, default=None),
        },
        "alerted_benign_runs": alerted_benign_runs,
        "missed_ransomware_runs": missed_ransomware_runs,
        "folds": fold_details,
    }


def _aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    window = [report["window_level"] for report in reports]
    run = [report["run_level"] for report in reports]
    folds = [fold for report in reports for fold in report["folds"]]
    workloads = sorted({name for report in reports for name in report["benign_workloads"]})
    return {
        "window_level": {
            metric: _spread([values[metric] for values in window])
            for metric in ("precision", "recall", "f1", "false_positive_rate", "mcc")
        },
        "run_level": {
            metric: _spread([values[metric] for values in run])
            for metric in ("precision", "recall", "false_positive_rate")
        },
        "least_favourable_bounds": {
            "window_precision_lower": _minimum(
                values["precision_lower_bound"] for values in window
            ),
            "window_recall_lower": _minimum(
                values["recall_lower_bound"] for values in window
            ),
            "window_false_positive_rate_upper": _maximum(
                values["false_positive_rate_upper_bound"] for values in window
            ),
            "run_recall_lower": _minimum(values["recall_lower_bound"] for values in run),
            "run_false_positive_rate_upper": _maximum(
                values["false_positive_rate_upper_bound"] for values in run
            ),
        },
        "errors_per_repetition": {
            "false_positive_windows": _spread(
                [values["confusion_matrix"]["fp"] for values in window]
            ),
            "false_negative_windows": _spread(
                [values["confusion_matrix"]["fn"] for values in window]
            ),
            "alerted_benign_runs": _spread(
                [values["confusion_matrix"]["fp"] for values in run]
            ),
            "missed_ransomware_runs": _spread(
                [values["confusion_matrix"]["fn"] for values in run]
            ),
        },
        "benign_workloads": {
            name: {
                "runs": reports[0]["benign_workloads"].get(name, {}).get("runs"),
                "windows": reports[0]["benign_workloads"].get(name, {}).get("windows"),
                "false_positive_rate": _spread(
                    [
                        report["benign_workloads"][name]["false_positive_rate"]
                        for report in reports
                        if name in report["benign_workloads"]
                    ]
                ),
                "false_positive_rate_upper_bound": _maximum(
                    report["benign_workloads"][name]["false_positive_rate_upper_bound"]
                    for report in reports
                    if name in report["benign_workloads"]
                ),
                "run_false_positive_rate": _spread(
                    [
                        report["benign_workloads"][name]["run_false_positive_rate"]
                        for report in reports
                        if name in report["benign_workloads"]
                    ]
                ),
            }
            for name in workloads
        },
        "false_incidents_per_host_day": _spread(
            [report["false_incidents"]["per_host_day"] for report in reports]
        ),
        "false_incidents_per_host_day_upper_bound": _maximum(
            report["false_incidents"]["per_host_day_upper_bound"] for report in reports
        ),
        "benign_hours_per_repetition": reports[0]["false_incidents"]["benign_hours"],
        "ransomware_runs_detected_in_first_window": _spread(
            [
                report["time_to_first_alert"]["detected_in_first_window"]
                / report["time_to_first_alert"]["ransomware_runs"]
                for report in reports
                if report["time_to_first_alert"]["ransomware_runs"]
            ]
        ),
        "max_seconds_to_first_alert": _maximum(
            report["time_to_first_alert"]["max_seconds"] for report in reports
        ),
        "fold_pr_auc": _spread([fold["pr_auc"] for fold in folds]),
        "fold_brier_score": _spread([fold["brier_score"] for fold in folds]),
        "fold_threshold": _spread([fold["threshold"] for fold in folds]),
    }


def _compact(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "window_confusion_matrix": report["window_level"]["confusion_matrix"],
        "run_confusion_matrix": report["run_level"]["confusion_matrix"],
        "false_incidents": report["false_incidents"]["count"],
        "alerted_benign_runs": report["alerted_benign_runs"],
        "missed_ransomware_runs": report["missed_ransomware_runs"],
        "fold_thresholds": [fold["threshold"] for fold in report["folds"]],
    }


def _explain_errors(
    model: Any,
    rows: Sequence[dict[str, Any]],
    probabilities: Sequence[float],
    threshold: float,
    names: Sequence[str],
    fold: int,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    import numpy as np
    import shap

    errors = [
        index
        for index, (row, probability) in enumerate(zip(rows, probabilities))
        if (probability >= threshold) != (row["label"] == "ransomware")
    ]
    if not errors:
        return []
    values = _matrix([rows[index] for index in errors], names)
    contributions = np.asarray(shap.TreeExplainer(model)(values).values)
    if contributions.ndim == 3:
        contributions = contributions[:, :, 1]
    examples = []
    for position, index in enumerate(errors):
        row = rows[index]
        run_id = str(row["run_id"])
        benign = row["label"] == "benign"
        order = np.argsort(-np.abs(contributions[position]))[:top_k]
        examples.append(
            {
                "type": "false_positive" if benign else "false_negative",
                "run_id": run_id,
                "group": (
                    _workload_from_run_id(run_id) if benign else encryption_scenario(run_id)
                ),
                "fold": fold,
                "start": float(row["start"]),
                "probability": float(probabilities[index]),
                "threshold": float(threshold),
                "top_contributors": [
                    {
                        "feature": names[feature_index],
                        "value": float(values[position, feature_index]),
                        "shap_value": float(contributions[position, feature_index]),
                    }
                    for feature_index in order
                ],
            }
        )
    return examples


def _leading_error_features(examples: list[dict[str, Any]]) -> dict[str, Any]:
    """Count features among the top three pushing each error the wrong way."""
    leading: dict[str, dict[str, int]] = {
        "false_positive": defaultdict(int),
        "false_negative": defaultdict(int),
    }
    totals = {"false_positive": 0, "false_negative": 0}
    for example in examples:
        kind = example["type"]
        totals[kind] += 1
        wrong_way = [
            item
            for item in example["top_contributors"]
            if (item["shap_value"] > 0) == (kind == "false_positive")
        ]
        for item in wrong_way[:3]:
            leading[kind][item["feature"]] += 1
    return {
        kind: {
            "windows": totals[kind],
            "features": dict(
                sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ),
        }
        for kind, counts in leading.items()
    }


def _scenario_result(
    split_rows: dict[str, list[dict[str, Any]]],
    result: dict[str, Any],
    threshold: float,
) -> dict[str, Any]:
    test = _scored_windows(split_rows["test"], result["scores"]["test"], threshold)
    return {
        "threshold": threshold,
        "unseen_scenario": _detection_summary(
            _scored_windows(split_rows["unseen"], result["scores"]["unseen"], threshold)
        ),
        "seen_scenarios_test": _detection_summary(
            [window for window in test if window["label"] == "ransomware"]
        ),
        "benign_test": _false_alarm_summary(
            [window for window in test if window["label"] == "benign"]
        ),
    }


def _detection_summary(windows: list[dict[str, Any]]) -> dict[str, Any]:
    import numpy as np

    runs = _group_runs(windows)
    detected_windows = sum(_is_alert(window) for window in windows)
    detected_runs = sum(any(_is_alert(window) for window in run) for run in runs.values())
    return {
        "windows": len(windows),
        "detected_windows": detected_windows,
        "window_recall": detected_windows / len(windows) if windows else None,
        "window_recall_lower_bound": exact_proportion_bounds(
            detected_windows, len(windows)
        )["lower"],
        "runs": len(runs),
        "detected_runs": detected_runs,
        "run_recall": detected_runs / len(runs) if runs else None,
        "run_recall_lower_bound": exact_proportion_bounds(detected_runs, len(runs))[
            "lower"
        ],
        "median_probability": (
            float(np.median([window["probability"] for window in windows]))
            if windows
            else None
        ),
    }


def _false_alarm_summary(windows: list[dict[str, Any]]) -> dict[str, Any]:
    runs = _group_runs(windows)
    false_positives = sum(_is_alert(window) for window in windows)
    alerted_runs = sum(any(_is_alert(window) for window in run) for run in runs.values())
    return {
        "windows": len(windows),
        "false_positive_windows": false_positives,
        "false_positive_rate": false_positives / len(windows) if windows else None,
        "false_positive_rate_upper_bound": exact_proportion_bounds(
            false_positives, len(windows)
        )["upper"],
        "runs": len(runs),
        "alerted_runs": alerted_runs,
        "run_false_positive_rate": alerted_runs / len(runs) if runs else None,
        "run_false_positive_rate_upper_bound": exact_proportion_bounds(
            alerted_runs, len(runs)
        )["upper"],
    }


def _spread(values: Sequence[float | None]) -> dict[str, float] | None:
    present = [float(value) for value in values if value is not None]
    if not present:
        return None
    return {
        "mean": sum(present) / len(present),
        "min": min(present),
        "max": max(present),
    }


def _quantiles(values: Sequence[float]) -> dict[str, float]:
    import numpy as np

    return {
        "median": float(np.median(values)),
        "p95": float(np.quantile(values, 0.95)),
    }


def _minimum(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def _maximum(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None
