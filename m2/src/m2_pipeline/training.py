from __future__ import annotations

import json
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .features import feature_names


def assign_run_splits(
    run_labels: dict[str, str],
    *,
    seed: int = 321,
    train_ratio: float = 0.70,
    validation_ratio: float = 0.15,
) -> dict[str, str]:
    """Create deterministic, class-stratified splits at independent-run level."""
    grouped: dict[str, list[str]] = defaultdict(list)
    for run_id, label in run_labels.items():
        grouped[label].append(run_id)

    assignments: dict[str, str] = {}
    for label, run_ids in sorted(grouped.items()):
        ordered = sorted(run_ids)
        random.Random(f"{seed}:{label}").shuffle(ordered)
        count = len(ordered)
        train_end = max(1, round(count * train_ratio))
        validation_count = max(1, round(count * validation_ratio))
        validation_end = min(count - 1, train_end + validation_count)
        train_end = min(train_end, validation_end - 1)
        for index, run_id in enumerate(ordered):
            if index < train_end:
                split = "train"
            elif index < validation_end:
                split = "validation"
            else:
                split = "test"
            assignments[run_id] = split
    return assignments


def train_models(
    feature_path: Path,
    output_directory: Path,
    *,
    seed: int = 321,
    exclude_features: tuple[str, ...] = (),
) -> dict[str, Any]:
    try:
        import joblib
        import numpy as np
        import shap
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (
            accuracy_score,
            average_precision_score,
            brier_score_loss,
            confusion_matrix,
            f1_score,
            matthews_corrcoef,
            precision_score,
            recall_score,
            roc_auc_score,
        )
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from xgboost import XGBClassifier
    except ImportError as error:
        raise RuntimeError(
            "ML dependencies are missing; install with: pip install -e '.[ml]'"
        ) from error

    rows = _load_rows(feature_path)
    if not rows:
        raise ValueError(f"No feature rows found in {feature_path}")
    available_names = feature_names(rows[0])
    unknown_exclusions = sorted(set(exclude_features) - set(available_names))
    if unknown_exclusions:
        raise ValueError(f"Unknown excluded features: {unknown_exclusions}")
    names = [name for name in available_names if name not in exclude_features]
    if not names:
        raise ValueError("Ablation excluded every feature")
    run_labels = {str(row["run_id"]): str(row["label"]) for row in rows}
    assignments = assign_run_splits(run_labels, seed=seed)

    arrays: dict[str, tuple[Any, Any]] = {}
    split_run_counts: dict[str, dict[str, int]] = {}
    for split in ("train", "validation", "test"):
        selected = [row for row in rows if assignments[str(row["run_id"])] == split]
        arrays[split] = (
            np.asarray([[float(row[name]) for name in names] for row in selected]),
            np.asarray([1 if row["label"] == "ransomware" else 0 for row in selected]),
        )
        run_ids = {str(row["run_id"]) for row in selected}
        split_run_counts[split] = {
            "total": len(run_ids),
            "benign": sum(run_labels[run_id] == "benign" for run_id in run_ids),
            "ransomware": sum(
                run_labels[run_id] == "ransomware" for run_id in run_ids
            ),
        }

    x_train, y_train = arrays["train"]
    positives = int(y_train.sum())
    negatives = len(y_train) - positives
    scale_pos_weight = negatives / max(positives, 1)
    models = {
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(
                class_weight="balanced",
                max_iter=2000,
                random_state=seed,
            ),
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=400,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        ),
        "xgboost": XGBClassifier(
            n_estimators=350,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=2.0,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            n_jobs=-1,
            random_state=seed,
        ),
    }

    output_directory.mkdir(parents=True, exist_ok=True)
    model_reports: dict[str, Any] = {}
    for name, model in models.items():
        model.fit(x_train, y_train)
        validation_probabilities = model.predict_proba(arrays["validation"][0])[:, 1]
        threshold_report = _select_threshold(
            arrays["validation"][1], validation_probabilities
        )
        threshold = threshold_report["threshold"]
        validation_metrics = _metrics(
            arrays["validation"][1],
            validation_probabilities,
            threshold,
            accuracy_score=accuracy_score,
            average_precision_score=average_precision_score,
            brier_score_loss=brier_score_loss,
            confusion_matrix=confusion_matrix,
            f1_score=f1_score,
            matthews_corrcoef=matthews_corrcoef,
            precision_score=precision_score,
            recall_score=recall_score,
            roc_auc_score=roc_auc_score,
        )
        test_probabilities = model.predict_proba(arrays["test"][0])[:, 1]
        test_metrics = _metrics(
            arrays["test"][1],
            test_probabilities,
            threshold,
            accuracy_score=accuracy_score,
            average_precision_score=average_precision_score,
            brier_score_loss=brier_score_loss,
            confusion_matrix=confusion_matrix,
            f1_score=f1_score,
            matthews_corrcoef=matthews_corrcoef,
            precision_score=precision_score,
            recall_score=recall_score,
            roc_auc_score=roc_auc_score,
        )
        importance = _feature_importance(model, names)
        test_rows = [
            row for row in rows if assignments[str(row["run_id"])] == "test"
        ]
        artifact = {
            "model": model,
            "threshold": threshold,
            "feature_names": names,
            "feature_version": rows[0]["feature_version"],
        }
        artifact_path = output_directory / f"{name}.joblib"
        joblib.dump(artifact, artifact_path)
        model_reports[name] = {
            "artifact": str(artifact_path),
            "threshold_selection": threshold_report,
            "validation": validation_metrics,
            "test": test_metrics,
            "test_run_level": _run_level_metrics(
                test_rows,
                test_probabilities,
                threshold,
                accuracy_score=accuracy_score,
                average_precision_score=average_precision_score,
                brier_score_loss=brier_score_loss,
                confusion_matrix=confusion_matrix,
                f1_score=f1_score,
                matthews_corrcoef=matthews_corrcoef,
                precision_score=precision_score,
                recall_score=recall_score,
                roc_auc_score=roc_auc_score,
            ),
            "test_benign_workloads": _benign_workload_metrics(
                test_rows, test_probabilities, threshold
            ),
            "inference_latency_ms_per_window": _inference_latency(
                model, arrays["test"][0], np
            ),
            "top_features": importance[:15],
        }

    selected_model = max(
        model_reports,
        key=lambda name: _selection_key(model_reports[name]["validation"]),
    )
    selected_artifact = joblib.load(output_directory / f"{selected_model}.joblib")
    test_rows = [row for row in rows if assignments[str(row["run_id"])] == "test"]
    explainability = _shap_report(
        selected_artifact["model"],
        arrays["test"][0],
        arrays["test"][1],
        test_rows,
        selected_artifact["threshold"],
        names,
        shap,
        np,
    )
    explainability_path = output_directory / "explainability.json"
    explainability_path.write_text(
        json.dumps(explainability, indent=2) + "\n", encoding="utf-8"
    )
    univariate_separation = _univariate_separation(
        rows, names, roc_auc_score, np
    )
    report = {
        "feature_file": str(feature_path),
        "rows": len(rows),
        "features": names,
        "excluded_features": list(exclude_features),
        "seed": seed,
        "split_method": (
            "deterministic class-stratified 70/15/15 assignment by run_id; "
            "no window from a run crosses splits"
        ),
        "split_runs": split_run_counts,
        "selection_policy": (
            "Select on validation only: models meeting precision >= 0.90 and "
            "FPR < 0.02 rank first, then F1, PR-AUC and recall."
        ),
        "selected_model": selected_model,
        "explainability": str(explainability_path),
        "dataset_shortcut_audit": {
            "top_univariate_features": univariate_separation[:10],
            "warning": (
                "Near-perfect held-out results and highly separating individual "
                "features may reflect collection/scenario artifacts. External "
                "IRDP hard-benign validation is required before deployment."
            ),
        },
        "models": model_reports,
    }
    report_path = output_directory / "evaluation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _select_threshold(y_true: Any, probabilities: Any) -> dict[str, Any]:
    import numpy as np
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

    candidates = sorted(
        set(np.linspace(0.01, 0.99, 99).tolist())
        | set(float(value) for value in probabilities)
    )
    evaluated: list[dict[str, float]] = []
    for threshold in candidates:
        predictions = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(
            y_true, predictions, labels=[0, 1]
        ).ravel()
        evaluated.append(
            {
                "threshold": float(threshold),
                "precision": float(
                    precision_score(y_true, predictions, zero_division=0)
                ),
                "recall": float(recall_score(y_true, predictions, zero_division=0)),
                "f1": float(f1_score(y_true, predictions, zero_division=0)),
                "fpr": float(fp / max(fp + tn, 1)),
            }
        )
    feasible = [
        row for row in evaluated if row["precision"] >= 0.90 and row["fpr"] < 0.02
    ]
    pool = feasible or evaluated
    selected = max(
        pool,
        key=lambda row: (row["f1"], row["recall"], row["precision"], -row["fpr"]),
    )
    return {
        **selected,
        "constraints_met": bool(feasible),
        "criterion": "validation precision >= 0.90 and FPR < 0.02, then max F1",
    }


def _metrics(y_true: Any, probabilities: Any, threshold: float, **metrics: Any) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = metrics["confusion_matrix"](
        y_true, predictions, labels=[0, 1]
    ).ravel()
    return {
        "accuracy": float(metrics["accuracy_score"](y_true, predictions)),
        "precision": float(
            metrics["precision_score"](y_true, predictions, zero_division=0)
        ),
        "recall": float(
            metrics["recall_score"](y_true, predictions, zero_division=0)
        ),
        "f1": float(metrics["f1_score"](y_true, predictions, zero_division=0)),
        "pr_auc": float(metrics["average_precision_score"](y_true, probabilities)),
        "roc_auc": float(metrics["roc_auc_score"](y_true, probabilities)),
        "mcc": float(metrics["matthews_corrcoef"](y_true, predictions)),
        "brier_score": float(metrics["brier_score_loss"](y_true, probabilities)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": float(threshold),
    }


def _selection_key(validation: dict[str, Any]) -> tuple:
    safe = validation["precision"] >= 0.90 and validation["false_positive_rate"] < 0.02
    return (
        safe,
        validation["f1"],
        validation["pr_auc"],
        validation["recall"],
    )


def _feature_importance(model: Any, names: list[str]) -> list[dict[str, float]]:
    estimator = model.steps[-1][1] if hasattr(model, "steps") else model
    if hasattr(estimator, "feature_importances_"):
        values = estimator.feature_importances_
    elif hasattr(estimator, "coef_"):
        values = abs(estimator.coef_[0])
    else:
        return []
    pairs = sorted(zip(names, values), key=lambda item: float(item[1]), reverse=True)
    return [{"feature": name, "importance": float(value)} for name, value in pairs]


def _run_level_metrics(
    rows: list[dict[str, Any]],
    probabilities: Any,
    threshold: float,
    **metrics: Any,
) -> dict[str, Any]:
    import numpy as np

    grouped: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row, probability in zip(rows, probabilities):
        label = 1 if row["label"] == "ransomware" else 0
        grouped[str(row["run_id"])].append((label, float(probability)))
    y_true = np.asarray([values[0][0] for values in grouped.values()])
    # A run is detected when any one of its windows crosses the threshold.
    y_probability = np.asarray(
        [max(probability for _, probability in values) for values in grouped.values()]
    )
    return _metrics(y_true, y_probability, threshold, **metrics)


def _benign_workload_metrics(
    rows: list[dict[str, Any]],
    probabilities: Any,
    threshold: float,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"windows": 0, "false_positives": 0, "runs": set()}
    )
    for row, probability in zip(rows, probabilities):
        if row["label"] != "benign":
            continue
        workload = _workload_from_run_id(str(row["run_id"]))
        grouped[workload]["windows"] += 1
        grouped[workload]["runs"].add(str(row["run_id"]))
        if probability >= threshold:
            grouped[workload]["false_positives"] += 1
    result: dict[str, dict[str, Any]] = {}
    for workload, values in sorted(grouped.items()):
        result[workload] = {
            "runs": len(values["runs"]),
            "windows": values["windows"],
            "false_positives": values["false_positives"],
            "false_positive_rate": (
                values["false_positives"] / max(values["windows"], 1)
            ),
        }
    return result


def _workload_from_run_id(run_id: str) -> str:
    lowered = run_id.lower()
    for workload in (
        "browser",
        "compression",
        "filebench",
        "idle",
        "mediaserver",
        "spec",
    ):
        if lowered.startswith(workload):
            return workload
    return "other"


def _inference_latency(model: Any, values: Any, np: Any) -> dict[str, float]:
    if len(values) == 0:
        return {"median": 0.0, "p95": 0.0}
    sample = values[: min(len(values), 512)]
    model.predict_proba(sample[:1])
    timings = []
    for _ in range(20):
        started = time.perf_counter()
        model.predict_proba(sample)
        timings.append((time.perf_counter() - started) * 1000 / len(sample))
    return {
        "median": float(np.median(timings)),
        "p95": float(np.quantile(timings, 0.95)),
    }


def _shap_report(
    model: Any,
    values: Any,
    labels: Any,
    rows: list[dict[str, Any]],
    threshold: float,
    names: list[str],
    shap: Any,
    np: Any,
) -> dict[str, Any]:
    limit = min(len(values), 500)
    sample = values[:limit]
    sample_labels = labels[:limit]
    sample_rows = rows[:limit]
    probabilities = model.predict_proba(sample)[:, 1]
    estimator = model.steps[-1][1] if hasattr(model, "steps") else model
    if hasattr(model, "steps") and hasattr(estimator, "coef_"):
        transformed = model[:-1].transform(sample)
        explanation = shap.LinearExplainer(estimator, transformed)(transformed)
        method = "LinearSHAP on held-out test windows"
    else:
        explanation = shap.TreeExplainer(model)(sample)
        method = "TreeSHAP on held-out test windows"
    shap_values = np.asarray(explanation.values)
    if shap_values.ndim == 3:
        shap_values = shap_values[:, :, 1]
    global_values = np.mean(np.abs(shap_values), axis=0)
    ranking = np.argsort(-global_values)

    predictions = (probabilities >= threshold).astype(int)
    categories = {
        "true_positive": (predictions == 1) & (sample_labels == 1),
        "false_positive": (predictions == 1) & (sample_labels == 0),
        "false_negative": (predictions == 0) & (sample_labels == 1),
        "true_negative": (predictions == 0) & (sample_labels == 0),
    }
    local: dict[str, Any] = {}
    for category, mask in categories.items():
        indices = np.flatnonzero(mask)
        if len(indices) == 0:
            local[category] = None
            continue
        index = int(indices[0])
        order = np.argsort(-np.abs(shap_values[index]))[:10]
        local[category] = {
            "window_id": sample_rows[index]["window_id"],
            "run_id": sample_rows[index]["run_id"],
            "probability": float(probabilities[index]),
            "top_contributors": [
                {
                    "feature": names[position],
                    "value": float(sample[index, position]),
                    "shap_value": float(shap_values[index, position]),
                }
                for position in order
            ],
        }

    adjacent_scores: list[float] = []
    by_run: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(sample_rows):
        by_run[str(row["run_id"])].append(index)
    for indices in by_run.values():
        ordered = sorted(indices, key=lambda index: float(sample_rows[index]["start"]))
        for left, right in zip(ordered, ordered[1:]):
            left_top = set(np.argsort(-np.abs(shap_values[left]))[:5].tolist())
            right_top = set(np.argsort(-np.abs(shap_values[right]))[:5].tolist())
            adjacent_scores.append(len(left_top & right_top) / len(left_top | right_top))

    return {
        "method": method,
        "sample_windows": limit,
        "global_mean_absolute_shap": [
            {"feature": names[index], "mean_abs_shap": float(global_values[index])}
            for index in ranking[:15]
        ],
        "local_examples": local,
        "adjacent_window_top5_jaccard": {
            "pairs": len(adjacent_scores),
            "mean": float(np.mean(adjacent_scores)) if adjacent_scores else None,
            "median": float(np.median(adjacent_scores)) if adjacent_scores else None,
        },
    }


def _univariate_separation(
    rows: list[dict[str, Any]],
    names: list[str],
    roc_auc_score: Any,
    np: Any,
) -> list[dict[str, float]]:
    labels = np.asarray([1 if row["label"] == "ransomware" else 0 for row in rows])
    results = []
    for name in names:
        values = np.asarray([float(row[name]) for row in rows])
        auc = float(roc_auc_score(labels, values))
        results.append(
            {
                "feature": name,
                "direction_free_roc_auc": max(auc, 1.0 - auc),
            }
        )
    return sorted(
        results,
        key=lambda item: item["direction_free_roc_auc"],
        reverse=True,
    )
