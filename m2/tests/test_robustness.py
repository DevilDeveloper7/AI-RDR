import math
import random

import pytest

from m2_pipeline.robustness import (
    _leading_error_features,
    assign_cv_folds,
    count_incidents,
    cross_validate,
    encryption_scenario,
    exact_proportion_bounds,
    poisson_rate_upper,
    precision_at_prevalence,
    select_margin_threshold,
    zero_event_exposure,
)
from m2_pipeline.training import _select_threshold


def test_exact_bounds_match_closed_form_for_perfect_results() -> None:
    perfect = exact_proportion_bounds(29, 29)
    clean = exact_proportion_bounds(0, 14)

    assert perfect["upper"] == 1.0
    assert perfect["lower"] == pytest.approx(0.05 ** (1 / 29))
    assert clean["lower"] == 0.0
    assert clean["upper"] == pytest.approx(1 - 0.05 ** (1 / 14))
    assert exact_proportion_bounds(0, 0) == {"lower": None, "upper": None}


def test_exact_bounds_contain_the_observed_proportion() -> None:
    bounds = exact_proportion_bounds(7, 20)

    assert bounds["lower"] < 7 / 20 < bounds["upper"]
    with pytest.raises(ValueError):
        exact_proportion_bounds(21, 20)


def test_zero_event_rate_bound_is_rule_of_three() -> None:
    assert poisson_rate_upper(0, 1.0) == pytest.approx(-math.log(0.05))
    assert poisson_rate_upper(0, 0.0) is None
    assert zero_event_exposure(1 / 24) == pytest.approx(-math.log(0.05) * 24)


def test_cv_folds_are_stratified_deterministic_and_cover_every_run() -> None:
    labels = {
        **{f"benign-{index}": "benign" for index in range(23)},
        **{f"ransomware-{index}": "ransomware" for index in range(17)},
    }

    folds = assign_cv_folds(labels, folds=5, repetition=0, seed=321)

    assert set(folds) == set(labels)
    for label in ("benign", "ransomware"):
        sizes = [
            sum(1 for run, fold in folds.items() if labels[run] == label and fold == k)
            for k in range(5)
        ]
        assert max(sizes) - min(sizes) <= 1
    assert folds == assign_cv_folds(labels, folds=5, repetition=0, seed=321)
    assert folds != assign_cv_folds(labels, folds=5, repetition=1, seed=321)
    with pytest.raises(ValueError):
        assign_cv_folds({"a": "benign", "b": "ransomware"}, folds=5)


def test_encryption_scenario_is_read_from_trace_names() -> None:
    prefix = "ftrace_results__parsed__out_exec_parsed__"

    assert encryption_scenario(prefix + "asymm_35") == "asymmetric"
    assert encryption_scenario(prefix + "symm_AES_256t_8") == "aes"
    assert encryption_scenario(prefix + "symm_Salsa20_128t_1") == "salsa20"
    assert encryption_scenario("browser__parsed__syscall_output__download_3") is None


def test_nearby_alerts_merge_into_one_incident() -> None:
    def window(start: float, probability: float) -> dict:
        return {
            "start": start,
            "end": start + 5.0,
            "probability": probability,
            "threshold": 0.5,
        }

    windows = [window(0, 0.9), window(5, 0.9), window(10, 0.1), window(15, 0.9)]
    distant = [window(0, 0.9), window(200, 0.9)]

    assert count_incidents(windows, gap_seconds=60.0) == 1
    assert count_incidents(windows, gap_seconds=0.0) == 2
    assert count_incidents(distant, gap_seconds=60.0) == 2
    assert count_incidents([window(0, 0.1)]) == 0


def test_margin_threshold_starts_from_the_primary_rule() -> None:
    np = pytest.importorskip("numpy")
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1])
    probabilities = np.asarray([0.052, 0.104, 0.203, 0.304, 0.705, 0.806, 0.907])

    primary = _select_threshold(labels, probabilities)["threshold"]
    margin = select_margin_threshold(labels, probabilities)

    assert primary == pytest.approx(0.31)
    assert margin == pytest.approx(0.51)


def test_error_review_counts_features_pushing_the_wrong_way() -> None:
    examples = [
        {
            "type": "false_positive",
            "top_contributors": [
                {"feature": "metadata_ratio", "shap_value": 0.3},
                {"feature": "event_rate", "shap_value": -0.2},
                {"feature": "open_ratio", "shap_value": 0.1},
            ],
        },
        {
            "type": "false_negative",
            "top_contributors": [
                {"feature": "metadata_ratio", "shap_value": 0.2},
                {"feature": "write_ratio", "shap_value": -0.4},
            ],
        },
    ]

    leading = _leading_error_features(examples)

    assert leading["false_positive"] == {
        "windows": 1,
        "features": {"metadata_ratio": 1, "open_ratio": 1},
    }
    assert leading["false_negative"] == {"windows": 1, "features": {"write_ratio": 1}}


def test_precision_at_prevalence_shows_base_rate_effect() -> None:
    assert precision_at_prevalence(1.0, 0.0, 0.001) == 1.0
    assert precision_at_prevalence(1.0, 1 / 306, 0.001) == pytest.approx(0.2345, abs=1e-4)
    assert precision_at_prevalence(0.0, 0.0, 0.001) is None


def test_cross_validation_scores_every_run_once_per_repetition() -> None:
    generator = random.Random(7)
    rows = []
    for run_index in range(30):
        label = "ransomware" if run_index % 2 else "benign"
        for window_index in range(3):
            centre = 4.0 if label == "ransomware" else 0.0
            rows.append(
                {
                    "run_id": f"{label}-{run_index}",
                    "label": label,
                    "start": window_index * 5.0,
                    "end": window_index * 5.0 + 5.0,
                    "signal": centre + generator.gauss(0.0, 1.0),
                    "noise": generator.gauss(0.0, 1.0),
                }
            )

    report = cross_validate(
        rows,
        ["signal", "noise"],
        repetitions=2,
        folds=3,
        seed=11,
        model_names=("logistic_regression",),
    )

    model = report["models"]["logistic_regression"]
    assert len(model["per_repetition"]) == 2
    for repetition in model["per_repetition"]:
        windows = repetition["window_confusion_matrix"]
        runs = repetition["run_confusion_matrix"]
        assert sum(windows.values()) == len(rows)
        assert sum(runs.values()) == 30
        assert len(repetition["fold_thresholds"]) == 3
    summary = model["summary"]
    assert summary["window_level"]["recall"]["mean"] > 0.8
    assert summary["benign_hours_per_repetition"] == pytest.approx(15 * 15 / 3600)
    margin = model["margin_threshold_rule"]["per_repetition"]
    assert all(
        sum(repetition["window_confusion_matrix"].values()) == len(rows)
        for repetition in margin
    )
