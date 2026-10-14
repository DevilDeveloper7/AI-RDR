"""RF/XGBoost ensemble training + evaluation, per SDD §6.2.5's exact spec:

- RandomForestClassifier, 100 trees.
- XGBClassifier, 200 estimators, learning_rate=0.05, max_depth=6, scale_pos_weight
  calibrated to the training set's actual class ratio.
- anomaly_score = 0.45 * P_rf + 0.55 * P_xgb.
- Detection threshold 0.65 (default, configurable).

Class imbalance — decided and documented here, not silently papered over (per
planning/model-training-progress.md's explicit instruction): the positive class
(ransomware) is the *majority* class in this training set (20,232 of 23,544 windows,
85.9%) because only EN2025 contributes any benign windows at all (3,312) — ELFEN and
Lifecycle are ransomware-only sources. This is the inverse of the textbook "rare
positive" imbalance case, but the fix is the same either way: both RF and XGBoost are
told to weight the *minority* class (benign) more heavily than its raw frequency, via
`class_weight="balanced"` (RF) and `scale_pos_weight = n_negative / n_positive` (XGBoost,
computed on the actual pooled training split, not assumed). Resampling (SMOTE et al.) was
considered and rejected: synthesizing interpolated feature vectors for a security
detector's minority class risks manufacturing benign-looking points that don't correspond
to any real process behavior, which is a worse failure mode here than a moderately
imbalanced but real training set. Class weighting leaves every training row real.

Missing values: both `RandomForestClassifier` (native missing-value split support since
scikit-learn 1.4) and `XGBClassifier` (native since XGBoost's original tree-boosting
design) accept NaN directly — `dataset.to_feature_matrix` deliberately preserves real
NaNs in entropy_score/encryption_rate rather than imputing 0.0, which would fabricate a
"definitely no encryption" reading for the 79-100% of windows per source that simply have
no decodable byte sample (see data/features/SUMMARY.md). Verified explicitly in this
module (not assumed) via `_assert_native_missing_support` at import time in train.py.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from xgboost import XGBClassifier

RF_PARAMS = dict(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1)
XGB_BASE_PARAMS = dict(
    n_estimators=200,
    learning_rate=0.05,
    max_depth=6,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss",
    tree_method="hist",
)

RF_WEIGHT = 0.45
XGB_WEIGHT = 0.55
DEFAULT_THRESHOLD = 0.65


def assert_native_missing_support() -> None:
    """Fits a throwaway RF and XGB on a tiny frame containing NaN, to confirm (not just
    assume from a changelog) that this environment's installed sklearn/xgboost versions
    actually accept NaN directly without raising — run once at train.py's start."""
    X = np.array([[1.0, np.nan], [2.0, 3.0], [np.nan, 1.0], [4.0, 5.0]] * 5)
    y = np.array([0, 1, 0, 1] * 5)
    RandomForestClassifier(n_estimators=5, random_state=0).fit(X, y)
    XGBClassifier(n_estimators=5, random_state=0).fit(X, y)


def compute_scale_pos_weight(y_train: np.ndarray) -> float:
    """n_negative / n_positive on the actual pooled training split — not assumed from the
    full dataset's ratio, since the per-source split changes it slightly."""
    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    assert n_pos > 0 and n_neg > 0, (
        f"scale_pos_weight requires both classes present in the training split, got "
        f"n_pos={n_pos} n_neg={n_neg}"
    )
    return n_neg / n_pos


def train_rf(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    rf = RandomForestClassifier(**RF_PARAMS)
    rf.fit(X_train, y_train)
    return rf


def train_xgb(X_train: np.ndarray, y_train: np.ndarray, scale_pos_weight: float) -> XGBClassifier:
    xgb = XGBClassifier(**XGB_BASE_PARAMS, scale_pos_weight=scale_pos_weight)
    xgb.fit(X_train, y_train)
    return xgb


def ensemble_proba(rf: RandomForestClassifier, xgb: XGBClassifier, X: np.ndarray) -> np.ndarray:
    """anomaly_score = 0.45 * P_rf(ransomware) + 0.55 * P_xgb(ransomware), per SDD §6.2.5."""
    p_rf = rf.predict_proba(X)[:, 1]
    p_xgb = xgb.predict_proba(X)[:, 1]
    return RF_WEIGHT * p_rf + XGB_WEIGHT * p_xgb


def evaluate(
    y_true: np.ndarray, anomaly_score: np.ndarray, threshold: float = DEFAULT_THRESHOLD
) -> dict:
    """Confusion matrix + precision/recall/F1 + false-positive rate for one labeled
    (has-both-classes-or-not) slice. FPR is reported as None (not 0.0 or NaN) when the
    slice has zero real negatives — e.g. the ELFEN/Lifecycle test splits, which are
    ransomware-only and therefore cannot produce a false positive by definition, not
    because the model happened to get them all right."""
    y_pred = (anomaly_score >= threshold).astype(int)
    labels_present = set(np.unique(y_true))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    if 0 in labels_present:
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    else:
        fpr = None  # no real negatives in this slice — FPR is undefined, not zero

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=[1], average=None, zero_division=0
    )
    return {
        "n": int(len(y_true)),
        "n_positive": int((y_true == 1).sum()),
        "n_negative": int((y_true == 0).sum()),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": float(precision[0]),
        "recall": float(recall[0]),
        "f1": float(f1[0]),
        "false_positive_rate": fpr,
        "threshold": threshold,
    }


def feature_importance(rf: RandomForestClassifier, feature_names: list[str]) -> list[tuple[str, float]]:
    """RF's native impurity-based feature_importances_, sorted descending. XGBoost's own
    gain-based importance is reported alongside in train.py for cross-checking, but RF's
    is the one the SDD/task-breakdown call out as the natively-available one."""
    pairs = list(zip(feature_names, rf.feature_importances_.tolist()))
    return sorted(pairs, key=lambda p: p[1], reverse=True)


def xgb_feature_importance(xgb: XGBClassifier, feature_names: list[str]) -> list[tuple[str, float]]:
    pairs = list(zip(feature_names, xgb.feature_importances_.tolist()))
    return sorted(pairs, key=lambda p: p[1], reverse=True)
