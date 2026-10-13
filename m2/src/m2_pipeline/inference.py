from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .features import extract_window_features
from .schema import NormalizedEvent
from .windowing import WindowRecord


@dataclass(frozen=True, slots=True)
class InferenceResult:
    prediction: str
    ransomware_probability: float
    threshold: float
    alert: bool
    response_mode: str
    model_name: str
    feature_version: str
    inference_ms: float
    explanation: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "prediction": self.prediction,
            "ransomware_probability": self.ransomware_probability,
            "threshold": self.threshold,
            "alert": self.alert,
            "response_mode": self.response_mode,
            "model_name": self.model_name,
            "feature_version": self.feature_version,
            "inference_ms": self.inference_ms,
            "explanation": list(self.explanation),
        }


class InferenceService:
    def __init__(
        self,
        artifact: dict[str, Any],
        *,
        model_name: str = "random_forest",
        enable_shap: bool = True,
    ) -> None:
        self.model = artifact["model"]
        self.threshold = float(artifact["threshold"])
        self.feature_names = tuple(artifact["feature_names"])
        self.feature_version = str(artifact["feature_version"])
        self.model_name = model_name
        self._explainer = None
        if enable_shap:
            try:
                import shap

                self._explainer = shap.TreeExplainer(self.model)
            except (ImportError, TypeError):
                # Prediction remains available if SHAP is absent or the loaded
                # estimator is not tree-based; the response makes this visible.
                self._explainer = None

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        enable_shap: bool = True,
    ) -> "InferenceService":
        try:
            import joblib
        except ImportError as error:
            raise RuntimeError(
                "ML dependencies are missing; install with: pip install -e '.[ml]'"
            ) from error
        artifact = joblib.load(path)
        return cls(artifact, model_name=path.stem, enable_shap=enable_shap)

    def predict(
        self,
        events: Iterable[NormalizedEvent],
        *,
        run_id: str,
        start: float | None = None,
        end: float | None = None,
        top_k: int = 8,
    ) -> InferenceResult:
        ordered = tuple(sorted(events, key=lambda event: event.timestamp))
        if not ordered:
            raise ValueError("At least one event is required")
        if any(event.run_id != run_id for event in ordered):
            raise ValueError("All events must match the request run_id")
        resolved_start = ordered[0].timestamp if start is None else start
        resolved_end = ordered[-1].timestamp if end is None else end
        if resolved_end <= resolved_start:
            resolved_end = resolved_start + 1e-9

        identity = f"live:{run_id}:{resolved_start:.9f}:{resolved_end:.9f}"
        window = WindowRecord(
            window_id=hashlib.sha256(identity.encode()).hexdigest()[:20],
            run_id=run_id,
            label="unknown",
            split="live",
            start=resolved_start,
            end=resolved_end,
            event_count=len(ordered),
            events=ordered,
        )
        features = extract_window_features(window)
        vector = [[float(features[name]) for name in self.feature_names]]

        started = time.perf_counter()
        probability = float(self.model.predict_proba(vector)[0][1])
        explanation = self._explain(vector, features, top_k)
        inference_ms = (time.perf_counter() - started) * 1000
        alert = probability >= self.threshold
        return InferenceResult(
            prediction="ransomware" if alert else "benign",
            ransomware_probability=probability,
            threshold=self.threshold,
            alert=alert,
            # Offline validation is not enough to authorize host containment.
            response_mode="alert_only",
            model_name=self.model_name,
            feature_version=self.feature_version,
            inference_ms=inference_ms,
            explanation=explanation,
        )

    def _explain(
        self,
        vector: list[list[float]],
        features: dict[str, Any],
        top_k: int,
    ) -> tuple[dict[str, Any], ...]:
        if self._explainer is None:
            return ()
        import numpy as np

        explanation = self._explainer(np.asarray(vector))
        values = np.asarray(explanation.values)
        if values.ndim == 3:
            values = values[:, :, 1]
        row = values[0]
        order = np.argsort(-np.abs(row))[:top_k]
        return tuple(
            {
                "feature": self.feature_names[index],
                "value": float(features[self.feature_names[index]]),
                "shap_value": float(row[index]),
                "direction": "toward_ransomware" if row[index] > 0 else "toward_benign",
            }
            for index in order
        )
