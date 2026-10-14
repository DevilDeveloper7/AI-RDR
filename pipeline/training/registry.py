"""Minimal versioned model registry, per the SDD's own stated ModelRegistry design goal
(joblib-serialized artifacts, tracked reproducibility metadata) and
planning/model-training-progress.md's checklist item for it. Deliberately simple: no
database, no remote store — a version subdirectory per training run under
`models/registry/`, each holding the two model artifacts, the ensemble weighting config,
and a metadata.json with everything needed to know what produced it (feature-window
params, exact dataset file hashes + row counts, training timestamp, hyperparameters).

`models/` itself is gitignored except this file's own directory-level SUMMARY.md (see
.gitignore's `/models/*` + `!/models/SUMMARY.md` negation, added alongside the existing
`data/normalized/` and `data/features/` ones) — trained joblib artifacts are large,
regeneratable binaries, exactly like the parquet files under data/.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
import xgboost

REGISTRY_ROOT = Path(__file__).resolve().parents[2] / "models" / "registry"


class ModelRegistry:
    def __init__(self, root: Path = REGISTRY_ROOT):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _next_version(self) -> str:
        existing = sorted(
            int(p.name[1:]) for p in self.root.glob("v*") if p.is_dir() and p.name[1:].isdigit()
        )
        return f"v{(existing[-1] + 1) if existing else 1}"

    def save(
        self,
        *,
        rf_model,
        xgb_model,
        ensemble_config: dict,
        dataset_metadata: dict,
        window_params: dict,
        hyperparameters: dict,
        version: str | None = None,
    ) -> str:
        version = version or self._next_version()
        out_dir = self.root / version
        out_dir.mkdir(parents=True, exist_ok=False)

        joblib.dump(rf_model, out_dir / "rf_model.joblib")
        joblib.dump(xgb_model, out_dir / "xgb_model.joblib")
        (out_dir / "ensemble_config.json").write_text(json.dumps(ensemble_config, indent=2))

        metadata = {
            "version": version,
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "window_params": window_params,
            "dataset_metadata": dataset_metadata,
            "hyperparameters": hyperparameters,
            "library_versions": {
                "scikit_learn": sklearn.__version__,
                "xgboost": xgboost.__version__,
                "joblib": joblib.__version__,
                "python": platform.python_version(),
            },
        }
        (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
        return version

    def load(self, version: str) -> dict:
        in_dir = self.root / version
        return {
            "rf_model": joblib.load(in_dir / "rf_model.joblib"),
            "xgb_model": joblib.load(in_dir / "xgb_model.joblib"),
            "ensemble_config": json.loads((in_dir / "ensemble_config.json").read_text()),
            "metadata": json.loads((in_dir / "metadata.json").read_text()),
        }

    def list_versions(self) -> list[str]:
        return sorted(
            (p.name for p in self.root.glob("v*") if p.is_dir()),
            key=lambda v: int(v[1:]) if v[1:].isdigit() else -1,
        )
