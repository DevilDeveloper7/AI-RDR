"""
Live ML scoring adapter (task 4.2; planning/live-ml-inference-spec.md) — the
adapter that turns a batch of IRDP's live `RawEvent`s into the exact
windowing-contract shape every offline Tier-1 loader already produces
(pipeline/features/windowing.py's own "Caller contract" docstring), runs the
real 30-second `build_feature_windows()` aggregation, and scores the result
with the real trained v3 ensemble already on disk (models/registry/v3/) —
producing one ai-rdr-ml-detections-*-shaped dict per (host, process, window).

Phase A only, per this task's scope: takes a `list[RawEvent]` IRDP has
already fetched as input; never polls Wazuh/OpenSearch itself (no live infra
available or needed here) and never writes anywhere (returns plain dicts —
an eventual `ai-rdr-ml-detections-*` writer is later work, the same
deferral backend/irdp/writer.py's `OpenSearchEventWriter` stub already
documents for its own 3 indices).

One flat module, not a sub-package (contrast IRDP's event_source.py /
normalize.py / checkpoint.py / writer.py / pipeline.py split - see
backend/irdp/__init__.py's own "Layout" note for why IT split): IRDP split
because it had 5 genuinely separate concerns, each wanting its own
ABC+fake+real triple (a live event *source*, a checkpoint *store*, a
normalization *ruleset*, a *writer*, an *orchestrator*). This task has one
concern - adapt RawEvents into the windowing contract, then score - with no
ABC and no live-vs-fake split to make (the "live" dependency here,
models/registry/v3/, is a static file loaded read-only, not a network
resource needing a fake/real pair), so one file matches the actual shape of
the problem instead of manufacturing structure it doesn't need.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple

import re

import joblib
import pandas as pd
import polars as pl

from backend.irdp.event_source import RawEvent
from backend.irdp.normalize import _infer_tier1_event_type
from pipeline.features.windowing import build_feature_windows
from pipeline.training.dataset import FEATURE_COLUMNS, to_feature_matrix
from pipeline.training.model import DEFAULT_THRESHOLD, ensemble_proba

# ---------------------------------------------------------------------------
# Registry / windowing constants
# ---------------------------------------------------------------------------

MODEL_VERSION = "v3"
"""Matches models/registry/v3/metadata.json's own "version" field. In this
project's convention the registry directory name IS the version string - not
a separately tracked value that could drift from it."""

REGISTRY_DIR = Path(__file__).resolve().parent.parent / "models" / "registry" / MODEL_VERSION

WINDOW_SEC = 30
"""Matches every offline Tier-1 loader's default (pipeline/features/
windowing.py) and IRDP's own CORRELATION_WINDOW_SECONDS (backend/irdp/
normalize.py) - this project's one shared definition of "the same incident's
time window," reused here rather than re-picked."""

SOURCE_DATASET = "live_airdr"
"""`source_dataset` tag for live-scored windows - distinguishes them from
every offline Tier-1 parquet's own name (elfen/lifecycle/en2025/...) in any
downstream table that might ever pool rows from both."""


def _parse_ts(ts: str) -> datetime:
    """Mirrors backend/irdp/normalize.py's own private `_parse_ts`
    exactly (deliberately duplicated rather than imported - this module's
    instructions explicitly authorize importing `_infer_tier1_event_type`
    from that module, not every private symbol in it; this function is
    small enough that duplicating it is cheaper and less coupling-prone
    than a second private cross-module import).

    Real bug found and fixed live on `airdr-detect` (2026-09-30, Python
    3.10) - found independently duplicated in both copies: real Wazuh
    timestamps carry a colonless UTC offset (`...+0000`), which
    `datetime.fromisoformat()` only accepts from Python 3.11 onward. This
    repo's own dev venv runs 3.14 (lenient), which is exactly why neither
    copy's tests caught this - the real deployment target is 3.10. Fixed
    identically in both files: insert the missing colon before parsing."""
    ts = ts.replace("Z", "+00:00")
    ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)
    return datetime.fromisoformat(ts)


def _extension_of(file_path: Optional[str]) -> Optional[str]:
    """Lower-cased extension incl. leading '.', or None - matches
    windowing.py's caller-contract wording for `extension` exactly.
    `PurePosixPath`, not `Path`: auditd-reported paths are always POSIX
    (this pipeline's real target is Linux - see planning/pathpredict-spec.md
    §7's own note that the production host is Ubuntu Server), so parsing
    them with the host OS's path flavor would be wrong on a non-POSIX dev
    machine."""
    if not file_path:
        return None
    suffix = PurePosixPath(file_path).suffix
    return suffix.lower() or None


_WINDOWING_SCHEMA = {
    "sample_id": pl.Utf8,
    "process_id": pl.Int64,
    "t_seconds": pl.Float64,
    "event_type": pl.Utf8,
    "extension": pl.Utf8,
    "is_write": pl.Boolean,
    "is_read": pl.Boolean,
    "is_rename": pl.Boolean,
    "entropy_bits": pl.Float64,
    "label": pl.Utf8,
    "label_type": pl.Utf8,
    "label_confidence": pl.Float64,
    "family": pl.Utf8,
}
"""Exactly pipeline/features/windowing.py's "Caller contract" column list and
dtypes (see that module's docstring) - the schema every offline Tier-1
loader also produces before calling `build_feature_windows`."""


# ---------------------------------------------------------------------------
# Step 1: RawEvents -> windowing.py's caller-contract DataFrame
# ---------------------------------------------------------------------------


def build_windowing_frame(events: Sequence[RawEvent]) -> pl.DataFrame:
    """Builds the exact DataFrame shape `build_feature_windows()` requires,
    directly from live IRDP `RawEvent`s - no live infra, `events` is a plain
    already-fetched list (possibly spanning several hosts/processes at once;
    each entity's own windows come out independent of every other entity's,
    same as a mixed offline parquet already does).

    Column-by-column mapping (each a judgment call this adapter owns, same
    disclosure discipline as backend/irdp/normalize.py's Corrections 1/2):

      sample_id    = raw.host_id (this pipeline's "sample" is one live host -
                     the same role ELFEN's per-sample-hash sample_id plays
                     offline: the entity that owns a process).
      process_id   = raw.process_id, unchanged (already numeric or None; a
                     None group is still a valid, distinct group per
                     windowing.py's own contract note).
      t_seconds    = raw.timestamp parsed, then made relative to this row's
                     OWN (sample_id, process_id) group's earliest parsed
                     timestamp - matching windowing.py's documented design
                     rationale (per-entity relative time, never a fabricated
                     shared absolute clock) directly in this adapter, rather
                     than passing raw absolute epoch seconds and relying on
                     `build_feature_windows`'s internal `_t_min` subtraction
                     to redo the same job a second time.
      event_type   = `_infer_tier1_event_type(raw)` - IRDP's own already-
                     established mapping (backend/irdp/normalize.py),
                     imported and reused, never redone here.
      extension    = `_extension_of(raw.file_path)`.
      is_write/is_read/is_rename = directly from `raw.auditd_syscall`
                     ("write"/"read"/"rename" respectively) - already
                     resolved by event_source.py, no further classification
                     needed.
      entropy_bits = None for every row: live IRDP has no byte-level entropy
                     capture yet (auditd/Wazuh report file metadata, not file
                     contents) - an all-null column, exactly matching
                     windowing.py's documented convention for sources with no
                     byte content at all (e.g. Lifecycle's 100%-null case),
                     never a fabricated placeholder value.
      label/label_type/label_confidence/family = None: confirmed by reading
                     `build_feature_windows`'s body (pipeline/features/
                     windowing.py) that these are only ever read via
                     `.first()` / `.mode().first()` in the group_by
                     aggregation - never used in any feature-VALUE
                     computation (file_mod_rate, write_read_ratio, etc. never
                     reference them). They're training-only provenance
                     columns `build_feature_windows` needs present, and live
                     inference has no ground truth to put there.
    """
    if not events:
        return pl.DataFrame(schema=_WINDOWING_SCHEMA)

    parsed = [_parse_ts(e.timestamp) for e in events]
    group_min: Dict[Tuple[str, Optional[int]], datetime] = {}
    for e, ts in zip(events, parsed):
        key = (e.host_id, e.process_id)
        if key not in group_min or ts < group_min[key]:
            group_min[key] = ts

    rows = []
    for e, ts in zip(events, parsed):
        key = (e.host_id, e.process_id)
        t_seconds = (ts - group_min[key]).total_seconds()
        syscall = e.auditd_syscall
        rows.append(
            {
                "sample_id": e.host_id,
                "process_id": e.process_id,
                "t_seconds": t_seconds,
                "event_type": _infer_tier1_event_type(e),
                "extension": _extension_of(e.file_path),
                "is_write": syscall == "write",
                "is_read": syscall == "read",
                "is_rename": syscall == "rename",
                "entropy_bits": None,
                "label": None,
                "label_type": None,
                "label_confidence": None,
                "family": None,
            }
        )

    return pl.DataFrame(rows, schema=_WINDOWING_SCHEMA)


# ---------------------------------------------------------------------------
# Step 2: windowing.py's build_feature_windows(), reused directly
# ---------------------------------------------------------------------------


def build_live_windows(events: Sequence[RawEvent], *, window_sec: int = WINDOW_SEC) -> pl.DataFrame:
    """`build_windowing_frame` -> `pipeline.features.windowing.
    build_feature_windows` (imported, not reimplemented) with
    `source_dataset=SOURCE_DATASET`, `training_eligible=False` - matching how
    validation-only offline sources (e.g. Linux-APT-2024, see pipeline/
    training/dataset.py) are marked: live-scored windows must never be
    pooled into a future retrain by accident."""
    frame = build_windowing_frame(events)
    return build_feature_windows(
        frame,
        window_sec=window_sec,
        source_dataset=SOURCE_DATASET,
        training_eligible=False,
    )


# ---------------------------------------------------------------------------
# Step 3: load the real v3 model + score
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_models(registry_dir: str = str(REGISTRY_DIR)) -> Tuple[Any, Any]:
    """Loads the real rf_model.joblib/xgb_model.joblib from the v3 registry,
    read-only (task scope: never retrain/re-evaluate/touch anything under
    models/ or pipeline/training/ - this only ever calls `joblib.load`).
    Cached (one process, one registry dir): rf_model.joblib alone is ~13MB,
    and it's immutable for the lifetime of this process, so re-reading it
    from disk on every scored batch would be pure waste, not a real safety
    margin."""
    d = Path(registry_dir)
    rf = joblib.load(d / "rf_model.joblib")
    xgb = joblib.load(d / "xgb_model.joblib")
    return rf, xgb


def confidence_level_for(anomaly_score: float, *, threshold: float = DEFAULT_THRESHOLD) -> str:
    """confidence_level banding - a judgment call, NOT SDD-given. Confirmed
    directly (planning/irdp-pipeline-spec.md's SDD Data Dictionary
    cross-check): `confidence_level` is typed only as a bare `keyword`
    everywhere in the SDD's §5.2 dictionary - no value vocabulary is defined
    for it anywhere. This reuses the vocabulary the SDD/task-breakdown.md DO
    establish elsewhere in this same dictionary for the sibling `severity`
    field - low/medium/high/critical - rather than inventing a new one, and
    bands by DISTANCE from the decision threshold rather than the raw score
    directly: a score far from the threshold in EITHER direction (confidently
    benign or confidently ransomware) should read as high-confidence, not
    just a numerically high raw score.

    Bands (symmetric around `threshold`; tunable - same disclosed-guess
    caveat as PathPredict's DEFAULT_DECAY or IRDP's 2-tier severity rule, no
    real live-incident data exists yet to fit these precisely):
        distance >= 0.30 -> "critical"
        distance >= 0.20 -> "high"
        distance >= 0.10 -> "medium"
        else             -> "low"
    """
    distance = abs(anomaly_score - threshold)
    if distance >= 0.30:
        return "critical"
    if distance >= 0.20:
        return "high"
    if distance >= 0.10:
        return "medium"
    return "low"


def predicted_label_for(anomaly_score: float, *, threshold: float = DEFAULT_THRESHOLD) -> str:
    """"ransomware" | "benign" - matches the trained model's OWN training
    label vocabulary exactly (pipeline/training/dataset.py's `to_label`:
    1="ransomware", 0="benign"; pipeline/training/model.py's own docstring
    calls the positive class "ransomware" throughout). The SDD leaves
    `predicted_label` completely undefined (planning/irdp-pipeline-spec.md's
    cross-check: it's the one field in this entire index with no type OR
    vocabulary given anywhere in the SDD), so this reuses the model's own
    real label ontology rather than inventing a third pair of strings
    ("malicious"/"benign") that appear nowhere else in this project."""
    return "ransomware" if anomaly_score >= threshold else "benign"


def score_windows(windows: pl.DataFrame, *, threshold: float = DEFAULT_THRESHOLD) -> List[Dict[str, Any]]:
    """Scores an already-built windowed-feature DataFrame (e.g.
    `build_live_windows`'s output - or any offline Tier-1 parquet, this
    function doesn't care where the rows came from as long as they carry the
    SDD Table 5.1a feature columns plus sample_id/process_id/window_index)
    against the real v3 ensemble, returning one
    ai-rdr-ml-detections-*-shaped dict per row.

    Feature extraction reuses `pipeline.training.dataset.to_feature_matrix`
    (the exact Float64/NaN-preserving cast the model was actually trained
    against) rather than a local reimplementation - a live window's
    `entropy_score`/`encryption_rate` will usually be null (no byte-level
    entropy capture live yet, see `build_windowing_frame`), and
    `to_feature_matrix`'s NaN-preserving behavior is exactly what RF/
    XGBoost's native missing-value handling expects, matching how every
    already-null-heavy offline source (Lifecycle: 100% null, ELFEN: 84.7%
    null) is already scored.
    """
    if windows.is_empty():
        return []

    rf, xgb = _load_models()
    cols = FEATURE_COLUMNS + ["sample_id", "process_id", "window_index"]
    pdf = windows.select(cols).to_pandas()
    X = to_feature_matrix(pdf)
    scores = ensemble_proba(rf, xgb, X)

    results: List[Dict[str, Any]] = []
    for i in range(len(pdf)):
        anomaly_score = float(scores[i])
        encryption_rate = pdf.iloc[i]["encryption_rate"]
        file_mod_rate = pdf.iloc[i]["file_mod_rate"]
        process_id = pdf.iloc[i]["process_id"]
        results.append(
            {
                "model_version": MODEL_VERSION,
                "feature_window_seconds": WINDOW_SEC,
                "encryption_rate": None if pd.isna(encryption_rate) else float(encryption_rate),
                "anomaly_score": anomaly_score,
                "predicted_label": predicted_label_for(anomaly_score, threshold=threshold),
                "confidence_level": confidence_level_for(anomaly_score, threshold=threshold),
                # Denormalized entity/window identifiers - not in the SDD's
                # abbreviated primary-fields list for this index either (see
                # module docstring), added for the same reason backend/irdp/
                # normalize.py's to_normalized_event_doc adds @timestamp/
                # event_mask beyond ITS abbreviated list: a per-entity
                # detection with no entity/window identifier attached is
                # useless to any downstream consumer (ARM, Risk Fusion).
                "host_id": pdf.iloc[i]["sample_id"],
                "process_id": None if pd.isna(process_id) else int(process_id),
                "window_index": int(pdf.iloc[i]["window_index"]),
                # file_mod_rate (files/minute - pipeline/features/windowing.py's
                # `_n_filemod / minutes`) - already computed in `windows` as a
                # model input feature, but previously dropped before this
                # ai-rdr-ml-detections-*-shaped dict was returned. Same
                # denormalization rationale as host_id/process_id/window_index
                # just above: PathPredict (backend/pathpredict.py's
                # eta_seconds()/build_prediction()) is now exactly the kind of
                # downstream consumer that needs this entity's own windowed
                # rate directly, not re-derived.
                "file_mod_rate": None if pd.isna(file_mod_rate) else float(file_mod_rate),
            }
        )
    return results


def score_events(
    events: Sequence[RawEvent],
    *,
    window_sec: int = WINDOW_SEC,
    threshold: float = DEFAULT_THRESHOLD,
) -> List[Dict[str, Any]]:
    """The full adapter, end to end: RawEvents -> windowing-contract frame ->
    real `build_feature_windows()` -> real v3 model score -> one
    ai-rdr-ml-detections-*-shaped dict per (host, process, window). This is
    the one function a later live-wiring phase should call; every other
    function in this module is exposed so each stage can be tested (and
    reused) independently."""
    windows = build_live_windows(events, window_sec=window_sec)
    return score_windows(windows, threshold=threshold)
