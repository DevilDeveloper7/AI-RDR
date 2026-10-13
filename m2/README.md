# AI-RDR M2 — preprocessing, training and evaluation

Weeks 1–2 implementation for the behavioural ML component. It normalizes
Lifecycle or IRDP/Wazuh-style CSV/JSON/JSONL traces into one schema and creates
sliding windows without crossing execution boundaries.

The existing standalone SOC console is retained unchanged. Week 3 adds
parity-safe feature generation, Logistic Regression/Random Forest/XGBoost
comparison, validation-only threshold selection and TreeSHAP evaluation.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,ml]'
pytest
```

## Primary dataset

Download [Ransomware's Lifecycle Dataset](https://zenodo.org/records/18502469)
to `data/raw/dataset_results.tar.gz`, verify it, then extract it:

```bash
md5 data/raw/dataset_results.tar.gz
# expected: 103a8e88b66764e1fb1947efd6d2649b
mkdir -p data/raw/lifecycle
tar -xzf data/raw/dataset_results.tar.gz -C data/raw/lifecycle
```

The archive is 3.11 GB compressed, so raw and processed data are git-ignored.
Leave its inner `*.tar.gz` files compressed: the Lifecycle adapter streams
trace-cmd members directly and avoids expanding very large traces onto disk.
The reason for this choice and rejected alternatives is documented in
`docs/DATASET_DECISION.md`.

## Inspect before preprocessing

```bash
ai-rdr-m2 inspect data/raw/lifecycle
```

Review unknown labels and parse errors before proceeding. Labels are inferred
from explicit fields first and then from benign/ransomware path names.

## Create windows

Default: 5-second windows, 1-second stride, at least two events.

```bash
ai-rdr-m2 preprocess \
  data/raw/lifecycle \
  data/processed/lifecycle-windows.jsonl \
  --mode time --size 5 --stride 1 --min-events 2
```

For traces without reliable timestamps, event-count windows are supported:

```bash
ai-rdr-m2 preprocess INPUT OUTPUT \
  --mode events --size 100 --stride 20 --min-events 20
```

Every output record includes the normalized events, `run_id`, label, time
bounds and a deterministic split. Split assignment is SHA-256 based on
`run_id` (70/15/15), so overlapping windows from an execution cannot leak
between train, validation and test. Unknown-label runs are skipped unless
`--allow-unknown-labels` is explicitly set.

A sibling `*.report.json` records input counts, skipped runs, labels, splits
and window configuration.

## Normalized event contract

Required fields:

- `timestamp` — Unix seconds (ISO, s/ms/us/ns inputs accepted);
- `run_id` — independent execution/trace ID;
- `label` — `benign`, `ransomware`, or `unknown`;
- `event_type` and `operation`.

Optional parity-safe fields are `pid`, `ppid`, `process_name`, `path` and
`bytes`. The same schema accepts flattened Wazuh/auditd keys such as
`@timestamp`, `auditd.data.syscall`, `auditd.data.pid`, `process.name` and
`file.path`.

Content entropy and extension-specific features are intentionally absent:
their availability from both Lifecycle and live IRDP telemetry has not yet
been demonstrated.

## Generate features and train

Feature extraction streams the nested archives and caps each run at 200
deterministically sampled windows:

```bash
ai-rdr-m2 features \
  data/raw/lifecycle \
  data/processed/lifecycle-features.jsonl \
  --size 5 --stride 5 --max-windows-per-run 200 --seed 321
```

On Linux with OpenMP installed:

```bash
ai-rdr-m2 train \
  data/processed/lifecycle-features.jsonl \
  artifacts/models --seed 321
```

On this macOS development machine, Homebrew was not writable, so a local
OpenMP runtime is used by:

```bash
bash scripts/train_models.sh
```

Results are written to `artifacts/models/evaluation.json` and
`artifacts/models/explainability.json`. Current results and their
dataset-shortcut limitation are documented in `docs/MODEL_DOCUMENTATION.md`;
the predefined acceptance policy is in `docs/EVALUATION_CRITERIA.md`.

## Run the inference API

```bash
ai-rdr-m2-api
```

The default artifact is `artifacts/models/random_forest.joblib`; override it
with `AI_RDR_MODEL_PATH`. API documentation is served at
`http://127.0.0.1:8000/docs`.

The service exposes `/health`, `/v1/model` and `/v1/predict`. Predictions
include probability, selected threshold and local SHAP contributors. The
current response mode is intentionally `alert_only`, not automatic blocking.
See `docs/M2_API_CONTRACT.md` and `docs/WEEK_4_REPORT.md`.
