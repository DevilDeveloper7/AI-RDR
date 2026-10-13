# Ransomware model documentation

## Intended use

M2 is a binary Linux behavioural detector over short windows of host syscall
telemetry. It complements the high-confidence honey-file path; it does not
replace antivirus, identify ransomware families, or detect the currently
deferred network/exfiltration path.

## Selected dataset

Primary source: **Ransomware's Lifecycle Dataset**, Zenodo record 18502469,
published under CC BY 4.0.

- downloaded archive: 3,111,511,474 bytes;
- verified MD5: `103a8e88b66764e1fb1947efd6d2649b`;
- selected positive runs: 96 execution/encryption traces;
- selected negative runs: 89 benign syscall traces;
- benign workloads: browser (25), compression (25), filebench (15), idle (5),
  media server (10), and SPEC (9).

The benign workloads are important: compression, browser and file-server I/O
resemble high-rate ransomware activity more closely than idle-only negatives.

## Filtering and rejected labels

The ransomware archive also contains 144 exfiltration and 15 reconnaissance
traces. They are excluded from this binary detector because network and
exfiltration detection are deferred in the approved scope. Marking generic
SFTP, scanning or compression activity as ransomware would broaden the
positive class and increase false alarms.

Only `benign` and `ransomware` labels enter model training. `unknown` labels
are rejected by default. A run containing mixed labels is rejected. The
dataset does not justify treating all 96 positive traces as distinct
ransomware families; results are reported as scenario/run generalisation.

## Supported inputs

The normalizer supports:

- Lifecycle's nested `.tar.gz` trace-cmd archives;
- CSV;
- JSON;
- JSON Lines / NDJSON;
- gzip-compressed CSV/JSON/JSONL;
- flattened or nested Wazuh/auditd/IRDP fields.

The Lifecycle adapter reads `sys_enter_*` records and drops `sys_exit_*`
records, preventing each syscall from being counted twice and improving
parity with auditd.

## Normalized event schema

Required fields are timestamp, run ID, label, event type and operation.
Optional parity-safe fields are PID, parent PID, process name, path and byte
count. Epoch seconds/milliseconds/microseconds/nanoseconds and ISO timestamps
are normalized to Unix seconds.

Content entropy, file extension, static binary features and hardware counters
are not model inputs because equivalent values are not yet available from both
Lifecycle and the live Wazuh/auditd/IRDP stream.

## Windowing and feature extraction

The training default is a 5-second non-overlapping window. Live inference may
advance the same 5-second window every second; the feature definition remains
identical. Window size and stride are configuration, not claimed optima.

Features are reproducible syscall statistics:

- event rate and syscall diversity/entropy;
- unique PID and process counts;
- read, write, open, close, rename, delete, sync and metadata counts/ratios;
- memory, network and process-creation counts/ratios;
- requested read/write byte totals where trace arguments provide them;
- fixed local transitions such as open→read, read→write and write→sync.

At most 200 windows per run are retained by deterministic reservoir sampling.
This prevents very long runs from dominating training and limits correlation
between neighbouring windows. Sampling is reproducible from the run ID and
seed.

## Run-level split methodology

Runs are assigned with a deterministic, class-stratified 70/15/15
train/validation/test split. The split is performed on `run_id`, never on
individual windows:

- every window from one run stays in one split;
- overlapping or adjacent windows cannot leak across splits;
- both labels are represented in each split;
- threshold selection uses validation data only;
- the test split is used once for final reporting.

The seed, run counts and exact assignments must accompany every experiment.

## Candidate models

- Logistic Regression: simple baseline proving whether non-linear models add
  value.
- Random Forest: robust bagging candidate with class weighting.
- XGBoost: boosted-tree candidate for non-linear feature interactions.

The final model is selected from validation results. It is not a fixed
RF/XGBoost ensemble.

## Preliminary week-3 experiment

Feature generation produced 2,253 non-overlapping five-second windows:
2,061 benign and 192 ransomware. The difference reflects trace duration, not
185-to-185 class imbalance at run level. Class weighting is used; neighbouring
ransomware windows are not duplicated.

The stratified run split contains:

- train: 129 runs (62 benign, 67 ransomware);
- validation: 27 runs (13 benign, 14 ransomware);
- test: 29 runs (14 benign, 15 ransomware).

Validation-only threshold selection produced these held-out test results:

- Logistic Regression at threshold 0.65: accuracy, precision, recall and F1
  all 1.000; window FPR 0%;
- Random Forest at threshold 0.13: accuracy, precision, recall and F1 all
  1.000; window and run FPR 0%;
- XGBoost at threshold 0.06: accuracy 0.9970, precision 0.9667, recall 1.000,
  F1 0.9831, MCC 0.9816 and window FPR 0.327%; its one compression false
  positive makes run-level FPR 7.14%.

Random Forest is the preliminary selected model under the predefined
validation policy. Its measured median batch inference cost was approximately
0.08 ms per window on the development machine. This is model inference only,
not end-to-end live detection latency.

These scores are **not yet evidence of production generalisation**. One feature,
`max_pid_share`, separates labels by itself with direction-free ROC-AUC 0.9925;
`metadata_ratio` reaches 0.9768. This indicates possible scenario or collection
shortcuts. External IRDP hard-benign testing is mandatory before automatic
response is enabled. Until then the model is dashboard-only.

Week-4 ablation confirms that the concern is not limited to one feature.
Removing `max_pid_share`, and then removing all process-concentration features,
still leaves Random Forest and XGBoost perfect on the same test split.
`metadata_ratio` and `open_ratio` become the dominant separators. The ablation
therefore strengthens the need for external validation rather than proving the
model is robust.

## Explainability result

TreeSHAP was calculated on all 335 held-out test windows for the selected
Random Forest. The leading global attributions are `max_pid_share`,
`metadata_ratio`, `open_ratio`, `metadata_count` and `unique_processes`.
Adjacent-window top-five explanation sets have mean Jaccard similarity 0.768
and median 0.667 across 306 pairs.

The attribution pattern reinforces the shortcut warning: process concentration
is more influential than direct write/encryption behaviour. The report includes
local true-positive and true-negative explanations. No selected-model false
positive or false negative existed in this split, so those example fields are
explicitly null rather than fabricated.

## False-positive controls

- use matched benign data from the same publication;
- retain high-activity benign compression, browser and file-server runs;
- cap windows per run;
- use class weighting rather than duplicating windows;
- select the probability threshold under precision ≥ 90% and FPR < 2%;
- report errors by benign workload, not only aggregate accuracy;
- reserve live hard-benign workloads—backup, rsync, database writes,
  OpenSSL/GnuPG and bulk conversion—for external validation;
- do not automatically contain a host solely because a low-confidence model
  score crossed the default 0.5 threshold.

## Reproducibility

Feature files contain a feature-schema version. Saved model artifacts contain
the estimator, ordered feature names and selected threshold. Evaluation output
records the seed, run-level split counts, metrics, confusion matrix and leading
feature importances. Full machine-readable results are written to
`artifacts/models/evaluation.json`; TreeSHAP output is written to
`artifacts/models/explainability.json`.
