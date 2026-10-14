# Ransomware model evaluation criteria

## Evaluation protocol

All offline metrics are calculated on windows from held-out independent runs.
Model fitting uses training runs. Probability-threshold selection uses
validation runs. Test runs are not used for feature selection, model choice,
resampling or threshold tuning.

Logistic Regression, Random Forest and XGBoost use the same features and exact
split. The selected model is determined by validation results only.

## Required classification metrics

- **Detection accuracy:** report for completeness, but never use it alone.
  Class imbalance can make an always-benign model look accurate.
- **Recall / detection rate:** target ≥ 80%; below 70% requires retuning or
  reconsidering the model.
- **Precision:** target ≥ 90%. This is a response-safety constraint because a
  false alert can trigger disruptive containment.
- **F1 score:** target ≥ 0.85; headline balance of precision and recall.
- **PR-AUC:** required and preferred to ROC-AUC under class imbalance.
- **MCC:** required balanced correlation measure.
- **False-positive rate:** target < 2%, calculated as FP/(FP+TN).
- **Confusion matrix:** report TN, FP, FN and TP as absolute values.
- **ROC-AUC and Brier score:** supporting discrimination and probability
  calibration measures.

Thresholds are selected on validation data. A model satisfying precision
≥90% and FPR <2% ranks ahead of one that does not; among safe candidates,
F1, PR-AUC and recall decide the order. The test threshold is never retuned.

## False-positive evaluation

Aggregate FPR is insufficient. Report benign errors for browser, compression,
filebench, idle, media-server and SPEC runs separately. Then evaluate an
external hard-benign set collected through the live IRDP path:

- backup and restore;
- tar/zip/7z/zstd compression;
- rsync and bulk file copy;
- legitimate OpenSSL/GnuPG encryption;
- database write bursts;
- compilation and bulk file conversion.

A model that meets aggregate targets but consistently blocks one legitimate
workload is not accepted for automatic response.

## Explainability criteria

Tree models must provide SHAP explanations using the same ordered feature
schema saved with the model. Evaluation includes:

- global mean absolute SHAP ranking;
- local top contributors for true positives, false positives and false
  negatives;
- sign/direction of each local contribution;
- agreement between leading SHAP features and plausible behavioural evidence;
- explanation stability across small perturbations or adjacent windows.

For stability, compare top-k feature sets using Jaccard similarity and compare
full attribution rankings with rank correlation. The exact stability threshold
is reported before final testing; it must not be chosen after viewing the test
result. Native tree importance may be reported as a diagnostic but does not
replace SHAP.

Explanations are supporting evidence, not proof of causality. A high event
rate alone is not an acceptable rationale for containment.

## Operational criteria

- behavioural detection latency: <10 seconds;
- honey-file fast-path latency: <1 second;
- encrypted files before detection/containment: minimize and report;
- CPU, memory and inference latency: report on the Ubuntu VM target;
- adversarial recall retained: ≥60% under the defined evasion tests.

Offline classifier latency and live end-to-end detection latency are reported
separately.

## Robustness tests

Evaluate slowed encryption, partial encryption, no extension change, no
rename, work split across processes, plausible process identity, and
high-activity/high-entropy benign workloads. Report the point where detection
fails instead of claiming universal resistance.

## Acceptance decision

Automatic-response eligibility requires all of the following:

- precision ≥90%;
- FPR <2%;
- recall ≥80%;
- F1 ≥0.85;
- no severe workload-specific false-positive pattern;
- reproducible run-level evaluation;
- an explanation available for each model alert.

If classification targets are missed, the model can remain dashboard-only
while the honey-file high-confidence path continues to trigger response.

## Week-3 evaluation status

The current run-level experiment satisfies the numerical offline targets for
the preliminary Random Forest: test accuracy, precision, recall, F1, PR-AUC
and MCC are 1.000, with window and run FPR of 0%. XGBoost demonstrates why both
window- and run-level reporting are required: one false-positive compression
window gives only 0.327% window FPR but 7.14% run FPR.

TreeSHAP explanations are available for the selected model. Mean adjacent
top-five-feature Jaccard stability is 0.768. No fixed acceptance threshold for
explanation stability is retroactively introduced from this result; it remains
a reported diagnostic until agreed with the mentor.

The model is **not eligible for automatic response yet**, despite meeting
offline numerical targets. Individual features almost perfectly separate the
published classes (`max_pid_share` direction-free ROC-AUC 0.9925), creating a
credible dataset-shortcut risk. The missing acceptance evidence is:

- external hard-benign IRDP evaluation;
- live Ubuntu end-to-end latency and resource measurements;
- robustness/evasion tests;
- local explanation review for genuine false positives and false negatives;
- confirmation that leading features behave similarly in live Wazuh/auditd
  telemetry.
