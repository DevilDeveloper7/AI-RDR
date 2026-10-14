# M2 week-4 completion report

## Completed locally

- production-shaped model artifact loading;
- REST endpoints for health, model metadata and prediction;
- the same parity-safe feature extraction used for offline and live windows;
- per-alert Random Forest TreeSHAP explanations;
- explicit `alert_only` response safety mode;
- strict request validation and a written M1/M5/M6 interface contract;
- API and inference unit tests;
- real-artifact API smoke test;
- feature-ablation experiments.

The real-artifact smoke request returned HTTP 200, an alert probability of
0.174 against threshold 0.13, eight SHAP contributors and approximately 34 ms
combined prediction-plus-explanation time on the development Mac. This is not
the Ubuntu VM end-to-end latency measurement.

## Ablation result

Removing only `max_pid_share` did not reduce Random Forest test scores: F1 and
MCC remained 1.0 with zero test false positives. Removing all three
process-concentration features (`max_pid_share`, `unique_processes`,
`unique_pids`) also left Random Forest and XGBoost perfect on this split.

This does not clear the shortcut concern. The replacement leading features are
`metadata_ratio` and `open_ratio`, whose individual direction-free ROC-AUC
values are 0.9768 and 0.9525. The dataset still contains strong class
separation that may not transfer to live hosts. Ablation reports are stored in:

- `artifacts/ablation-no-pid-share/evaluation.json`;
- `artifacts/ablation-no-process-concentration/evaluation.json`.

## External work still required

The remaining acceptance evidence cannot be generated from the local published
dataset:

1. M1 must provide representative IRDP/Wazuh events from the Ubuntu VM.
2. Capture held-out backup, rsync, compression, OpenSSL/GnuPG, database and
   bulk-conversion workloads through that same live path.
3. Replay their five-second windows into `POST /v1/predict`.
4. Report workload-level and run-level FPR, end-to-end latency, CPU and memory.
5. Keep the model `alert_only` unless precision, recall, F1 and FPR targets also
   hold on this external set.

This is an integration/testbed dependency, not unfinished local model code.
