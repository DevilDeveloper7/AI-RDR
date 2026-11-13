# Ransomware model evaluation criteria

These criteria decide when an M2 model may be trusted. Numerical targets come
from the Implementation Document (§17.4–17.6); the evaluation methods follow
the references at the end. Results are in `artifacts/models/evaluation.json`
(primary split) and `artifacts/robustness/robustness.json` (robustness checks).

## Evaluation protocol

All offline metrics are calculated on windows from held-out independent runs.
Model fitting uses training runs. Probability-threshold selection uses
validation runs. Test runs are not used for feature selection, model choice,
resampling or threshold tuning.

Logistic Regression, Random Forest and XGBoost use the same features and exact
split. The selected model is determined by validation results only.

The seed-321 70/15/15 run split is the primary, pre-registered result. Because
its test set is small (29 runs), it is complemented by 10 repetitions of
five-fold cross-validation grouped by run. Training and threshold selection
are repeated inside every fold on validation runs only, so no tuning step sees
the fold being tested (Cawley & Talbot, 2010). Every run is tested exactly once
per repetition. Cross-validation measures how much the primary result varies;
it does not replace it.

## Required classification metrics

- **Detection accuracy:** report for completeness, but never use it alone.
  Class imbalance can make an always-benign model look accurate.
- **Recall / detection rate:** target ≥ 80%; below 70% requires retuning or
  reconsidering the model.
- **Precision:** target ≥ 90%. This is a response-safety constraint because a
  false alert can trigger disruptive containment.
- **F1 score:** target ≥ 0.85; headline balance of precision and recall.
- **PR-AUC:** required and preferred to ROC-AUC under class imbalance
  (Saito & Rehmsmeier, 2015).
- **MCC:** required balanced correlation measure (Chicco & Jurman, 2020).
- **False-positive rate:** target < 2%, calculated as FP/(FP+TN).
- **Confusion matrix:** report TN, FP, FN and TP as absolute values.
- **ROC-AUC and Brier score:** supporting discrimination and probability
  calibration measures (Brier, 1950).

## Statistical confidence

A perfect score on a small test set is weak evidence. With zero errors in n
cases, the 95% upper bound on the error rate is still about 3/n (Hanley &
Lippman-Hand, 1983).

- Every headline rate is reported with a one-sided 95% exact bound
  (Clopper & Pearson, 1934): a lower bound for precision and recall and an
  upper bound for FPR.
- A target is *observed* when the point estimate meets it and *demonstrated*
  when the bound meets it.
- Windows of one run are correlated, so window-level bounds are optimistic;
  run-level bounds are the conservative reading.
- Cross-validation results are reported as the mean and range over
  repetitions; bounds are taken from the least favourable repetition.

## Model selection and tie-break

Candidates are ranked on validation by (1) precision ≥ 0.90 and FPR < 0.02,
(2) F1, (3) PR-AUC and (4) recall, compared at three decimals. If candidates
are still tied, the choice is provisional and is made on the external
hard-benign set by lower run-level FPR, then lower Brier score, then lower p95
latency. This is the same rule as REQ-M2-04 in the M2 test plan.

The probability threshold maximises validation F1 subject to precision ≥ 0.90
and FPR < 0.02. When several thresholds tie, the current implementation keeps
the lowest one. A change to this operating point is a pre-registered decision
taken before the external hard-benign test, never after viewing a test result.

## False-positive evaluation

Aggregate FPR is insufficient. Report benign errors for browser, compression,
filebench, idle, media-server and SPEC runs separately; FPR must stay below 2%
for every workload. Then evaluate an external hard-benign set collected
through the live IRDP path:

- backup and restore;
- tar/zip/7z/zstd compression;
- rsync and bulk file copy;
- legitimate OpenSSL/GnuPG encryption;
- database write bursts;
- compilation and bulk file conversion.

A model that meets aggregate targets but consistently alerts on one legitimate
workload is not accepted for automatic response.

Per-window FPR must also be translated into analyst workload:

- **False alerts per host-day:** FPR × 17,280, the number of five-second
  windows in 24 hours. The FPR < 2% target alone still permits about 346
  false alerts per host-day.
- **False incidents per host-day:** alerts from one host session that are at
  most 60 seconds apart count as one incident. Proposed target, to be agreed
  with the mentor: at most one false incident per host-day on the live
  hard-benign set. Zero incidents in 72 hours of benign recording are needed
  to demonstrate it (one-sided 95% Poisson bound). The whole published
  dataset holds 2.86 hours of benign activity.
- **Base rate:** test precision depends on the share of ransomware in the test
  set (8.7% of test windows). In deployment ransomware is far rarer, so the
  same FPR yields much lower precision (Axelsson, 2000; Arp et al., 2022).
  Report precision at illustrative prevalences of 1%, 0.1% and 0.01% next to
  test precision.

## Generalisation to unseen ransomware

The dataset has no family labels. Trace names identify three encryption
scenarios of one lab encryptor: asymmetric (48 runs), AES (24) and Salsa20
(24). Each scenario is held out in turn: it is removed from training and
validation, and all of its runs are scored as unseen. This tests an unseen
scenario of the same encryptor, not unseen families. Family-level claims
require external traces of real Linux ransomware replayed through the M2
feature schema.

## Explainability criteria

Tree models must provide SHAP explanations using the same ordered feature
schema saved with the model (Lundberg et al., 2020). Evaluation includes:

- global mean absolute SHAP ranking;
- local top contributors for true positives, false positives and false
  negatives;
- sign/direction of each local contribution;
- agreement between leading SHAP features and plausible behavioural evidence;
- explanation stability across small perturbations or adjacent windows.

Following the explanation criteria of Warnecke et al. (2020), also report:

- **Faithfulness:** set the k features with the largest positive SHAP value to
  the median of training benign windows. The ransomware probability must fall
  more than when k random features are replaced (k = 1, 3, 5).
- **Sparsity:** the share of total absolute SHAP held by the top 3, 5 and 8
  features. The API shows 8.
- **Efficiency:** SHAP computation time per alert.
- **Completeness:** every model alert carries an explanation.

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
- M2 stage latency, from a complete window to the response including SHAP:
  proposed ≤ 1 second at p95 on the Ubuntu detection VM;
- encrypted files before detection/containment: minimize and report;
- offline time to first alert: share of ransomware runs alerted in their first
  five-second window;
- CPU, memory and inference latency: report on the Ubuntu VM target;
- adversarial recall retained: ≥60% under the defined evasion tests.

Offline classifier latency and live end-to-end detection latency are reported
separately.

## Window-scope parity

Live windows must use the training scope: five seconds over all processes of
one host (REQ-M2-08 in the M2 test plan). In an exploratory check, re-windowing
held-out benign data per process raised the served Random Forest from 0 to 150
of 306 benign windows alerted (49%); the Random Forest without
process-concentration features stayed at 0. Any other live scope requires
retraining and re-validation.

## Robustness tests

Evaluate slowed encryption, partial encryption, no extension change, no
rename, work split across processes, plausible process identity, and
high-activity/high-entropy benign workloads. Report the point where detection
fails instead of claiming universal resistance.

## Acceptance decision

Automatic-response eligibility requires all of the following, on held-out
runs and on the external hard-benign set:

- precision ≥90%;
- FPR <2%, overall and for every benign workload;
- recall ≥80%;
- F1 ≥0.85;
- precision and FPR targets demonstrated by their one-sided 95% bounds, not
  only observed (proposed);
- at most one false incident per host-day (proposed);
- no severe workload-specific false-positive pattern;
- reproducible run-level evaluation;
- live windows that match the training scope;
- an explanation available for each model alert that passes the faithfulness
  check.

If classification targets are missed, the model can remain dashboard-only
while the honey-file high-confidence path continues to trigger response.

## Evaluation status (6 November 2026)

### Primary split

On the seed-321 test split (29 runs, 335 windows), Logistic Regression and
Random Forest score 1.000 on every metric; XGBoost has one compression false
positive (precision 0.967, window FPR 0.33%, run FPR 7.14%). All three scored
1.000 on validation, so the Random Forest choice is provisional under the
tie-break rule: the unrounded comparison picked it because Logistic
Regression's PR-AUC was 0.9999999999999999.

Even with zero errors, this split demonstrates only precision ≥ 0.902 (29
alerts), run-level recall ≥ 0.819 (15 runs) and run-level FPR ≤ 19.3% (14
benign runs).

### Repeated cross-validation

Ten repetitions of five-fold cross-validation (185 runs, 2,253 windows); mean
over repetitions with the least favourable one-sided 95% bound:

| Model and threshold rule | Window precision | Window recall | Window FPR | Benign runs with an alert |
|---|---|---|---|---|
| Random Forest, current rule | 0.944 (≥ 0.866) | 0.995 (≥ 0.953) | 0.55% (≤ 1.41%) | 6.9% (≤ 15.6%) |
| Logistic Regression, current rule | 0.954 (≥ 0.820) | 0.993 (≥ 0.968) | 0.46% (≤ 1.97%) | 7.4% (≤ 20.9%) |
| XGBoost, current rule | 0.948 (≥ 0.859) | 0.992 (≥ 0.953) | 0.52% (≤ 1.46%) | 7.2% (≤ 19.6%) |
| Random Forest, midpoint threshold (comparison) | 0.990 (≥ 0.953) | 0.985 (≥ 0.939) | 0.09% (≤ 0.44%) | 1.7% (≤ 8.5%) |

- No ransomware run was missed in any repetition (run-level recall ≥ 0.969);
  99.8% of ransomware runs alert in their first five-second window and all
  within 10 seconds.
- The single split was favourable: average targets still hold, but the
  precision target is not demonstrated (bound 0.866).
- False alerts are concentrated in filebench file-server runs: Random Forest
  window FPR 8.2% (up to 13.8%) with an alert in 26% of filebench runs,
  against 0.5% for compression and 0% for browser and idle runs. This breaks
  the per-workload criterion. `fileserver_2` and `fileserver_3` were alerted
  in all ten repetitions.
- Random Forest is the most stable candidate: fold PR-AUC never fell below
  0.9975, while Logistic Regression dropped to 0.50 in one fold and produced
  up to 30 false-alert windows in one repetition.

The current threshold rule keeps the lowest tied threshold. For the served
model that is 0.13, just above the highest benign validation probability
(0.128), although the lowest ransomware validation probability is 0.854. The
threshold therefore depends on which benign runs are in validation: across
folds the selected Random Forest threshold ranged from 0.04 to 0.68 (median
0.135), and from 0.08 to 0.66 within a single repetition. Taking
the midpoint of the tied thresholds instead removes about 83% of false-alert
windows (11.4 → 1.9 per repetition) and loses 2 of 192 ransomware windows but
no ransomware run. The served threshold is not changed, because of the
unseen-scenario result below.

### Unseen encryption scenario

With the current rule, every held-out run is detected by every model:
asymmetric 48/48, AES 24/24 and Salsa20 24/24, with no false alerts on the 14
benign test runs for Random Forest. With the midpoint rule, Random Forest and
XGBoost detect **none of the 48 asymmetric runs** when that scenario is
unseen; their median probability on these runs is about 0.37. Logistic
Regression still detects all 48.

The low threshold therefore both causes the filebench false alerts and lets
the tree models catch an unseen scenario. Choosing the operating point is a
trade-off between precision and detection of unseen ransomware. It must be
decided on the external hard-benign set and external ransomware traces, and
fixed before that test. One option for M5/M6 is two operating points: a
low review threshold for the dashboard and a high-confidence threshold, the
only one ever considered for response.

### False alerts per host-day

Projected for 24 hours of continuous scoring of the published benign mix,
which is dominated by I/O-heavy workloads:

- Random Forest, current rule: about 96 false alerts and 52 false incidents
  per host-day (upper bounds 243 and 121); precision 0.15 if 0.1% of windows
  were ransomware.
- Random Forest, midpoint rule: about 16 false alerts and 13 false incidents
  per host-day (upper bounds 77 and 65); precision 0.52 at 0.1% prevalence.

Both are far above the proposed one false incident per host-day, and the
dataset is too small to demonstrate that target in any case.

### Explanation quality

For the served Random Forest (29 test alerts):

- **Faithful:** replacing the top 1, 3 and 5 SHAP features with benign
  medians lowers the probability by 0.40, 0.72 and 0.86 on average, against
  0.06, 0.18 and 0.28 for random features. Top-5 replacement clears 76% of
  alerts; random replacement clears none.
- **Not sparse:** the top 3 features hold 51% of absolute attribution and the
  8 shown by the API hold 79%; 80% needs 8–10 features.
- **Stable on adjacent windows:** top-5 Jaccard 0.768 and Spearman rank
  correlation 0.66 over 306 pairs; no acceptance threshold has been agreed.
- **Cheap:** on the development Mac, TreeSHAP takes 0.47 ms per alert (p95
  0.52 ms) and a single-window Random Forest prediction 26 ms (p95 28 ms;
  about 10 ms single-threaded in a separate check). Both are far below the
  proposed 1-second M2 allocation; the Ubuntu VM figure is still required.

### Errors explained

TreeSHAP was run on every Random Forest error in the first cross-validation
repetition: 8 false-alert windows (six filebench, two compression) and 4 missed
windows.

- Seven of the eight false alerts had a probability of only 0.10–0.25 and fired
  because their folds selected thresholds of 0.08–0.09. The feature pushing
  them towards ransomware most often was `metadata_ratio`, the share of
  stat-type system calls (6 of 8). File-server windows have a median of 0.124,
  close to the ransomware lower quartile of 0.133.
- The one confident false alert (`fileserver_2`, probability 0.75) also had a
  single process producing 95% of the events, which is typical of the
  encryptor (ransomware median 0.977).
- The four missed windows came from three AES/Salsa20 runs in one fold whose
  threshold was 0.66; each of these runs still alerted on another window. A
  lower single-process share (`max_pid_share` 0.63–0.73) pushed three of them
  towards benign.
- Without the three process-concentration features, Random Forest has the same
  filebench false-alert rate (8.3%) and a lower median probability on unseen
  asymmetric runs (0.18 instead of 0.37). These features do not cause the
  false alerts and help with the unseen scenario.

The explanations point at plausible behaviour: metadata-heavy legitimate file
activity resembles encryption. The external hard-benign set must therefore
include file-server and backup loads.

### Decision

The model is **not eligible for automatic response** and stays alert-only:

- precision is not demonstrated by its bound;
- filebench breaks the per-workload false-positive criterion;
- the projected false-incident rate is far above the proposed target;
- the selected threshold is unstable across folds, and detection of an unseen
  scenario depends on a threshold at the edge of benign scores.

The remaining evidence needs M1 and the testbed:

- external hard-benign IRDP evaluation, including file-server and backup loads
  and at least 72 hours of benign host activity;
- live Ubuntu end-to-end latency and resource measurements;
- robustness/evasion tests and explanation stability under evasion;
- confirmation that leading features behave similarly in live Wazuh/auditd
  telemetry, with windows that match the training scope;
- external traces of real ransomware families.

Reproduce the robustness results with `bash scripts/evaluate_robustness.sh`.

## References

AI-RDR Capstone Team. (2026). *AI-RDR implementation document: Consolidated
reference for Semester 2 implementation* [Unpublished project document].

Anonymous. (2026). *Ransomware's Lifecycle Dataset* [Data set]. Zenodo.
https://doi.org/10.5281/zenodo.18502469

Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F.,
Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine
learning in computer security. In *Proceedings of the 31st USENIX Security
Symposium* (pp. 3971–3988). USENIX Association.

Axelsson, S. (2000). The base-rate fallacy and the difficulty of intrusion
detection. *ACM Transactions on Information and System Security, 3*(3),
186–205. https://doi.org/10.1145/357830.357849

Brier, G. W. (1950). Verification of forecasts expressed in terms of
probability. *Monthly Weather Review, 78*(1), 1–3.
https://doi.org/10.1175/1520-0493(1950)078<0001:VOFEIT>2.0.CO;2

Cawley, G. C., & Talbot, N. L. C. (2010). On over-fitting in model selection
and subsequent selection bias in performance evaluation. *Journal of Machine
Learning Research, 11*, 2079–2107. https://jmlr.org/papers/v11/cawley10a.html

Chicco, D., & Jurman, G. (2020). The advantages of the Matthews correlation
coefficient (MCC) over F1 score and accuracy in binary classification
evaluation. *BMC Genomics, 21*, Article 6.
https://doi.org/10.1186/s12864-019-6413-7

Clopper, C. J., & Pearson, E. S. (1934). The use of confidence or fiducial
limits illustrated in the case of the binomial. *Biometrika, 26*(4), 404–413.
https://doi.org/10.1093/biomet/26.4.404

Hanley, J. A., & Lippman-Hand, A. (1983). If nothing goes wrong, is everything
all right? Interpreting zero numerators. *JAMA, 249*(13), 1743–1745.
https://doi.org/10.1001/jama.1983.03330370053031

Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B.,
Katz, R., Himmelfarb, J., Bansal, N., & Lee, S.-I. (2020). From local
explanations to global understanding with explainable AI for trees. *Nature
Machine Intelligence, 2*(1), 56–67. https://doi.org/10.1038/s42256-019-0138-9

Saito, T., & Rehmsmeier, M. (2015). The precision-recall plot is more
informative than the ROC plot when evaluating binary classifiers on imbalanced
datasets. *PLOS ONE, 10*(3), Article e0118432.
https://doi.org/10.1371/journal.pone.0118432

Warnecke, A., Arp, D., Wressnegger, C., & Rieck, K. (2020). Evaluating
explanation methods for deep learning in security. In *2020 IEEE European
Symposium on Security and Privacy (EuroS&P)* (pp. 158–174). IEEE.
https://doi.org/10.1109/EuroSP48549.2020.00018
