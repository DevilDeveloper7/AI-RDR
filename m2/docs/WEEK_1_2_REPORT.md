# M2 weeks 1–2 implementation report

## Scope completed

- reviewed the implementation document and the existing standalone SOC console;
- selected the Lifecycle dataset under the train/deploy parity rule;
- defined a versioned normalized event contract for Lifecycle and live
  Wazuh/auditd/IRDP telemetry;
- implemented CSV, JSON, JSONL, NDJSON and gzip input adapters;
- implemented a streaming adapter for the dataset's nested trace-cmd archives;
- implemented configurable time-based and event-count sliding windows;
- made run-level train/validation/test assignment deterministic;
- rejected unknown labels by default and rejected mixed labels within a run;
- emitted a machine-readable preprocessing report;
- added tests and benign/ransomware smoke traces.

The primary archive was downloaded and verified against its published MD5.
Inspection found 96 ransomware execution/encryption traces and 89 benign
syscall traces. The remaining ransomware-side traces are 144 exfiltration and
15 reconnaissance scenarios; they are deliberately excluded from this M2
binary corpus because those behaviours are deferred in the current design and
would introduce broad positive labels.

The standalone HTML is a bundled dashboard prototype and has no raw telemetry
or M2 backend implementation to reuse. It was therefore left unchanged.

## Default experimental settings

The current 5-second window and 1-second stride are explicit starting
parameters, not claimed optimum values. Week 3–4 experiments should compare
several window sizes under the same held-out runs. The selected setting must be
based on precision, recall, PR-AUC, MCC, FPR and latency, with precision and FPR
treated as response-safety constraints.

## Leakage controls

- windows never cross `run_id` boundaries;
- every window from one run receives the same split;
- split identity does not depend on event rows or window order;
- duplicate/overlapping windows cannot land in different splits;
- labels are run-consistent;
- raw source and schema version remain attached to each event.

## Anti-false-positive plan

Accuracy is not used as the model-selection objective. The validation design
must include high-activity benign workloads: backup/restore, compression,
`rsync`, legitimate OpenSSL/GnuPG encryption, database writes and bulk file
conversion. These runs should be captured through M1's actual IRDP schema.
Threshold tuning happens on validation data; a final hard-benign set remains
untouched for reporting FPR.

The primary model should not be trained by blindly joining CIC-IDS, CTU-13,
MLRan or metadata datasets. Their modality or collection source differs enough
that the classifier could learn the dataset source instead of ransomware
behaviour.

## Handoff to M1/M6

M1 should provide one representative normalized IRDP event containing:
timestamp, independent execution/session identifier, syscall/event type, PID,
process name, file path and byte count when available. M2 will run this sample
through the same normalizer and retain only fields reproducible in both paths.

M6 can treat each JSONL window as the preprocessing contract for now. The
inference endpoint and SHAP response contract belong to weeks 3–4.
