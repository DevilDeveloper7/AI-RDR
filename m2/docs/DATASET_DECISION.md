# M2 dataset decision (weeks 1–2)

## Decision

Use **Ransomware's Lifecycle Dataset** (Zenodo 18502469) as the primary
training source. It is the only listed source that directly matches all core
requirements:

- Linux behavioural telemetry;
- ransomware and benign workloads collected in the same publication;
- syscall/event traces suitable for time windows;
- independent executions that can be kept in separate splits.

Do not merge unrelated rows from every available security dataset. That would
make dataset origin an easy label shortcut and inflate offline scores while
increasing live false positives.

## False-positive controls

1. Split by `run_id` before model work. Adjacent windows from one execution
   always receive the same train/validation/test assignment.
2. Keep benign/ransomware collection conditions comparable. Record collection
   source and reject unknown labels by default.
3. Reserve hard benign Linux runs (backup, `tar`/compression, `rsync`, database
   writes, OpenSSL/GnuPG and bulk file conversion) as a dedicated false-positive
   validation set. These can be collected through M1's auditd/IRDP path so the
   live schema is exact; they supplement rather than replace the public primary
   dataset.
4. Tune the decision threshold against validation precision and FPR, not
   accuracy. Project acceptance targets are precision >= 90% and FPR < 2%.
5. Keep the final benign hard-workload test set out of feature selection,
   resampling and threshold tuning.

## Candidate assessment

- **Lifecycle (primary):** correct OS, modality and both classes. Archive is
  3,111,511,474 bytes; expected MD5
  `103a8e88b66764e1fb1947efd6d2649b`.
- **ELFEN reports (external ransomware test):** useful, small Linux dynamic
  reports for 16 named families. It has no matched benign class and therefore
  must not be the primary training set.
- **Linux-APT-2024 (schema/integration test only):** Linux/Wazuh-like logs with
  general and suspicious events, but its target is APT TTPs rather than
  ransomware behaviour.
- **MLRan (not for the live model):** balanced goodware/ransomware data, but
  feature-selected Cuckoo behaviour is not demonstrably reproducible from the
  Linux Wazuh/auditd stream. Its 483 selected features risk train/deploy drift.
- **EN2025 (not primary):** large balanced endpoint/API and traffic dataset,
  but the published record does not establish Linux auditd parity. Use only if
  its raw schema and OS are later verified.
- **CIC-IDS-2018 and CTU-13 (exclude):** network intrusion/botnet telemetry;
  the M2 detector is currently a host syscall/event detector and network
  detection is deferred.
- **Akira/LockBit metadata (exclude from training):** useful for threat
  intelligence and sample provenance, not sliding-window host behaviour.
- **RanSMAP/RansomSet (defer):** credentials/subscription are unavailable and
  their storage/feature schemas still require a live-parity review.
- **ProvSec (optional benign benchmark):** Linux sysdig syscall traces can test
  the normalizer, but should remain a separate benchmark because collection
  differs from Lifecycle and auditd.
- **“Is it Encrypted?” (optional robustness benchmark):** valuable hard-benign
  crypto/compression coverage, but it uses ftrace function graphs and sensor
  counters rather than the approved Wazuh/auditd schema.

## Verified archive structure

The downloaded archive passed the published MD5 check. Its syscall traces are
headerless trace-cmd/ftrace text, not CSV. The adapter therefore parses
`sys_enter_*` records directly and drops `sys_exit_*` records so each syscall
is represented once, matching auditd semantics more closely.

Ransomware ftrace contains 255 independent phase traces:

- 96 `out_exec_parsed` encryption/execution traces;
- 144 exfiltration traces;
- 15 reconnaissance traces.

The current binary M2 corpus uses the 96 execution/encryption traces as the
positive class. Reconnaissance and exfiltration are excluded because the
implementation document explicitly defers network/exfiltration detection, and
labelling generic reconnaissance/SFTP/compression behaviour as ransomware
would create exactly the over-suspicious model this project must avoid.

The benign side provides 89 syscall runs: browser (25), compression (25),
filebench (15), idle (5), media server (10), and SPEC workloads (9). This is
substantially better negative coverage than a generic “clean idle” class:
compression, browser I/O and file-server workloads are hard benign cases.

A real browser run was parsed successfully: 2,881,360 `sys_enter` events, zero
parse errors. Exact window counts depend on the selected window size/stride and
are generated in the preprocessing report.

## Evidence to report during model work

The preprocessing report must record exact run/scenario counts, class counts,
raw fields, timestamp units, trace ordering, collection differences between
classes, unknown/failed files, window counts and split counts. Family-level
generalisation must not be claimed unless the archive metadata actually maps
independent runs to families.
