# AI-RDR — AI-Based Ransomware Detection and Response System

Capstone diploma project: a layered detection and response pipeline combining SIEM
telemetry, AI/ML behavioral detection, honey-file deception, threat-intelligence
enrichment, a risk-fusion decision engine, automated graded response, and incident
case management.

## Repository contents

- **`docs/system-architecture.md`** — current-state architecture diagrams: infra
  topology, the full detect → decide → respond pipeline, the proven end-to-end
  detect/respond/reverse loop, credential architecture, and known gaps — stated
  plainly, not just the design-on-paper version.
- **`ansible/`** — the Ansible playbooks used to provision the test environment's 3
  VMs from scratch: base OS hardening/bootstrap, Wazuh SIEM manager setup, the
  detection host (ARM backend + IRDP + ML + Risk Fusion + AICM), the simulated
  protected endpoint (honey-files + auditd), and the credential-provisioning
  playbooks for each component's least-privilege identity.
- **`m2/`** — Pavel's reproducible behavioural-ML package: Lifecycle dataset
  normalization, leakage-safe windowing, parity-safe features, Logistic
  Regression/Random Forest/XGBoost evaluation, TreeSHAP, an alert-only inference
  API, tests, model documentation, and compact evaluation reports. Raw datasets,
  virtual environments, and generated model binaries are intentionally excluded.
- **`backend/`** — the real IRDP/Risk Fusion/ARM/AICM application: event
  normalization and windowing, the RF+XGB anomaly-scoring ensemble, threat-intel
  enrichment (with caching and a degraded-mode-safe fallback), the graded
  response module (approval gating, full undo support), the incident case
  manager, PathPredict, and `m2_client.py` — the integration seam that adapts
  `m2/`'s independently-developed model into this pipeline as a second,
  display-only opinion that `backend/risk_fusion.py`'s `fuse()` never reads
  (see that module's own docstring for the full scope boundary). A trained
  ensemble snapshot ships under `models/registry/`.
- **`pipeline/`** — offline dataset loaders/feature extraction/training code for
  the project's own RF+XGB ensemble (separate from `m2/`'s own training
  pipeline, trained on a different, only-partially-overlapping set of
  datasets).

### Testing: mock services, not live infrastructure

`backend/`'s test suite (run with `pytest backend/tests/`) exercises the full
detect → decide → respond → case pipeline end to end using fakes in place of
every live dependency — `FakeEventSource`, `FakeThreatIntelClient`,
`FakeM2Client`, `FakeHostController`, `InMemoryCaseStore`, and others in
`backend/tests/fakes.py` — so the whole pipeline's logic is independently
verifiable by anyone cloning this repo, with no real SIEM, OpenSearch cluster,
SSH-reachable host, or M2 service required. Live infrastructure verification
(real alerts, real approved actions, real reversal) is documented separately
in `docs/system-architecture.md`, since that can't be reproduced outside the
original test environment.

## Layered architecture

1. **SIEM / Intelligent Data Pipeline** — Wazuh + OpenSearch, IRDP (poll, normalize,
   deduplicate, write)
2. **Detection** — honey-file deception (auditd-based), AI/ML behavioral engine
   (Random Forest + XGBoost ensemble), PathPredict (directory-order prediction)
3. **Decision** — Risk Fusion (corroborates ML anomaly score + threat-intelligence
   match into a single risk tier)
4. **Response** — Automated Response Module (graded containment playbooks, approval
   gating for disruptive actions, full undo support)
5. **Case Management** — AI Incident Case Manager (correlation, lifecycle tracking,
   ranked recommendations)
6. **Dashboard** — React/Flask operational UI (scaffold only, not yet built out)

See `docs/system-architecture.md` for exactly what's live and independently verified
versus still in progress.

## Running the Ansible playbooks against your own environment

The playbooks in `ansible/` reference your own infrastructure's variables (git
remotes, secrets-manager address, inventory host IPs) — none of this project's own
specific infrastructure values are committed here. Replace the placeholder values
(marked clearly in each file) with your own before running.
