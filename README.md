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
