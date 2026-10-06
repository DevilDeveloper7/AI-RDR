# AI-RDR — System Architecture & Interaction Diagrams

Real, current-state diagrams of how the test environment's hosts actually talk to each
other — grounded in what's been built and independently verified in this project, not
just the design on paper. Where something isn't live yet, it's marked as such.

## 1. Infrastructure topology

```
 AI-RDR TEST ENVIRONMENT (3 VMs, flat LAN, no VLAN isolation yet)
 --------------------------------------------------------------------------------------

   +------------------+   auditd events,        +------------------+
   |  airdr-target    |   rules 100100/100103    |   airdr-siem     |
   |  192.168.70.64   |------------------------->|   192.168.70.62  |
   |  Wazuh agent,    |                          |  Wazuh Manager + |
   |  honeyfiles,     |<-------------------------|  Indexer         |
   |  auditd          |   SSH (arm-executor,     +------------------+
   +------------------+   scoped sudoers)                 |
            ^                                              | active-response POST
            |  real actions (isolate,                      | on honey-file rule match
            |  quarantine, kill, backup)                   v
            |                                     +------------------+
            +-------------------------------------|   airdr-detect   |
                                                   |   192.168.70.63  |
                                                   |  Flask backend   |
                                                   |  (ARM + IRDP +   |
                                                   |   Risk Fusion +  |
                                                   |   AICM)          |
                                                   |  React dashboard |
                                                   |  (scaffold only) |
                                                   +------------------+

 Provisioning: Ansible playbooks, run via SemaphoreUI --> all 3 VMs above.
 Secrets: a dedicated secrets manager (Infisical) --> read by airdr-detect and by
          the provisioning playbooks themselves. Never hardcoded into any playbook.
```

**Status**: all three `airdr-*` VMs are live and independently verified. No VLAN/
firewall isolation between them yet (flat LAN) — deferred by design until live
detonation testing is actually greenlit.

## 2. The proven detect → respond → reverse loop (independently verified live)

This is the core loop, including a real disruptive action executed and reversed —
not just designed on paper.

```
mock_ransomware_       airdr-target        airdr-siem         airdr-detect        Analyst
behavior.py                                (Wazuh)             (ARM backend)      (approval gate)
     |                     |                    |                    |                  |
     |--touch decoy file-->|                    |                    |                  |
     |  (e.g. /srv/finance/|                    |                    |                  |
     |  Q3_2026_Payroll_   |                    |                    |                  |
     |  Master.xlsx)       |                    |                    |                  |
     |                     |--auditd event----->|                    |                  |
     |                     |  (audit key        |                    |                  |
     |                     |  airdr_honeyfile_  |                    |                  |
     |                     |  access)            |                    |                  |
     |                     |                    |--rule 100100/103   |                  |
     |                     |                    |  match (level 12,  |                  |
     |                     |                    |  MITRE T1486)      |                  |
     |                     |                    |--active-response-->|                  |
     |                     |                    |  POST /api/arm/    |                  |
     |                     |                    |  trigger           |                  |
     |                     |                    |                    |--selects PB-04-->|
     |                     |                    |                    |  (Honey-File     |
     |                     |                    |                    |   Trigger)       |
     |                     |                    |                    |--writes          |
     |                     |                    |                    |  pending_approval |
     |                     |                    |                    |  record, NOT     |
     |                     |                    |                    |  executed        |
     |                     |                    |                    |                  |
     |     [ disruptive playbooks PB-01/03/04 always stop here for a human decision ]    |
     |                     |                    |                    |                  |
     |                     |                    |                    |<--POST approve---|
     |                     |<---SSH (arm-executor, scoped sudoers)----|                  |
     |                     |    iptables airdr_isolate chain          |                  |
     |                     |--isolate_host: success------------------>|                  |
     |                     |  (mgmt channel on :22 preserved)         |                  |
     |                     |                    |                    |--opens real AICM-|
     |                     |                    |                    |  case record     |
     |                     |                    |                    |<--POST undo------|
     |                     |<---SSH: remove airdr_isolate chain-------|                  |
     |                     |--reversed, INPUT back to normal UFW----->|                  |
```

**Verified live**: real alert (`rule_id 100100`) → real `pending_approval` → approved →
real `iptables` isolation chain created on `airdr-target` (confirmed via live packet
counters, not just the API's success response) → SSH access preserved through the
isolation (the quarantine-bridge design) → released → chain confirmed fully removed.

**PB-02 (Suspicious Behaviour)** is the one playbook that auto-executes without the
approval gate — both its actions (backup, throttle) are reversible/low-blast-radius.
Also proven live multiple times through real, non-synthetic Wazuh telemetry.

## 3. Full detection → decision → response pipeline (current state)

```
[LIVE] SIEM (Wazuh)         -> [LIVE] IRDP            -> [LIVE] AI/ML Engine
  airdr-siem, real alerts      poll+normalize+dedup       real v3 ensemble (RF+XGB),
                                real OpenSearch writes     real ai-rdr-ml-detections-*

[LIVE] AI/ML Engine         -> [LIVE] Risk Fusion       -> [LIVE] ARM
  anomaly_score per entity     ML + threat-intel           graded playbooks PB-01..04,
                                corroboration table         real approve/execute/undo

[LIVE] Threat Intelligence  -> [LIVE] Risk Fusion
  VirusTotal public API v3     (capped at "medium" until
  + caching layer               a real match occurs -
                                 zero real alerts recently,
                                 so untested against a real
                                 positive hit yet)

[LIVE] ARM (PB-01/03/04)    -> [LIVE] AICM
  real playbook execution      real correlated case records,
                                lifecycle tracking, ranked
                                recommendations (templated,
                                no LLM call)

[WIP]  PathPredict           -> ARM / dashboard (display-only)
  directory-order prediction   code live-wired into IRDP;
  (within-directory ranking,   empirical validation against
  live per-incident accuracy   the real Linux filesystem
  tracking)                    still pending - deliberately
                                never wired into any
                                automated action until that
                                validation passes

[TODO] Operational Dashboard -> (everything above)
  React scaffold only, no
  real case/alert UI yet
```

`[LIVE]` = live and independently verified against real, non-synthetic data.
`[WIP]` = code written, unit-tested, and live-wired; one empirical validation step
still open before it can feed any automated action. `[TODO]` = not started.

## 4. Credential/access architecture (least-privilege, per-purpose)

A deliberate pattern this project settled on rather than reusing one broad credential
everywhere: every automated component that touches live infrastructure gets its own
narrowly-scoped identity, stored in a secrets manager, never the shared bootstrap key.

| Credential | Scope | Used by |
|---|---|---|
| Shared bootstrap key | Passwordless sudo, all 3 VMs | Ansible provisioning only, never a running service |
| `arm-executor` | Sudoers scoped to exactly ARM's action commands (`iptables`, `kill -9`, `mv`/`chmod`, `chattr`, `cp`, `ls`) on `airdr-target` | ARM + PathPredict's `SSHHostController`, live |
| `irdp-writer` | Read `wazuh-alerts-*`, write `ai-rdr-*` only, no cluster-admin | IRDP's OpenSearch access, live |
| `threat-intel-cache-agent` | Read/write/create-index on exactly one cache index, nothing else | Threat-intel caching layer, live |
| OpenSearch `admin` | Full cluster access | Manual verification only, never a running service |

Every credential above was independently verified live: each new role's scope was
tested against a real out-of-scope index/host and confirmed denied, not just assumed
correct from the role definition.

## Known gaps, stated plainly

- No VLAN/network isolation between the 3 `airdr-*` VMs yet.
- PathPredict's core assumption (alphabetical file-touch order, empirically validated
  on Windows sandbox data) has **not yet been re-checked against real Linux/ext4
  behavior** on `airdr-target` — Linux's default htree directory indexing doesn't
  guarantee the same ordering NTFS's enumeration API does. Runs display-only (feeds no
  automated action) until that validation happens.
- Risk Fusion's threat-intel path is live end-to-end but has never processed a real
  positive match yet — real monitored activity has been quiet, so every real trigger
  observed so far has been capped at `medium` (the expected result with no threat-intel
  corroboration, not a bug).
- The Operational Dashboard (React) is a bare scaffold — no real alert feed, case view,
  or analyst controls built yet.
- AICM's case-management logic is real and tested but not yet wired into the live ARM
  deployment (code-complete, deployment pending).
