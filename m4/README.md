# AI-RDR M4: Threat-Intelligence Enrichment

Looks up file hashes, IPs and domains in **abuse.ch** (MalwareBazaar, ThreatFox,
URLhaus; primary) and **OTX** (secondary context) and attaches the reputation
to AI-RDR alerts, in the background. It is **context only**: detection is done
by M2 (ML) and M3 (honey files).

**Start here:** `docs/M4_BUILD_REPORT.md` covers what's done, what's unverified and your to-do list.

## Quick start
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -t .        # 94 offline tests

# Demo without keys (fake data, clearly labelled MOCK):
M4_MOCK_PROVIDERS=1 .venv/bin/python -m m4_threat_intel.app
.venv/bin/python scripts/e2e_smoke.py

# Real use:
cp .env.example .env      # add ABUSECH_AUTH_KEY and OTX_API_KEY; never commit .env
set -a; . ./.env; set +a
.venv/bin/python -m m4_threat_intel.app                    # http://127.0.0.1:5004
```

## API
| Method | Path | Purpose |
|---|---|---|
| POST | `/enrich` | synchronous lookup → contract response |
| POST | `/enrich/async` | 202 + `job_id`; use this from the alert path |
| GET | `/enrich/jobs/<job_id>` | `pending` / `done` / `failed` + result |
| GET | `/health`, `/stats` | liveness, and cache/job counters |

Contract: `docs/interface_contract.md`.

## Layout
| Path | What |
|---|---|
| `m4_threat_intel/` | config, schema, providers (abuse.ch, OTX, mock), enricher, cache, rate limit/retry, jobs, Flask app, M5 client |
| `integrations/custom-m4-enrich.py` | Wazuh custom integration (see `docs/wazuh_integration.md`) |
| `scripts/` | live check scripts (need your keys), sample generator, end-to-end smoke test |
| `docs/` | contract, API notes, phase notes, Wazuh/M5/M6 integration, Assessment 7 test plan, build report |
| `data/` | allowlist example, mock indicators, M6 sample responses |
