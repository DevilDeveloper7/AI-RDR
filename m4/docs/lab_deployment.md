# Running M4 in the lab (VMs, no internet, any folder)

M4 is context only: if it is slow, down or has no internet, the rest of AI-RDR must keep working
(M6 shows "unavailable", M5 gets status `unavailable`, nothing is ever shown as "Clean").

## Start it
```bash
cd m4
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a            # ABUSECH_AUTH_KEY, OTX_API_KEY (never commit .env)
.venv/bin/python -m m4_threat_intel.app          # http://127.0.0.1:5004
```
Check: `curl -s http://127.0.0.1:5004/health` (mode "live", both keys "set") and `curl -s http://127.0.0.1:5004/stats`.

## Which machine?
M4 listens on 127.0.0.1 by default, so M6 / M5 / the Wazuh integration must run **on the same machine**
(on `airdr-detect`, next to the Flask backend). To reach it from another VM set `M4_HOST=<lan ip of that VM>`
(only inside the isolated lab, M4 has no authentication) and use that address as `M4_BASE_URL` in M6.

## No internet on the VM (or outbound traffic blocked)
Measured: with the defaults one lookup waited about 24 s (retries and back-off for 3 services), longer than M6's
10 s timeout. Two protections now exist:
* **Provider breaker**: after 2 network failures in a row a provider is skipped for 30 s (`M4_BREAKER_THRESHOLD`,
  `M4_BREAKER_COOLDOWN`, 0 = off). `/stats` shows `skipped_providers`.
* For a VM that has no internet at all, start M4 with no retries so even the first lookups answer in about 1-2 s:
```bash
M4_MAX_RETRIES=0 M4_HTTP_TIMEOUT=3 .venv/bin/python -m m4_threat_intel.app
```
Without internet M4 can only say "unknown" (never "clean"); real malicious verdicts need the abuse.ch keys AND outbound HTTPS
to `mb-api.abuse.ch`, `threatfox-api.abuse.ch` and `otx.alienvault.com`. For a demo without internet use
`M4_MOCK_PROVIDERS=1` (fake data, labelled MOCK).

## Other protections
* An unwritable cache folder no longer stops M4 (the cache is switched off with a warning); set `M4_CACHE_PATH` to a writable file.
* The mock data file is found from any working directory.

## Prove the whole chain in one command
```bash
python3 scripts/e2e_demo.py                    # offline demo, M4 starts itself in MOCK mode
python3 scripts/e2e_demo.py --live http://127.0.0.1:5004 --alert results/candidates/alerts/001_Akira.json
```
It runs: Wazuh integration script -> M4 -> M5 (real `RiskMatrix`) -> M6 (real `RealM4` adapter) and prints PASS / FAIL per step.
No malware runs. The M6 step needs `pip3 install -r m6/backend/requirements.txt`.

## How M5 gets the threat intelligence
1. Wazuh runs `integrations/custom-m4-enrich.py` for an alert: it queues the alert's sha256 / IPs in M4 (`/enrich/async`, fail-safe).
2. When M5 builds the evidence bundle for that alert it calls
   `m4_client.threat_intel_for_alert(alert_id)` (or `GET /alerts/<alert_id>/threat_intel`) and puts the returned list in
   `bundle["threat_intel"]`. It never raises; no answer yet means no threat-intelligence evidence, not an error.
3. Records are only valid for 15 minutes (M5 rule), so call it when the bundle is built, not hours later.
