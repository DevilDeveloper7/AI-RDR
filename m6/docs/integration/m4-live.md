# M4 live integration (threat-intelligence enrichment)

M6 reads M4 over HTTP through `backend/app/integrations/m4/real.py` (`RealM4`). Mock mode stays the default.
M4 is **context only**: nothing M4 returns can start, authorise or change a response action. Response decisions stay with M5
(M2 stays alert-only, M3 raises honeyfile events).

## What M6 uses (checked against the M4 source, `m4_threat_intel/app.py`)

| M6 call | M4 endpoint | Notes |
|---|---|---|
| `health()` | `GET /health` | `Connected` = live mode and both keys set. `Warning` = M4 in MOCK mode, or a key missing. `Failed` = M4 not reachable. |
| `list_indicators()` | `GET /indicators?limit=100` | Newest first. M4 keeps these in memory only, so the list is empty after an M4 restart until new alerts are enriched. |
| `enrich(indicator)` | `POST /enrich/m6` | Sent with alert id `m6-lookup`, which M4 never lists as an alert's indicator. |

`/enrich/m5` is M5's endpoint (different record shape). M6 does not use it. M4 already answers in M6's indicator shape, so M6 does not translate anything.

## `meta.is_mock`
`GET /api/v1/threat-intelligence` reports what M4 says about its own data: `true` in mock mode or when M4 runs with `M4_MOCK_PROVIDERS=1`,
`false` only for M4 in live mode. If M4 does not say, M6 treats it as mock.

## Failure behaviour
| Situation | Result |
|---|---|
| M4 not running / refused connection | Integration Status `Failed`; `/threat-intelligence` returns `503`; the alert page still loads with `enrichment_status: "unavailable"` |
| M4 too slow (over `M4_TIMEOUT`) | `504`, same alert-page behaviour |
| M4 returns HTTP 5xx | `503` |
| M4 returns malformed JSON or a record that breaks the contract | `502 MALFORMED_RESPONSE` (single bad items in the list are skipped; all bad = error) |
| M4 refuses an indicator (HTTP 400/422) | `404 INDICATOR_NOT_FOUND` |
| Lookup incomplete inside M4 | Indicator shows `reputation: "Unknown"`, `enrichment_status: "unavailable"`, never `Clean` |

## Start M4
```bash
cd m4
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# demo without API keys (fake data, labelled MOCK):
M4_MOCK_PROVIDERS=1 .venv/bin/python -m m4_threat_intel.app
# real use: put ABUSECH_AUTH_KEY and OTX_API_KEY in m4/.env (never commit it), then
set -a; . ./.env; set +a; .venv/bin/python -m m4_threat_intel.app      # http://127.0.0.1:5004
```
M4 has no authentication. Keep it on `127.0.0.1` unless you are inside the isolated lab network.

## Point M6 at M4
In `m6/.env`:
```
M4_MODE=real
M4_BASE_URL=http://127.0.0.1:5004     # optional; this is the default
M4_TIMEOUT=10                          # optional, seconds
```
Start M6 as usual (`./run.sh`). Back to mock: `M4_MODE=mock`.

## Verify
```bash
curl -s http://127.0.0.1:5004/health                              # M4 itself
curl -s http://127.0.0.1:5001/api/v1/integrations/status          # M4 row: mode "real", status Connected / Warning / Failed
curl -s http://127.0.0.1:5001/api/v1/threat-intelligence          # items + meta.is_mock
curl -s http://127.0.0.1:5001/api/v1/threat-intelligence/203.0.113.9
```
In the dashboard, open Integration Status and press the check button for M4.

## Tests
```bash
python3 -m pytest -q                                                         # unit + fake-HTTP tests (no M4 needed)
M4_LIVE_URL=http://127.0.0.1:5004 python3 -m pytest tests/test_m4_live.py -v # live tests against a running M4
```
`tests/test_real_m4.py` uses a local fake of M4's endpoints. `tests/test_m4_live.py` talks to the real M4 service and is skipped unless `M4_LIVE_URL` is set.
Real threat-intelligence data is only verified when M4 runs in live mode with real keys and internet access.