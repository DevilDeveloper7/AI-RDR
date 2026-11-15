# Using M4 from M5 (response/case manager) and M6 (dashboard)

M6 has not yet specified its format, so it is assumed to consume the agreed
contract response unchanged (`docs/interface_contract.md`). M5 has a fixed
`threat_intel` record format (`m5/ai_rdr_risk.py`); see "M5 record" below.
**Confirm with both teammates.**

## M5
Use `m4_threat_intel/m4_client.py`:
```python
from m4_threat_intel.m4_client import enrich
ti = enrich("hash", sha256, alert_id=case.alert_id, timeout=5)
case.attach("threat_intel", ti)
```
`enrich()` never raises. If M4 is down, slow or broken, you get
`verdict="unknown"` with `error` set, never `clean`.

| Verdict | Suggested M5 handling |
|---|---|
| `malicious` | Attach to the case and raise its priority for the analyst. **Do not** start response on this alone (Final Doc §10: response comes from M2/M3). |
| `suspicious` | Attach as supporting context. |
| `unknown` | Attach as "no intelligence". **Not safe.** If `error` is set, the lookup was incomplete. |
| `clean` | Locally allowlisted. Still never overrides an M2/M3 detection. |

For the alert path, prefer `POST /enrich/async` and poll
`GET /enrich/jobs/<job_id>`, so a slow lookup never delays containment.

### M5 record (`POST /enrich/m5`, or `enrich_for_m5()` in Python)
Put the returned object into `bundle["threat_intel"]`. It is checked against
M5's real `RiskMatrix` in `tests/test_m5_adapter.py`.

| M4 result | M5 `status` | Counts in M5? |
|---|---|---|
| `malicious` (sha256 or IP) | `match`, `malicious: true` | yes, weight 55, only if fresh (see below) and the indicator equals the bundle's `sha256` / `src_ip` |
| `suspicious`, `clean`, `unknown` without error | `no_match` (`m4_verdict` keeps the real verdict) | no (0) |
| `unknown` with `error`, M4 down or timed out | `unavailable` | no (0) |
| mock-mode data (when not allowed) | `unavailable`, `reason: synthetic_data_not_allowed` | no (0) |
| md5, sha1, domain | endpoint answers 422 / `enrich_for_m5` returns `None`: add nothing | n/a |

* `checked_at` is the original `enriched_at` (not renewed by a cache hit).
  M5 accepts it only when `-30 s <= now - checked_at <= 900 s` (900 is inclusive,
  verified). Cache TTLs (600 s hit, 300 s miss) stay below that window.
* Do not copy `checked_at` into `timestamp`: M5 uses `timestamp` for a different rule.
* M4 and M5 hosts need NTP-synced clocks.

## M6 (threat-intelligence panel)
M6 reads M4 live through `m6/backend/app/integrations/m4/real.py` (`RealM4`).
Turn it on in M6's `.env`: `M4_MODE=real` (empty `M4_BASE_URL` = `http://127.0.0.1:5004`).
Default stays `mock`.

| M6 call | M4 endpoint | Notes |
|---|---|---|
| `list_indicators()` | `GET /indicators?limit=N` | The most recent answers (max 500, in memory, newest first, one per alert + indicator). Empty after an M4 restart until new alerts are enriched. |
| `enrich(indicator)` | `POST /enrich/m6` | Alert id `m6-lookup`: never listed as an alert's indicator. |
| `health()` | `GET /health` | Connected = live and both keys set. Warning = mock mode or a key missing. Failed = M4 not reachable. |

Both M4 endpoints answer in M6's INDICATOR shape (`m4_threat_intel/m6_adapter.py`):

| M4 verdict | `reputation` | `enrichment_status` |
|---|---|---|
| malicious | Malicious | enriched |
| suspicious | Suspicious | enriched |
| clean (allowlist) | Clean | enriched |
| unknown, nothing found | Unknown | no_data |
| unknown, lookup failed | Unknown | unavailable (never "Clean") |

`type` is `SHA-256`, `SHA-1`, `MD5`, `IP address` or `Domain`. `related_alert` is the
alert id M4 was called with (M1/M5/the Wazuh script must call `/enrich` with the real alert id,
or the indicator will not be shown under that alert). Mock-mode answers say "(mock)" and "MOCK DATA".
If M4 is down, M6 shows its normal "unavailable" state (the alert page still loads).

Suggested fields to show: `reputation` (coloured badge), `source`, `last_checked`, `notes`,
`enrichment_status` (warning when `unavailable`). Label Unknown as "No threat intelligence", not "Safe".
