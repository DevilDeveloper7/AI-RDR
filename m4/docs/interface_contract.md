# M4 interface contract

M4 enriches one indicator per request. It **adds context**. It does not decide
whether something is ransomware; M2 (ML) and M3 (honey files) do that.

## Request
| Field | Type | Rules |
|---|---|---|
| `alert_id` | string | Non-empty, at most 200 characters. The ID of the alert this indicator came from. |
| `type` | string | `"hash"`, `"ip"` or `"domain"` |
| `value` | string | hash: hex MD5, SHA-1 or SHA-256. ip: IPv4 or IPv6. domain: DNS name. M4 normalises it (lowercase, trims spaces, standard IPv6 form, no trailing dot). |

## Response
| Field | Type | Meaning |
|---|---|---|
| `alert_id` | string | Copied from the request. On a cached answer it is the **current** request's ID. |
| `type`, `value` | string | Indicator type and normalised value |
| `verdict` | string | `malicious`, `suspicious`, `unknown` or `clean` (see below) |
| `score` | int 0–100 | Strength of the reputation evidence. 0 when there is no evidence. |
| `sources` | [string] | Sources that **reported a hit**, e.g. `["malwarebazaar"]` |
| `tags` | [string] | Tags from the sources (malware family, threat type...) |
| `cached` | bool | `true` if the answer came from M4's cache |
| `error` | string or null | Set when at least one lookup failed. **Never** cached. |
| `details` | [object] | One entry per source asked: `provider`, `status` (`hit`/`miss`/`error`), `score`, `tags`, `details`, `error` |
| `latency_ms` | float | Time M4 spent on this request |
| `enriched_at` | ISO-8601 | UTC time the lookup was made. For a cached answer, the time of the original lookup. |

## Verdict meanings
| Verdict | When | What M5/M6 should do |
|---|---|---|
| `malicious` | score ≥ 80 from a trusted source (abuse.ch) | Strong context: show prominently. It does not trigger response on its own. |
| `suspicious` | a source reports it, score 30–79, or OTX only | Weak context: show it, don't act on it alone |
| `unknown` | not found anywhere, **or** the lookup failed, **or** a private IP, **or** only weak context (e.g. URLhaus knows the host only from old offline URLs; then `sources`/`tags` show it) | No evidence. **This does not mean safe.** |
| `clean` | the indicator is on M4's local allowlist (and only then) | Known good by local decision |

> **`unknown` ≠ `clean`.** Most new or lab-built ransomware will not be in any
> public feed, so "unknown" is the normal result and must never be read as "safe".

## Rules for other modules
- **M1** sends only indicators it actually extracted from an alert. No need to filter private IPs, because M4 never sends them out.
- **M5** treats threat intelligence as context. The decision to respond comes from M2/M3 (Final Doc §10). If `error` is set, the result is incomplete.
- **M6** shows `verdict`, `score`, `sources`, `tags` and `error`, and should label `unknown` as "no intelligence", not as "safe".

## Endpoints (localhost:5004)
| Method | Path | Purpose |
|---|---|---|
| POST | `/enrich` | Synchronous lookup and contract response (for testing and demos) |
| POST | `/enrich/async` | Validates the request, replies 202 `{"job_id"}` immediately, and does the lookup in the background. **Use this one from the alert path.** |
| GET | `/enrich/jobs/<job_id>` | `{"status": "pending"/"done"/"failed", "result": ...}` |
| GET | `/health`, `/stats` | Liveness, and cache/job counters |

## Examples
**1. Known malware hash**
```json
{"alert_id": "A-1001", "type": "hash", "value": "<sha256 of a known sample>"}
```
```json
{"alert_id": "A-1001", "type": "hash", "value": "<sha256>", "verdict": "malicious",
 "score": 95, "sources": ["malwarebazaar"], "tags": ["LockBit", "ransomware"],
 "cached": false, "error": null,
 "details": [{"provider": "abusech", "status": "hit", "score": 95, "tags": ["LockBit", "ransomware"],
              "details": {"malwarebazaar": {"status": "hit", "signature": "LockBit"}}, "error": null}],
 "latency_ms": 412.5, "enriched_at": "2026-10-18T12:00:00+00:00"}
```
**2. Not found anywhere**
```json
{"alert_id": "A-1002", "type": "domain", "value": "example.com", "verdict": "unknown",
 "score": 0, "sources": [], "tags": [], "cached": false, "error": null,
 "details": [{"provider": "abusech", "status": "miss", "...": "..."},
             {"provider": "otx", "status": "miss", "...": "..."}],
 "latency_ms": 650.0, "enriched_at": "2026-10-18T12:00:01+00:00"}
```
**3. Lookup failed (no key, or service down)**
```json
{"alert_id": "A-1003", "type": "ip", "value": "8.8.4.4", "verdict": "unknown",
 "score": 0, "sources": [], "tags": [], "cached": false,
 "error": "abusech: ABUSECH_AUTH_KEY is not set; otx: OTX_API_KEY is not set",
 "details": ["..."], "latency_ms": 0.4, "enriched_at": "2026-10-18T12:00:02+00:00"}
```
The values in these examples are illustrative, not real lookups.
