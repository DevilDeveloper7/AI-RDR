# Phase 3 notes (Week 3): core client

## What was built and why
- `http.py`: one place that turns timeouts, network errors, bad HTTP statuses and bad JSON into a `ProviderError` with a short message that never contains the key. Phase 4 adds retry and rate limiting here.
- `providers/abusech.py`: MalwareBazaar, ThreatFox and URLhaus behind one provider.
  - Routing: hash → MalwareBazaar then ThreatFox (ThreatFox skipped for SHA-1, which it doesn't support); ip/domain → ThreatFox then URLhaus.
  - Combining: any hit → hit (highest score, tags merged); no hit but a service failed → **error** (we can't claim "not found" if one service didn't answer); otherwise miss.
  - Scores: MalwareBazaar 95; ThreatFox `confidence_level`, or 75 if missing; URLhaus 85 if any URL is online, otherwise 25 (changed from 70 after the live run: offline-only history is context only, see `docs/api_notes.md`).
  - A missing key gives a clear error with **no network call**.
  - Only the exact found/not-found `query_status` values are accepted. Anything unexpected becomes an error, so the UNVERIFIED parts of the abuse.ch format fail safely.
- `providers/otx.py`: types hash→`file`, ip→`IPv4`/`IPv6`, domain→`domain` (verified against the official SDK). 404 or zero pulses → miss. Hit score `min(60, 25 + 5 × pulses)`. Up to 20 pulse tags are collected. If OTX's own `validation` (whitelist) field is set, the result is a miss, never "clean".
- `enricher.py`: normalise → allowlist → non-routable IP guard → providers → `verdict_for`.
  - abuse.ch is asked first. OTX is always asked for ip/domain, and for a hash only if abuse.ch didn't confirm it.
  - `verdict_for`: score ≥ 80 with a trusted (non-OTX) hit → malicious; ≥ 30 with any hit → suspicious; otherwise unknown. OTX's contribution is capped at 60 there as well (defence in depth), and `config.py` asserts 60 < 80.
- `/enrich` now uses the real enricher. With no keys it returns `unknown` plus an explicit error.

## Bug found by the tests
Two enricher tests first used `203.0.113.9`. That is a reserved documentation address (TEST-NET-3), so the non-routable guard correctly refused to send it out. The tests and the doc example now use a public address.

## Tests
`.venv/bin/python -m unittest discover -s tests -t .` → 54 tests, OK (offline, fake HTTP session).
Real run by Claude Code (server without keys):
- `example.com` → `unknown` with "ABUSECH_AUTH_KEY is not set; OTX_API_KEY is not set"
- allowlisted `example.org` → `clean`
- `192.168.1.20` → `unknown`, no error (never sent out)

## Scenario → verdict (each row proven by a test)
| Scenario | Verdict | Test |
|---|---|---|
| Not found in any source | unknown (score 0, no error) | `test_enricher.test_not_found_is_unknown_not_clean` |
| All lookups failed | unknown + error, **never clean** | `test_enricher.test_failure_is_never_clean` |
| No API keys | unknown + "key not set" error | `test_app.test_without_keys_result_is_unknown_with_error_never_clean` |
| OTX hit only (even if it claimed 100) | suspicious, score ≤ 60, **never malicious** | `test_enricher.test_otx_alone_is_never_malicious` |
| abuse.ch hit, score 95 | malicious | `test_enricher.test_abusech_high_score_is_malicious` |
| abuse.ch hit, score 50 / 10 | suspicious / unknown | `test_enricher.test_medium_score_is_suspicious_low_score_unknown` |
| Hit + another source failed | hit verdict kept, error reported | `test_enricher.test_partial_failure_keeps_hit_and_reports_error` |
| Private/loopback/link-local IP | unknown, zero provider calls | `test_enricher.test_private_ip_makes_zero_provider_calls` |
| On local allowlist | clean, zero provider calls | `test_enricher.test_allowlist_is_clean_without_calls` |
| abuse.ch service fails, other says not found | provider error (not "miss") | `test_abusech.test_one_service_failing_without_hit_is_error_not_miss` |
| Unexpected `query_status` | error (not "miss") | `test_abusech.test_unexpected_query_status_is_error_not_miss` |
| OTX whitelisted (`validation`) | miss (not clean) | `test_otx.test_validation_is_miss_never_clean` |

## UNVERIFIED
The abuse.ch response details listed in `docs/api_notes.md`. The fake responses in the tests follow that document. They are **not** recordings of real API answers.
