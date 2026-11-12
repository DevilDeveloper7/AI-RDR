# M4 build report: Weeks 1–5

*AI-RDR module M4, threat-intelligence enrichment. Built 18 Oct 2026.*

## Update, 18 Oct 2026: first live run (by Kiana, macOS, Python 3.15)
- All 94 offline tests passed on Kiana's Mac with **Python 3.15**.
- Real abuse.ch calls with Kiana's key:
  - known sample → MalwareBazaar hit → `malicious` 95
  - made-up hash → not found → `unknown`
  - `example.com` → URLhaus with one offline URL only
- These responses are saved as fixtures (`tests/fixtures/`) and covered by `tests/test_live_fixtures.py`.
- Confirmed live: Auth-Key header, MalwareBazaar found/not-found, ThreatFox `no_result`, URLhaus `/v1/host/` found.
- **Rule change:** URLhaus offline-only history scores 25 (context only, verdict `unknown`) instead of 70, because benign `example.com` would otherwise have been flagged `suspicious`.
- Still not checked live: a ThreatFox hit, URLhaus not-found, OTX (no key yet), Wazuh.
- Tests now: **98**, all OK.

## 1. Status
| Done and verified by offline tests (94 tests, all pass) | Run for real by Claude Code | Not verified: needs you |
|---|---|---|
| Input validation and normalisation (hash/IP/domain) | Flask server started; curl `/enrich` returned contract-shaped JSON; bad input → 400 | **Live abuse.ch responses**: the format is partly UNVERIFIED (`docs/api_notes.md`); the build environment could not reach abuse.ch |
| Non-routable IPs never sent out | Server without keys → `unknown` + "key not set" error; allowlisted domain → `clean`; private IP → `unknown` | **Live OTX responses** (format verified from the official SDK, but never called) |
| abuse.ch parsing (MalwareBazaar, ThreatFox, URLhaus) against documented formats | MOCK mode: sync lookup, repeat → `cached: true` with new alert_id, async submit + poll, `/stats` | Real rate limits / 429 behaviour of both providers |
| OTX parsing, score cap 60, `validation` → miss | `scripts/e2e_smoke.py`: synthetic alert → integration script → M4 → enrichment; M4 stopped → script survived | **Wazuh**: version, real alert field names (`sha256_after` inferred; IP paths TODO), install path/permissions, running on the manager |
| Verdict rules (failure ≠ clean, OTX alone ≠ malicious, partial failure) | `scripts/make_sample_responses.py` generated the M6 samples | M5/M6 formats (contract assumed unchanged); whether M6 needs CORS |
| Cache (TTL, errors never cached, thread safety, stats) | Suite with `-W error::ResourceWarning`: no leaks, 0.4 s | Python 3.9 itself: code compiles on 3.11 and has no 3.10+ syntax, but tests ran on 3.13 |
| Rate limit + retry (backoff, Retry-After, no retry on 401/403) | | Free-tier terms (re-verify before submission) |
| Async jobs (202, pending/done/failed, bounded store), never blocks | | |
| Wazuh script and M5 client: fail-safe, no secrets in logs | | |

## 2. What each phase built
Test command (all phases):
`.venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -t .`

| Phase | Commit | Built | Tests after phase |
|---|---|---|---|
| 1 | `phase-1` | `config.py`, `schema.py`, contract, indicator-source and §9 docs | 11 OK |
| 2 | `phase-2` | `docs/api_notes.md`, `scripts/curl_examples.sh`, `try_abusech.py`, `try_otx.py`, `providers/base.py`, stub `/enrich` | 16 OK |
| 3 | `phase-3` | `http.py`, `providers/abusech.py`, `providers/otx.py`, `allowlist.py`, `enricher.py`, real `/enrich` | 54 OK |
| 4 | `phase-4` | `cache.py`, `ratelimit.py`, `jobs.py`, `/enrich/async`, `/enrich/jobs/<id>`, `/stats`, MOCK mode | 84 OK |
| 5 | `phase-5` | `integrations/custom-m4-enrich.py`, `m4_client.py`, `data/sample_responses.json`, `scripts/e2e_smoke.py`, test plan, Wazuh/M5/M6 docs | **94 OK** |

Details for each phase: `docs/PHASE_<n>_NOTES.md`.

## 3. Scenario → verdict (each row proven by a test)
| Scenario | Verdict | Test |
|---|---|---|
| Not found in any source | `unknown`, score 0, no error | `test_enricher.test_not_found_is_unknown_not_clean` |
| All lookups failed | `unknown` + error, **never clean** | `test_enricher.test_failure_is_never_clean` |
| No API keys | `unknown` + "key not set", no network call | `test_app.test_without_keys_result_is_unknown_with_error_never_clean`, `test_abusech/test_otx.test_missing_key_makes_no_network_call` |
| OTX hit only (even claiming 100) | `suspicious`, ≤ 60, **never malicious** | `test_enricher.test_otx_alone_is_never_malicious` |
| MalwareBazaar hit | `malicious` 95 | `test_abusech.test_malwarebazaar_hit` + `test_enricher.test_abusech_high_score_is_malicious` |
| abuse.ch score 50 / 10 | `suspicious` / `unknown` | `test_enricher.test_medium_score_is_suspicious_low_score_unknown` |
| Hit + other source failed | hit kept, error reported, **not cached** | `test_enricher.test_partial_failure_keeps_hit_and_reports_error`, `test_cache.test_partial_failure_not_cached` |
| One abuse.ch service fails, the other says not found | error (not "not found") | `test_abusech.test_one_service_failing_without_hit_is_error_not_miss` |
| Unexpected API status / shape | error (not "not found") | `test_abusech.test_unexpected_query_status_is_error_not_miss`, `test_otx.test_missing_pulse_info_is_error` |
| Private/loopback/link-local IP | `unknown`, zero provider calls | `test_enricher.test_private_ip_makes_zero_provider_calls` |
| On local allowlist | `clean`, zero provider calls | `test_enricher.test_allowlist_is_clean_without_calls` |
| OTX `validation` (OTX's own whitelist) | miss → `unknown`, not clean | `test_otx.test_validation_is_miss_never_clean` |
| Same indicator again | `cached: true`, zero provider calls, current alert_id | `test_cache.test_second_identical_lookup_makes_zero_provider_calls` |
| M4 down / slow / 500 (Wazuh script, M5 client) | logged / `unknown` + error; never raises | `test_integration.*` |

## 4. Assumptions and UNVERIFIED items
| Item | How you verify it |
|---|---|
| MalwareBazaar: found = `query_status "ok"` + `data` list; not found = `"hash_not_found"`; fields `signature`, `tags`, `file_type`, `first_seen` | `python scripts/try_abusech.py hash <known-bad sha256>` and a random hash |
| ThreatFox: not found = `"no_result"`; fields `malware_printable`, `threat_type`, `tags`; `exact_match` with bare IPs vs `ip:port` IOCs | `try_abusech.py ip <ip from a ThreatFox listing>` |
| URLhaus: `/v1/host/` path, form field `host`, not found = `"no_results"`, `urls[].url_status/threat/tags` | `try_abusech.py domain <host from a URLhaus listing>` |
| abuse.ch status for a bad/missing key | Run once with a wrong key |
| OTX `pulse_info.count` (not used; M4 counts the pulses itself) and `pulses[].tags` | `python scripts/try_otx.py ip 8.8.8.8` |
| Provider rate limits (M4 uses 1 req/s, burst 2) | The providers' terms pages |
| Wazuh `syscheck.sha256_after`; IP field paths; `custom-` naming; install path/permissions | A real FIM and network alert from M1, plus the Wazuh docs for your version |
| M5/M6 consume the contract unchanged; no CORS needed | Ask both teammates |
| Thresholds 80/30 and per-source scores | Design choices: tune with the Week 7 data and agree with your supervisor |

If a real response differs, M4 reports `unknown` + an error naming the
unexpected value. Paste the output (without your key) to Claude Code to fix
the parser.

## 5. Your manual to-do checklist (in order)
1. **Get keys:** abuse.ch Auth-Key (https://auth.abuse.ch) and OTX key (otx.alienvault.com → profile). Put them in `.env` (`cp .env.example .env`). Never commit or share them.
2. **First live test (hashes only, never download samples):**
   ```bash
   set -a; . ./.env; set +a
   scripts/curl_examples.sh <sha256 of a well-known sample from the MalwareBazaar site> 8.8.8.8 example.com
   .venv/bin/python scripts/try_abusech.py hash <same sha256>
   .venv/bin/python scripts/try_abusech.py hash 0000000000000000000000000000000000000000000000000000000000000000
   .venv/bin/python scripts/try_otx.py domain example.com
   ```
3. **Paste the outputs (remove your key)** to Claude Code if anything differs from `docs/api_notes.md`.
4. **Start M4 for real** and check a lookup: `.venv/bin/python -m m4_threat_intel.app`, then `curl -X POST localhost:5004/enrich -H 'Content-Type: application/json' -d '{"alert_id":"T1","type":"hash","value":"<sha256>"}'`
5. **Install the Wazuh integration** on the lab VM: `docs/wazuh_integration.md`. Ask M1 for the Wazuh version and one real FIM alert and one network alert, then fix `FIELD_PATHS`.
6. **Confirm formats with M5/M6:** `docs/m5_m6_integration.md`, `data/sample_responses.json`.
7. **Start the Week 7 labelled hash set** in `data/labelled.csv` (known-bad hashes from public listings, benign hashes from Ubuntu binaries). Agree the pass criteria with your supervisor (`docs/assessment7_test_plan.md`).
8. **Update the Final Doc**: §9 text in `docs/section9_provider_decision.md`; mark §15/§17.7 provider items as resolved.

## 6. Viva prep: likely questions
1. **Why abuse.ch and OTX, not X-Force or MISP?** X-Force has no free API access. MISP is a self-hosted sharing platform, not a feed, so it's future work. abuse.ch is free, open and malware-focused, with one key for three services. OTX adds broad community context (`docs/section9_provider_decision.md`).
2. **Why is "not found" `unknown` and not `clean`?** Absence of evidence isn't evidence of safety. New or lab ransomware is rarely in public feeds. Calling it clean would mislead the analyst. Only our local allowlist can say `clean` (`enricher.verdict_for`, `allowlist.py`).
3. **What happens when a provider is down?** The retry layer tries again with backoff. If it still fails, the provider returns `status="error"`, the verdict is `unknown` with `error` set, and it's not cached, so the next request tries again (`ratelimit.py`, `enricher.py`).
4. **Why not cache errors?** A cached error would turn a 10-second outage into hours of "unknown" for that indicator, and could hide real hits. `cache.set()` refuses errors as a second safety net.
5. **Why can't OTX alone make something malicious?** OTX is community-contributed and noisy. Its score is capped at 60, below the threshold of 80. This is enforced in three places: the provider, `verdict_for`, and a startup assertion.
6. **How does M4 avoid slowing down detection and response?** It's context only, and the alert path uses `/enrich/async`, which replies 202 immediately while a thread pool does the lookup. The Wazuh script exits 0 whatever happens (`jobs.py`, `custom-m4-enrich.py`).
7. **How do you respect rate limits?** A token bucket per provider (1 request/s, burst 2), plus honouring `Retry-After` on 429. The cache also removes repeat lookups (`ratelimit.py`, `/stats` hit rate).
8. **Why never send private IPs out?** It would leak internal network layout to third parties, and the result would be meaningless anyway. `is_non_routable()` checks every non-public category explicitly. A test found that Python's `is_global` alone treats multicast as public.
9. **How do you know the parsers are right?** OTX was checked against the official SDK. For abuse.ch, the parts I could confirm are documented, and the rest is marked UNVERIFIED. The parsers accept only exact known signals, so a wrong guess shows up as an error, not a wrong verdict. The final confirmation is a live run with the provided scripts.
10. **What are M4's limits?** Low coverage of novel and lab ransomware (expected), free-tier limits can change, no API authentication (lab network only), and the Wazuh field names and live API formats are still to be confirmed (section 7).

## 7. Honest limitations
- **Coverage:** public feeds rarely contain brand-new or lab-built ransomware, so most lab results will be `unknown`. That is correct behaviour, not a failure.
- **Unverified live behaviour:** neither provider was called for real. The abuse.ch formats are partly UNVERIFIED.
- **Free tiers** can change their terms or limits at any time.
- **No authentication** on M4's API: keep it on localhost or the isolated lab network.
- **Wazuh:** not installed or run on a real manager; field names partly inferred.
- **Results are not written back into Wazuh**; M5/M6 read them from M4.
- **Thresholds and scores** are design choices until tuned with measured data.
