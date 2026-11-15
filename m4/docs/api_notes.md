# API notes: what M4 relies on, and how sure we are

**How these were checked (18 Oct 2026).** The build environment's network
policy blocked `bazaar.abuse.ch`, `threatfox.abuse.ch`, `urlhaus.abuse.ch`,
`mb-api.abuse.ch` and `otx.alienvault.com`, so the official pages could not be
opened directly.
- **OTX** was verified against AlienVault's **official Python SDK source**
  (`github.com/AlienVault-OTX/OTX-Python-SDK`, files `OTXv2.py`,
  `IndicatorTypes.py` and `examples/is_malicious/get_malicious.py`).
- **abuse.ch** was checked only through search-engine extracts of the official
  API pages plus third-party integration docs. Everything not confirmed that way
  is marked **UNVERIFIED**.

**Run `scripts/curl_examples.sh` with your own key to confirm every UNVERIFIED
line.** Paste the output (without your key) back to Claude Code if anything differs.

## Live confirmation, 18 Oct 2026 (Kiana's real run, recorded in `tests/fixtures/abusech_live_2026-10-18.json`)
| Item | Result |
|---|---|
| Auth-Key header accepted; HTTP 200 for all calls | ✅ confirmed live |
| MalwareBazaar found = `query_status "ok"` + `data` list; fields `sha256_hash`, `first_seen`, `file_type`, `signature` (**can be null**), `tags` (list) | ✅ confirmed live |
| MalwareBazaar not found = `"hash_not_found"` (no `data` key) | ✅ confirmed live |
| ThreatFox not found = `"no_result"` with `data` = a **text string**, not a list (the parser checks the status before reading `data`) | ✅ confirmed live (`search_hash` and `search_ioc`) |
| URLhaus `POST /v1/host/` with form field `host` works; found = `"ok"` + `urls` list with `url_status`, `threat`, `tags` | ✅ confirmed live |
| URLhaus `url_count` is a **string** (`"4"`) and was larger than the number of entries in `urls` (1) | ✅ observed. M4 uses `len(urls)`. |
| Still unconfirmed: a ThreatFox **hit** (`confidence_level` etc.), URLhaus not found (`"no_results"`), the response to a bad key | ❌ |

Legend: ✅ confirmed from an official source · ⚠️ seen in official-page extracts or
third-party docs only · ❌ UNVERIFIED (our assumption)

---

## abuse.ch: shared
| Item | Value | Status |
|---|---|---|
| Auth | HTTP header `Auth-Key: <key>`. One free key from auth.abuse.ch covers MalwareBazaar, ThreatFox and URLhaus. | ⚠️ (official-page extract) |
| Missing or invalid key | Exact HTTP status/body | ❌ UNVERIFIED. M4 treats 401/403 as "authentication failed" and any other non-200 as an error. |
| Rate limits | "Fair use"; no number found | ❌ UNVERIFIED. M4 limits itself to 1 request/s with a burst of 2 (configurable). |

## MalwareBazaar: hash lookup
| Item | Value | Status |
|---|---|---|
| URL / method | `POST https://mb-api.abuse.ch/api/v1/` | ⚠️ (official-page extract shows the wget example) |
| Body | form-encoded `query=get_info&hash=<md5/sha1/sha256>` | ⚠️ |
| Found | `query_status == "ok"` and `data` is a list of samples | ❌ UNVERIFIED (inferred from the ThreatFox/URLhaus pattern) |
| Not found | `query_status == "hash_not_found"` | ❌ UNVERIFIED |
| Fields used | `data[0].signature` (malware family), `data[0].tags` (list), `data[0].file_type`, `data[0].first_seen`, `data[0].sha256_hash` | ❌ UNVERIFIED. All optional: a missing field is skipped, never invented. |

## ThreatFox: IOC search
| Item | Value | Status |
|---|---|---|
| URL / method | `POST https://threatfox-api.abuse.ch/api/v1/` | ⚠️ |
| Body | JSON. Hash: `{"query": "search_hash", "hash": "<md5/sha256>"}`. IP/domain: `{"query": "search_ioc", "search_term": "<value>", "exact_match": true}` | ⚠️ (`search_hash`+`hash` from a Velociraptor artifact; `exact_match` option from Tracecat docs, wildcard by default) |
| Found | `query_status == "ok"`, `data` is a list of IOC records | ⚠️ (PyPI client example) |
| Not found | `query_status == "no_result"` | ❌ UNVERIFIED |
| Fields used | `confidence_level` (0–100), `malware_printable`, `threat_type`, `tags` (list or null), `ioc` | ⚠️ `confidence_level` seen in an example (value 90). The others are ❌ UNVERIFIED and optional. |
| SHA-1 | not supported by `search_hash` (MD5/SHA-256 only) | ⚠️. M4 skips ThreatFox for SHA-1. |
| IP IOCs stored as `ip:port` | With `exact_match: true` a bare IP may not match an `ip:port` IOC | ❌ UNVERIFIED. **Check with a real run.** If needed, switch to wildcard search and filter on the IP prefix. |

## URLhaus: host lookup (IP or domain)
| Item | Value | Status |
|---|---|---|
| URL / method | `POST https://urlhaus-api.abuse.ch/v1/host/` | ⚠️ (base URL `urlhaus-api.abuse.ch/v1/` from third-party docs; the `/host/` path is UNVERIFIED) |
| Body | form-encoded `host=<ip or domain>` | ❌ UNVERIFIED |
| Found | `query_status == "ok"`, `urls` is a list | ⚠️ (`query_status: ok` seen in PSURLhaus output) |
| Not found | `query_status == "no_results"` | ❌ UNVERIFIED |
| Fields used | `urls[].url_status` (`"online"` / `"offline"`), `urls[].threat`, `urls[].tags`, `url_count` | ⚠️ `url_status: offline` seen in examples. Other fields ❌ UNVERIFIED and optional. |

## OTX (AlienVault / LevelBlue): indicator general section
| Item | Value | Status |
|---|---|---|
| Auth | header `X-OTX-API-KEY: <key>` | ✅ `OTXv2.py` |
| URL / method | `GET https://otx.alienvault.com/api/v1/indicators/<slug>/<value>/general` | ✅ `create_indicator_detail_url` |
| Slugs | IPv4 → `IPv4`, IPv6 → `IPv6`, domain → `domain`, MD5/SHA-1/SHA-256 → `file` | ✅ `IndicatorTypes.py` |
| Invalid key | HTTP **403** (the SDK raises `InvalidAPIKey`) | ✅ `handle_response_errors` |
| Not found | HTTP **404** (the SDK raises `NotFound`) | ✅. M4 treats 404 as a miss. |
| Other errors | 400 bad request; any non-2xx is an error. The SDK retries 429/500/502/503/504. | ✅ |
| Pulses | `pulse_info.pulses` (list); each pulse has `name` | ✅ `get_malicious.py` |
| Pulse tags | `pulses[].tags` | ⚠️ (tags are a pulse attribute in the SDK's create-pulse code; not shown in a read example) |
| Pulse count | `pulse_info.count` | ⚠️ third-party docs only. **M4 uses `len(pulses)`**, so it doesn't depend on this. |
| Whitelisted indicator | non-empty `validation` field. The official example ignores pulses when it is set. | ✅ `get_malicious.py`. M4 treats it as a **miss**, never "clean" (only our allowlist gives clean). |
| Rate limit | not found | ❌ UNVERIFIED. M4 limits itself to 1 request/s with a burst of 2. |

## Design rule that makes the unverified parts safe
Every parser accepts only the **exact** "found" and "not found" signals listed
above. Anything else (an unexpected `query_status`, missing `data`, non-JSON,
JSON that isn't an object, an unexpected HTTP status) becomes
`status="error"` with the raw status in the message. An error gives verdict
`unknown` and is **never cached**. So if one of our guesses is wrong, M4
reports "unknown + error" and you notice. It never reports a wrong "not
found" or a wrong verdict.

## Scoring change after the live run (18 Oct 2026)
The real run showed that the benign, reserved domain `example.com` is in
URLhaus with one **offline** URL, reported automatically from a honeypot.
With the original rule (offline-only → 70 → "suspicious") that was a false
alarm. Decision (Kiana): offline-only URLhaus history is now **context only**
(score 25, below the suspicious threshold of 30). The verdict stays `unknown`,
while `sources`, `tags` and `details` still show the URLhaus record. A host with
any **online** URL still scores 85 → `malicious`.
