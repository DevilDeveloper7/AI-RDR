"""Manual check of the raw abuse.ch API responses (needs your real key).

    export ABUSECH_AUTH_KEY=...
    python scripts/try_abusech.py hash <sha256>
    python scripts/try_abusech.py ip 203.0.113.5
    python scripts/try_abusech.py domain example.com

Prints the raw JSON of each service plus a one-line summary. Only the
indicator is sent: no files are downloaded. Independent of M4's parsers on
purpose, so you see exactly what the API returns.
"""
import json
import os
import sys

import requests

MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/host/"   # UNVERIFIED path


def call(label, url, headers, **kwargs):
    print(f"\n== {label} ==")
    try:
        resp = requests.post(url, headers=headers, timeout=15, **kwargs)
    except requests.RequestException as exc:
        print(f"SUMMARY: {label}: request failed ({type(exc).__name__})")
        return
    print(f"HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        print(resp.text[:1000])
        print(f"SUMMARY: {label}: response is not JSON")
        return
    print(json.dumps(body, indent=2)[:4000])
    status = body.get("query_status") if isinstance(body, dict) else None
    print(f"SUMMARY: {label}: HTTP {resp.status_code}, query_status={status!r}")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("hash", "ip", "domain"):
        sys.exit(__doc__)
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        sys.exit("ABUSECH_AUTH_KEY is not set (export it first; never paste it into files).")
    ioc_type, value = sys.argv[1], sys.argv[2].strip()
    headers = {"Auth-Key": key}
    if ioc_type == "hash":
        call("MalwareBazaar get_info", MB_URL, headers, data={"query": "get_info", "hash": value})
        call("ThreatFox search_hash", TF_URL, headers, json={"query": "search_hash", "hash": value})
    else:
        call("ThreatFox search_ioc", TF_URL, headers,
             json={"query": "search_ioc", "search_term": value, "exact_match": True})
        call("URLhaus host", UH_URL, headers, data={"host": value})


if __name__ == "__main__":
    main()
