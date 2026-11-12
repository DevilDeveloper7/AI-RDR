"""Manual check of the raw OTX API response (needs your real key).

    export OTX_API_KEY=...
    python scripts/try_otx.py ip 8.8.8.8
    python scripts/try_otx.py domain example.com
    python scripts/try_otx.py hash <md5/sha1/sha256>
"""
import ipaddress
import json
import os
import sys

import requests

BASE = "https://otx.alienvault.com/api/v1/indicators"


def slug(ioc_type, value):
    if ioc_type == "hash":
        return "file"
    if ioc_type == "ip":
        return "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
    return "domain"


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("hash", "ip", "domain"):
        sys.exit(__doc__)
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        sys.exit("OTX_API_KEY is not set (export it first; never paste it into files).")
    ioc_type, value = sys.argv[1], sys.argv[2].strip()
    url = f"{BASE}/{slug(ioc_type, value)}/{value}/general"
    try:
        resp = requests.get(url, headers={"X-OTX-API-KEY": key}, timeout=15)
    except requests.RequestException as exc:
        sys.exit(f"SUMMARY: request failed ({type(exc).__name__})")
    print(f"HTTP {resp.status_code}")
    if resp.status_code == 404:
        print("SUMMARY: not found (404)")
        return
    try:
        body = resp.json()
    except ValueError:
        print(resp.text[:1000])
        sys.exit("SUMMARY: response is not JSON")
    print(json.dumps(body, indent=2)[:4000])
    pulses = (body.get("pulse_info") or {}).get("pulses") or [] if isinstance(body, dict) else []
    print(f"SUMMARY: HTTP {resp.status_code}, pulses={len(pulses)}, "
          f"validation={bool(body.get('validation')) if isinstance(body, dict) else None}")


if __name__ == "__main__":
    main()
