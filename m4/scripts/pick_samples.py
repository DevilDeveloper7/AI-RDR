#!/usr/bin/env python3
"""Shortlist 2-3 malware families for the AI-RDR end-to-end test. METADATA ONLY: no sample is downloaded or run.

    set -a; . ./.env; set +a                       # loads ABUSECH_AUTH_KEY
    python3 scripts/pick_samples.py --m4 http://127.0.0.1:5004 --out results/candidates

For the most common ransomware families in MalwareBazaar it lists a few SHA-256 hashes (ELF first, because the lab
target is Linux), looks for C2 IP addresses of the same family in ThreatFox, and (with --m4) asks your running M4
what it says about each hash. Pick the rows where M4 says "malicious" AND the team can actually run the sample.

It also writes one fake Wazuh alert per hash (results/candidates/alerts/*.json). Feed one to the integration script
to test M4 WITHOUT running any malware:
    python3 integrations/custom-m4-enrich.py results/candidates/alerts/<file>.json x http://127.0.0.1:5004
"""
import argparse, collections, csv, json, os, re, ssl, sys, urllib.parse, urllib.request

try:   # python.org Python on macOS ships without CA certificates for urllib; use certifi (comes with requests)
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"


def post(url, key, data, as_json=False):
    body = json.dumps(data).encode() if as_json else urllib.parse.urlencode(data).encode()
    headers = {"Auth-Key": key}
    if as_json:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=40, context=_SSL) as r:
        return json.loads(r.read().decode())


def malwarebazaar(url, key, tags, limit):
    rows, notes = [], []
    for tag in tags:
        try:
            d = post(url, key, {"query": "get_taginfo", "tag": tag, "limit": str(limit)})
        except Exception as exc:
            notes.append(f"MalwareBazaar tag '{tag}' failed: {exc}")
            continue
        if d.get("query_status") == "ok":
            rows += d.get("data") or []
        else:
            notes.append(f"MalwareBazaar tag '{tag}': query_status={d.get('query_status')!r}")
    return rows, notes


def threatfox_ips(url, key, days):
    out = collections.defaultdict(list)          # family (lower) -> [ip, ...]
    try:
        d = post(url, key, {"query": "get_iocs", "days": days}, as_json=True)
    except Exception as exc:
        return out, [f"ThreatFox failed: {exc}"]
    for e in d.get("data") or []:
        if e.get("ioc_type") == "ip:port":
            ip = (e.get("ioc") or "").rsplit(":", 1)[0]
            fam = (e.get("malware_printable") or e.get("malware") or "").lower()
            if ip and fam and ip not in out[fam]:
                out[fam].append(ip)
    return out, []


def families(rows, per_family):
    """family -> up to per_family entries, ELF first; ordered by how many samples the family has."""
    groups, seen = collections.defaultdict(list), set()
    for e in rows:
        h = (e.get("sha256_hash") or "").lower()
        fam = e.get("signature") or ""
        if HEX64.match(h) and fam and h not in seen:
            seen.add(h)
            groups[fam].append(e)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    pick = {}
    for fam, entries in ordered:
        entries.sort(key=lambda e: 0 if (e.get("file_type") or "").lower() == "elf" else 1)
        pick[fam] = (len(entries), entries[:per_family])
    return pick


def m4_verdict(base, sha):
    try:
        req = urllib.request.Request(base.rstrip("/") + "/enrich", method="POST",
                                     data=json.dumps({"alert_id": "pick-samples", "type": "hash", "value": sha}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read().decode())
        return d.get("verdict", "?"), d.get("score", ""), d.get("error") or ""
    except Exception as exc:
        return "m4-unreachable", "", str(exc)[:60]


def fake_alert(sha, family, ip, n):
    alert = {"id": f"replay-{n:03d}", "rule": {"id": "554", "description": f"File added (replay: {family})", "level": 5},
             "agent": {"id": "001", "name": "airdr-target"},
             "syscheck": {"path": f"/tmp/sample_{n:03d}", "event": "added", "sha256_after": sha},
             "data": {}}
    if ip:
        alert["data"]["srcip"] = ip
    return alert


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tags", default="ransomware", help="comma-separated MalwareBazaar tags")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--families", type=int, default=6, help="how many families to show")
    ap.add_argument("--per-family", type=int, default=3)
    ap.add_argument("--days", type=int, default=7, help="ThreatFox look-back (1-7)")
    ap.add_argument("--m4", help="M4 base URL, e.g. http://127.0.0.1:5004 (asks M4 about each hash)")
    ap.add_argument("--out", default="results/candidates")
    ap.add_argument("--mb-url", default=MB_URL)
    ap.add_argument("--tf-url", default=TF_URL)
    a = ap.parse_args()
    key = os.environ.get("ABUSECH_AUTH_KEY", "")
    if not key:
        sys.exit("ERROR: ABUSECH_AUTH_KEY is not set (run: set -a; . ./.env; set +a)")

    rows, notes = malwarebazaar(a.mb_url, key, [t.strip() for t in a.tags.split(",") if t.strip()], a.limit)
    ips, tf_notes = threatfox_ips(a.tf_url, key, a.days)
    for n in notes + tf_notes:
        print("  note:", n)
    fam = families(rows, a.per_family)
    if not fam:
        sys.exit("ERROR: no samples found. Check the key and your internet connection.")

    os.makedirs(os.path.join(a.out, "alerts"), exist_ok=True)
    table, n = [], 0
    for name, (total, entries) in list(fam.items())[:a.families]:
        c2 = (ips.get(name.lower()) or [""])[0]
        for e in entries:
            n += 1
            sha = e["sha256_hash"].lower()
            verdict = m4_verdict(a.m4, sha) if a.m4 else ("-", "", "")
            table.append([name, total, e.get("file_type", ""), e.get("file_size", ""), (e.get("first_seen") or "")[:10],
                          sha, c2, verdict[0], verdict[1], verdict[2]])
            with open(os.path.join(a.out, "alerts", f"{n:03d}_{name}.json".replace(" ", "_").replace("/", "_")), "w") as fh:
                json.dump(fake_alert(sha, name, c2, n), fh, indent=2)

    head = ["family", "samples_seen", "file_type", "size", "first_seen", "sha256", "c2_ip_threatfox", "m4_verdict", "m4_score", "m4_error"]
    with open(os.path.join(a.out, "candidates.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([head] + table)
    print(f"\n{'family':<18} {'type':<5} {'first_seen':<11} {'m4':<10} sha256 (c2 ip)")
    for r in table:
        print(f"{r[0][:17]:<18} {r[2][:4]:<5} {r[4]:<11} {r[7]:<10} {r[5]} {('(' + r[6] + ')') if r[6] else ''}")
    print(f"\nwrote {a.out}/candidates.csv and {len(table)} fake alerts in {a.out}/alerts/")
    print("Pick the families where M4 says 'malicious', then check the team can run them safely.")


if __name__ == "__main__":
    main()
