#!/usr/bin/env python3
"""Build data/labelled.csv for the M4 evaluation. Hashes only: no sample is ever downloaded.

    export ABUSECH_AUTH_KEY=...        (set -a; . ./.env; set +a)
    python scripts/make_labelled.py --out data/labelled.csv --n-mal 25 --n-ben 25 [--lab lab_hashes.txt]
"""
import argparse, csv, hashlib, json, os, re, sys, urllib.parse, urllib.request

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def mb_query(url, key, fields):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
                                 headers={"Auth-Key": key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def fetch_malicious(url, key, n):
    entries, notes = [], []
    for fields in ({"query": "get_taginfo", "tag": "ransomware", "limit": "200"},
                   {"query": "get_recent", "selector": "100"}):
        try:
            d = mb_query(url, key, fields)
        except Exception as e:
            notes.append("%s failed: %s" % (fields["query"], e)); continue
        if d.get("query_status") == "ok" and d.get("data"):
            entries = d["data"]; notes.append("used %s (%d entries)" % (fields["query"], len(entries))); break
        notes.append("%s returned query_status=%r" % (fields["query"], d.get("query_status")))
    seen, elf, other = set(), [], []
    for e in entries:
        h = (e.get("sha256_hash") or "").lower()
        if not HEX64.match(h) or h in seen:
            continue
        seen.add(h)
        (elf if (e.get("file_type") or "").lower() == "elf" else other).append(h)
    return (elf + other)[:n], notes


def benign_hashes(n):
    out, seen = [], set()
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            try:
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            except Exception:
                continue
            if h not in seen:
                seen.add(h); out.append(h)
            if len(out) >= n:
                return out
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/labelled.csv")
    ap.add_argument("--n-mal", type=int, default=25)
    ap.add_argument("--n-ben", type=int, default=25)
    ap.add_argument("--lab", help="text file with one hash per line (your own samples)")
    ap.add_argument("--mb-url", default="https://mb-api.abuse.ch/api/v1/")
    a = ap.parse_args()
    key = os.environ.get("ABUSECH_AUTH_KEY", "")
    if not key:
        sys.exit("ERROR: ABUSECH_AUTH_KEY is not set (run: set -a; . ./.env; set +a)")
    mal, notes = fetch_malicious(a.mb_url, key, a.n_mal)
    for n in notes:
        print("  malicious:", n)
    if not mal:
        sys.exit("ERROR: no malicious hashes obtained. Check the key / try again later.")
    ben = benign_hashes(a.n_ben)
    lab = []
    if a.lab:
        for line in open(a.lab):
            h = line.strip().split(",")[0].strip().lower()
            if HEX64.match(h):
                lab.append(h)
            elif h:
                print("  skipped invalid lab hash:", h[:20])
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["value", "label", "type"])
        for h in mal: w.writerow([h, "malicious", "hash"])
        for h in ben: w.writerow([h, "benign", "hash"])
        for h in lab: w.writerow([h, "lab", "hash"])
    print("wrote %s: %d malicious, %d benign, %d lab" % (a.out, len(mal), len(ben), len(lab)))


if __name__ == "__main__":
    main()
