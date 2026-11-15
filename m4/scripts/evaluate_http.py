#!/usr/bin/env python3
"""M4 evaluation over HTTP (works with any running M4 service, no internal imports).

    python scripts/evaluate_http.py --input data/labelled.csv --out results/

Input CSV columns: value,label[,type]   label: malicious | benign | lab
"""
import argparse, csv, json, os, statistics, sys, time, urllib.request, urllib.error

LABELS = ("malicious", "benign", "lab")
FLAGGED = ("malicious", "suspicious")
MISS_TTL_S = 300


def post(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
            status = r.status
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode())
        except Exception:
            data = {}
        status = e.code
        data.setdefault("error", "HTTP %d" % e.code)
    except Exception as e:
        data, status = {"error": "%s: %s" % (type(e).__name__, e)}, 0
    return status, data, (time.perf_counter() - t0) * 1000.0


def read_rows(path):
    rows = []
    with open(path, newline="") as fh:
        rd = csv.DictReader(fh)
        if not rd.fieldnames or "value" not in rd.fieldnames or "label" not in rd.fieldnames:
            sys.exit("ERROR: CSV needs a header with at least: value,label")
        for n, r in enumerate(rd, start=2):
            label = (r.get("label") or "").strip().lower()
            if label not in LABELS:
                sys.exit("ERROR: line %d has invalid label %r (use malicious, benign or lab)" % (n, label))
            rows.append({"value": (r.get("value") or "").strip(), "label": label,
                         "type": (r.get("type") or "hash").strip().lower() or "hash"})
    if not rows:
        sys.exit("ERROR: no rows in %s" % path)
    return rows


def run_pass(base, rows, timeout, name):
    out = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows, 1):
        status, d, ms = post(base.rstrip("/") + "/enrich",
                             {"alert_id": "%s-%d" % (name, i), "type": r["type"], "value": r["value"]}, timeout)
        out.append({"value": r["value"], "type": r["type"], "label": r["label"],
                    "verdict": d.get("verdict", "unknown"), "score": d.get("score"),
                    "sources": ";".join(d.get("sources") or []), "cached": bool(d.get("cached")),
                    "error": d.get("error"), "http": status, "latency_ms": round(ms, 1),
                    "enriched_at": d.get("enriched_at")})
        if i % 10 == 0 or i == len(rows):
            print("  %s pass: %d/%d" % (name, i, len(rows)), flush=True)
    return out, time.perf_counter() - t0


def rate(num, den):
    return None if den == 0 else round(num / den, 4)


def pct(x):
    return "n/a" if x is None else "%.1f%%" % (100 * x)


def percentile(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round(p / 100 * (len(s) - 1)))))
    return round(s[k], 1)


def metrics(cold, warm, cold_s):
    mal = [r for r in cold if r["label"] == "malicious"]
    ben = [r for r in cold if r["label"] == "benign"]
    lab = [r for r in cold if r["label"] == "lab"]
    tp = sum(r["verdict"] in FLAGGED for r in mal)
    fp = sum(r["verdict"] in FLAGGED for r in ben)
    failed = [r for r in cold if r["error"]]
    lat = [r["latency_ms"] for r in cold if not r["cached"] and not r["error"]]
    m = {
        "counts": {"malicious": len(mal), "benign": len(ben), "lab": len(lab), "lookup_failures": len(failed)},
        "detection_rate": rate(tp, len(mal)),
        "false_positive_rate": rate(fp, len(ben)),
        "precision": rate(tp, tp + fp),
        "lab_sample_coverage": rate(sum(r["verdict"] in FLAGGED for r in lab), len(lab)),
        "cold_latency_ms": {"mean": round(statistics.mean(lat), 1) if lat else None,
                            "median": round(statistics.median(lat), 1) if lat else None,
                            "p95": percentile(lat, 95)},
        "cold_pass_seconds": round(cold_s, 1),
    }
    if warm is not None:
        wl = [r["latency_ms"] for r in warm]
        m["warm_cache_hit_rate"] = rate(sum(r["cached"] for r in warm), len(warm))
        m["warm_latency_ms_mean"] = round(statistics.mean(wl), 1) if wl else None
        m["warm_failures"] = sum(1 for r in warm if r["error"])
    return m


def summary_md(m, warnings):
    c = m["counts"]
    L = ["# M4 evaluation summary", "",
         "| Metric | Value |", "|---|---|",
         "| Rows (malicious / benign / lab) | %d / %d / %d |" % (c["malicious"], c["benign"], c["lab"]),
         "| Lookup failures (cold pass) | %d |" % c["lookup_failures"],
         "| Detection rate (known ransomware) | %s |" % pct(m["detection_rate"]),
         "| False-positive rate (benign) | %s |" % pct(m["false_positive_rate"]),
         "| Precision (malicious + benign rows only) | %s |" % pct(m["precision"]),
         "| Lab-sample coverage | %s |" % pct(m["lab_sample_coverage"]),
         "| Cold latency mean / median / p95 (ms) | %s / %s / %s |" % (
             m["cold_latency_ms"]["mean"], m["cold_latency_ms"]["median"], m["cold_latency_ms"]["p95"])]
    if "warm_cache_hit_rate" in m:
        L += ["| Warm-pass cache hit rate | %s |" % pct(m["warm_cache_hit_rate"]),
              "| Warm-pass mean latency (ms) | %s |" % m["warm_latency_ms_mean"]]
    if warnings:
        L += ["", "## Warnings"] + ["- " + w for w in warnings]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="results")
    ap.add_argument("--url", default="http://127.0.0.1:5004")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--no-warm", action="store_true")
    a = ap.parse_args()

    rows = read_rows(a.input)
    st, d, _ = post(a.url.rstrip("/") + "/enrich", {"alert_id": "probe", "type": "ip", "value": "10.0.0.1"}, a.timeout)
    if st != 200:
        sys.exit("ERROR: M4 service not reachable at %s (%s). Start it first." % (a.url, d.get("error")))

    print("Pass 1 (cold): %d lookups" % len(rows))
    cold, cold_s = run_pass(a.url, rows, a.timeout, "cold")
    warm = None
    if not a.no_warm:
        print("Pass 2 (warm)")
        warm, _ = run_pass(a.url, rows, a.timeout, "warm")

    m = metrics(cold, warm, cold_s)
    warnings = []
    if m["counts"]["lookup_failures"]:
        warnings.append("%d lookups failed in the cold pass: the rates above include failed lookups. "
                        "Fix the cause (keys, network, rate limit) and re-run before quoting them." %
                        m["counts"]["lookup_failures"])
    if any(r["cached"] for r in cold):
        warnings.append("Some cold-pass results were already cached: restart the service with an empty cache "
                        "(delete m4_cache.sqlite3) for a true cold pass.")
    if warm is not None and cold_s > MISS_TTL_S - 30:
        warnings.append("The cold pass took %.0f s; not-found results are cached for only %d s, so the warm-pass "
                        "hit rate may be understated. Use a smaller set or run the passes faster." % (cold_s, MISS_TTL_S))
    if m["counts"]["malicious"] and m["counts"]["lab"] == 0:
        warnings.append("No 'lab' rows: lab-sample coverage is n/a.")
    warnings.append("Malicious rows taken from MalwareBazaar itself are found by construction: the detection rate "
                    "then checks the pipeline (parser and verdict rules), not real-world coverage. Lab-sample "
                    "coverage is the realistic number.")

    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "results.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(cold[0].keys()))
        w.writeheader(); w.writerows(cold)
    with open(os.path.join(a.out, "metrics.json"), "w") as fh:
        json.dump(m, fh, indent=2)
    md = summary_md(m, warnings)
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(md)
    print("\n" + md)


if __name__ == "__main__":
    main()
