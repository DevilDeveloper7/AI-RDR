# M4 evaluation summary

| Metric | Value |
|---|---|
| Rows (malicious / benign / lab) | 25 / 25 / 0 |
| Lookup failures (cold pass) | 0 |
| Detection rate (known ransomware) | 100.0% |
| False-positive rate (benign) | 0.0% |
| Precision (malicious + benign rows only) | 100.0% |
| Lab-sample coverage | n/a |
| Cold latency mean / median / p95 (ms) | 2069.7 / 1951.7 / 3076.4 |
| Warm-pass cache hit rate | 100.0% |
| Warm-pass mean latency (ms) | 1.9 |

## Warnings
- No 'lab' rows: lab-sample coverage is n/a.
- Malicious rows taken from MalwareBazaar itself are found by construction: the detection rate then checks the pipeline (parser and verdict rules), not real-world coverage. Lab-sample coverage is the realistic number.
