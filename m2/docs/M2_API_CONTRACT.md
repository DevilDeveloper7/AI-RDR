# M2 inference API contract

## Runtime

```bash
AI_RDR_MODEL_PATH=artifacts/models/random_forest.joblib \
  ai-rdr-m2-api
```

The service listens on `127.0.0.1:8000`. OpenAPI is available at `/docs`.
The current model always returns `response_mode: alert_only`; M5 must not treat
an M2 alert as authorization for automatic containment until external
hard-benign validation is complete.

## Endpoints

- `GET /health` — process health.
- `GET /v1/model` — model name, threshold, feature version and ordered feature
  contract.
- `POST /v1/predict` — score one already-formed telemetry window.
- `POST /v1/predict/window` — score one host-wide feature row produced by the
  streaming aggregator.

## Prediction request

```json
{
  "run_id": "host-01:pid-4126:window-173",
  "start": 1760274000.0,
  "end": 1760274005.0,
  "top_k": 8,
  "events": [
    {
      "timestamp": 1760274000.1,
      "event_type": "openat",
      "pid": 4126,
      "ppid": 3900,
      "process_name": "worker",
      "path": "/srv/data/report.docx"
    },
    {
      "timestamp": 1760274000.2,
      "event_type": "write",
      "pid": 4126,
      "process_name": "worker",
      "bytes": 4096
    }
  ]
}
```

`run_id`, at least one event, timestamp and event type are required. Optional
fields are operation, PID, parent PID, process name, path and byte count.
Unknown fields are rejected to surface M1/M2 schema drift.

## Prediction response

```json
{
  "prediction": "ransomware",
  "ransomware_probability": 0.73,
  "threshold": 0.13,
  "alert": true,
  "response_mode": "alert_only",
  "model_name": "random_forest",
  "feature_version": "1.0",
  "inference_ms": 34.1,
  "explanation": [
    {
      "feature": "write_ratio",
      "value": 0.41,
      "shap_value": 0.08,
      "direction": "toward_ransomware"
    }
  ]
}
```

M6 should display probability, threshold, verdict, response mode and the
ordered explanation entries. SHAP direction is supporting evidence, not a
causal statement.

## Window feature request

High-volume sources should not send raw events. `m2_pipeline.streaming`
folds each event into counters and emits one row per host per five-second
window, which can be posted unchanged:

```json
{
  "window_id": "4f0c2a9e7b1d3c5a6e80",
  "host": "airdr-target-01",
  "start": 1763460000.0,
  "end": 1763460005.0,
  "feature_version": "1.0",
  "top_k": 8,
  "features": {
    "event_count": 18234,
    "event_rate": 3646.8,
    "write_ratio": 0.41
  }
}
```

The example is shortened: every feature listed by `GET /v1/model` is required
and must be a finite number, and `feature_version` must equal the model's.
Otherwise the request is rejected with 422. `window_id` is optional and is
derived from host and window bounds when omitted. The response is the
prediction response above plus `window_id`, `host`, `start` and `end`.

## Streaming from Falco

```bash
falco -o json_output=true | ai-rdr-m2 stream --model artifacts/models/random_forest.joblib
```

The command reads Falco JSON Lines from stdin (or a file argument), scores
each closed window in-process and prints one JSON line per window:
`window_id`, `host`, `start`, `end`, the prediction response fields and the
31 `features`. A summary is written to stderr. A window closes when the host's
next event falls after its end, when other hosts' events are `--lateness`
seconds (default 5) past its end, or at the end of the input.

On 71 Lifecycle runs (3.0 million events, 168 windows) the rows were exactly
equal to the batch features, both through the Python API and through
Falco-formatted JSON. On one core, aggregation takes about 0.5 µs per event;
parsing 436-byte Falco lines plus aggregation runs at about 210,000 events/s.
The model and SHAP run once per window, about 30 ms.

Falco must give the same view of the host as the training traces:

- Every syscall, not only file I/O, because ratios divide by the window's
  total event count. Falco ignores the read/write family by default; enable
  all events (`-A`, or the equivalent `base_syscalls` setting of the deployed
  version).
- One event per syscall. The parser drops enter events (`evt.dir` is `>`).
- Output fields `evt.type`, `evt.rawtime`, `thread.tid`, `proc.name` and
  `evt.rawarg.size`; without `evt.rawtime` the alert's ISO `time` is used.
  Training PIDs are ftrace thread IDs, so `thread.tid` is preferred over
  `proc.pid`. Requested byte counts come from the `size` argument, which
  Falco reports on exit events from version 0.42; with older versions the two
  byte features read 0.
- The `hostname` field, or `--host` when it is absent. Windows contain all
  processes of a host: per-process windows force `max_pid_share` to 1, which
  raised alerts on 49% of benign windows.

## Integration ownership

- M1 forms five-second windows from the IRDP-normalized event stream, or pipes
  Falco output through `ai-rdr-m2 stream` on the monitored host (or posts its
  rows to `/v1/predict/window`), so only one row per host per window crosses
  the network.
- M2 extracts the exact feature schema saved in the model and returns a score
  plus local SHAP evidence.
- M6 displays the response without reinterpreting the threshold.
- M5 may consume the alert, but automatic response remains disabled for this
  path while `response_mode` is `alert_only`.
