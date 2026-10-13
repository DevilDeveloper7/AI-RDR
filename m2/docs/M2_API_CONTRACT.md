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

## Integration ownership

- M1 forms five-second windows from the IRDP-normalized event stream.
- M2 extracts the exact feature schema saved in the model and returns a score
  plus local SHAP evidence.
- M6 displays the response without reinterpreting the threshold.
- M5 may consume the alert, but automatic response remains disabled for this
  path while `response_mode` is `alert_only`.
