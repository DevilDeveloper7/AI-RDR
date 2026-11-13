"""REAL M2 adapter: reads M2 results from OpenSearch detection documents (nested `m2` field).

M2 stays alert_only. This adapter never assigns severity, never reinterprets the prediction,
probability, threshold, alert flag or SHAP values, and never triggers or authorises containment.
Severity and response decisions belong to M5 Risk Fusion.

Configuration (all optional except M2_BASE_URL; read from the environment):
  M2_BASE_URL            OpenSearch URL, e.g. https://localhost:9200
  M2_OS_INDEX            index pattern            (default ai-rdr-ml-detections-*)
  M2_OS_USERNAME / M2_OS_PASSWORD   basic auth (optional)
  M2_OS_VERIFY_TLS      true|false                (default true)
  M2_OS_TIMEOUT         seconds                   (default 5)
  M2_OS_SIZE            max documents per query   (default 100)
  M2_OS_ONLY_ALERTS     only m2.alert == true     (default true)
  Top-level document fields (comma-separated = ordered fallbacks; defaults match the M2 detection documents):
  M2_OS_TIMESTAMP_FIELD (@timestamp)   M2_OS_ID_FIELD (detection_id)
  M2_OS_HOST_FIELD (host_id,agent_id)  M2_OS_PROCESS_FIELD (process_name,process_id)
"""
import base64
import json
import math
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib import error, request
from urllib.parse import quote

from ..base import IntegrationUnavailable, IntegrationTimeout, MalformedResponse
from . import M2Adapter

SOURCE = "m2-opensearch"
DEFAULT_INDEX = "ai-rdr-ml-detections-*"
_ENV_DEFAULTS = {"index": DEFAULT_INDEX, "username": "", "password": "", "verify_tls": "true", "timeout": "5", "size": "100",
                 "only_alerts": "true", "timestamp_field": "@timestamp", "id_field": "detection_id",
                 "host_field": "host_id,agent_id", "process_field": "process_name,process_id"}


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _dig(doc, path):
    """Value at a dotted path. A literal dotted key is tried first, then nested objects."""
    if path in doc:
        return doc[path]
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(doc, fields):
    for f in fields:
        v = _dig(doc, f)
        if v not in (None, ""):
            return v
    return None


def _iso(value):
    """Normalise an OpenSearch timestamp (ISO string or epoch s/ms) to M6's UTC form, or None."""
    try:
        if _num(value):
            dt = datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
        elif isinstance(value, str) and value.strip():
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class RealM2(M2Adapter):
    kind = "real"

    def __init__(self, base_url, settings=None):
        if not (base_url or "").strip():
            raise ValueError("M2_MODE=real requires M2_BASE_URL (the OpenSearch URL holding the M2 detection documents).")
        cfg = {k: os.environ.get(f"M2_OS_{k.upper()}", d) for k, d in _ENV_DEFAULTS.items()}
        cfg.update(settings or {})
        self._base = base_url.strip().rstrip("/")
        self._index = cfg["index"].strip() or DEFAULT_INDEX
        try:
            self._timeout, self._size = float(cfg["timeout"]), int(cfg["size"])
        except (TypeError, ValueError):
            raise ValueError("M2_OS_TIMEOUT must be a number and M2_OS_SIZE an integer.")
        self._only_alerts = str(cfg["only_alerts"]).strip().lower() != "false"
        self._ctx = None
        if self._base.startswith("https") and str(cfg["verify_tls"]).strip().lower() == "false":
            self._ctx = ssl._create_unverified_context()
        self._auth = None
        if cfg["username"]:
            self._auth = "Basic " + base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode()).decode()
        split = lambda s: [x.strip() for x in str(s).split(",") if x.strip()]
        self._ts, self._id, self._host = split(cfg["timestamp_field"]), split(cfg["id_field"]), split(cfg["host_field"])
        self._proc = split(cfg["process_field"])
        self.skipped = 0  # documents ignored in the last query because they were malformed

    # ------------------------------------------------------------------ transport
    def _post(self, path, body):
        url = f"{self._base}/{quote(self._index, safe='*,-_.')}/{path}"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        req = request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=self._timeout, context=self._ctx) as res:
                raw = res.read()
        except error.HTTPError as exc:
            if exc.code in (401, 403):
                raise IntegrationUnavailable("M2 OpenSearch rejected the credentials.")
            if exc.code == 404:
                raise IntegrationUnavailable(f"M2 OpenSearch has no index matching '{self._index}'.")
            raise IntegrationUnavailable(f"M2 OpenSearch returned HTTP {exc.code}.")
        except (socket.timeout, TimeoutError):
            raise IntegrationTimeout("M2 OpenSearch did not answer in time.")
        except error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise IntegrationTimeout("M2 OpenSearch did not answer in time.")
            raise IntegrationUnavailable("M2 OpenSearch is not reachable.")
        except (OSError, ValueError):
            raise IntegrationUnavailable("M2 OpenSearch is not reachable.")
        try:
            data = json.loads(raw)
        except ValueError:
            raise MalformedResponse("M2 OpenSearch returned a response that is not JSON.")
        if not isinstance(data, dict):
            raise MalformedResponse("M2 OpenSearch returned something that is not an object.")
        return data

    def _filters(self):
        f = [{"exists": {"field": "m2"}}]
        if self._only_alerts:
            f.append({"term": {"m2.alert": True}})
        return {"bool": {"filter": f}}

    def health(self):
        n = self._post("_count", {"query": self._filters()}).get("count")
        if not isinstance(n, int):
            raise MalformedResponse("M2 OpenSearch returned a malformed count response.")
        if n == 0:
            return {"status": "Warning", "detail": f"OpenSearch reachable, but '{self._index}' has no documents with M2 results yet."}
        return {"status": "Connected", "detail": f"Real M2 results from OpenSearch '{self._index}' ({n} documents). M2 is alert_only."}

    # ------------------------------------------------------------------ mapping
    def _fetch(self):
        body = {"size": self._size, "query": self._filters(),
                "sort": [{self._ts[0]: {"order": "desc", "unmapped_type": "date"}}]}
        outer = self._post("_search", body).get("hits")
        hits = outer.get("hits") if isinstance(outer, dict) else None
        if not isinstance(hits, list):
            raise MalformedResponse("M2 OpenSearch returned a malformed search response (no hits list).")
        out, self.skipped = [], 0
        for hit in hits:
            mapped = self._map(hit)
            if mapped is None:
                self.skipped += 1
            else:
                out.append(mapped)
        if hits and not out:
            raise MalformedResponse("M2 OpenSearch documents were found, but none had a valid 'm2' result.")
        return out

    def _map(self, hit):
        """One OpenSearch hit -> (detection, shap-or-None), or None when the document is unusable."""
        src = hit.get("_source") if isinstance(hit, dict) else None
        m2 = src.get("m2") if isinstance(src, dict) else None
        if not isinstance(m2, dict):
            return None
        pred, prob, thr, alert = m2.get("prediction"), m2.get("ransomware_probability"), m2.get("threshold"), m2.get("alert")
        model, ver = m2.get("model_name"), m2.get("feature_version")
        if not (isinstance(pred, str) and pred and _num(prob) and _num(thr) and isinstance(alert, bool)
                and isinstance(model, str) and model and isinstance(ver, str) and ver):
            return None
        ident = lambda v: str(v) if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) else None
        raw_id, host, proc = ident(_first(src, self._id)), ident(_first(src, self._host)), ident(_first(src, self._proc))
        ts = _iso(_first(src, self._ts))
        if not (raw_id and host and proc and ts):
            return None  # detection_id, host, process or @timestamp missing: not shown, never guessed
        alert_id = raw_id if raw_id.startswith("A-") else f"A-{raw_id}"  # M6 alert IDs must start with "A-"; detection_id is kept in m2.detection_id
        meta = {"probability": prob, "threshold": thr, "alert": alert, "prediction": pred, "model_name": model,
                "feature_version": ver, "response_mode": m2.get("response_mode"), "inference_ms": m2.get("inference_ms"),
                "detection_id": raw_id, "document_id": hit.get("_id"), "index": hit.get("_index")}
        detection = {"alert_id": alert_id, "severity": None,  # M2 never assigns severity (M5 Risk Fusion owns it)
                     "host": host, "process": proc,
                     "activity": f"M2 behavioural verdict: {pred} (probability {prob:g}, threshold {thr:g})",
                     "timestamp": ts, "threshold_exceeded_at": ts,  # M2 returns no separate time; the document time is used
                     "prediction": pred, "confidence": prob, "source": SOURCE, "m2": meta}
        return detection, self._shap(m2, meta, ts)

    @staticmethod
    def _shap(m2, meta, ts):
        expl = m2.get("explanation")
        if not isinstance(expl, list):
            return None
        feats = []
        for e in expl:
            if not (isinstance(e, dict) and isinstance(e.get("feature"), str) and _num(e.get("shap_value"))):
                return None  # a half-valid SHAP list is not shown
            feats.append({"feature": e["feature"], "value": e["shap_value"],
                          "feature_value": e.get("value") if _num(e.get("value")) else None, "direction": e.get("direction")})
        return {"model": meta["model_name"], "ransomware_likelihood": meta["probability"], "explained_at": ts,
                "summary": (f"M2 {meta['model_name']} scored {meta['probability']:g} against threshold {meta['threshold']:g} "
                            f"(verdict: {meta['prediction']}, alert: {str(meta['alert']).lower()}). SHAP values are shown as received; "
                            "direction is supporting evidence, not a causal statement."),
                "features": feats, "threshold": meta["threshold"], "alert": meta["alert"], "feature_version": meta["feature_version"],
                "response_mode": meta["response_mode"], "source": SOURCE}

    # ------------------------------------------------------------------ M2Adapter
    def list_detections(self):
        return [d for d, _ in self._fetch()]  # already newest first (sorted by the timestamp field)

    def get_shap(self, alert_id):
        for d, shap in self._fetch():
            if d["alert_id"] == alert_id:
                return shap
        return None