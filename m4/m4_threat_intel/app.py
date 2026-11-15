"""Flask API for M4 (binds to localhost:5004).

POST /enrich               synchronous lookup -> contract response (tests/demos)
POST /enrich/m5            same lookup, answered as the M5 `threat_intel` record
                           (200 record | 422 type M5 cannot use: md5/sha1/domain)
POST /enrich/m6            same lookup, answered as the M6 indicator record
GET  /indicators           recent answers as M6 indicator records, newest first
                           (?limit=N, 1..500; empty after a restart)
POST /enrich/async         validate now, 202 {"job_id"}; lookup in background
GET  /enrich/jobs/<id>     {"status": pending|done|failed, "result": ...}; 404 if unknown
GET  /health               liveness + whether keys are set (never the keys)
GET  /stats                cache and job counters
"""
import os
from typing import Optional

from flask import Flask, jsonify, request, url_for

from .allowlist import Allowlist
from .cache import Cache
from .config import Settings
from .enricher import Enricher
from .http import HttpClient
from .jobs import JobManager
from .m5_adapter import to_m5_record
from .m6_adapter import to_m6_indicator
from .providers.abusech import AbuseChProvider
from .providers.mock import load_mock_providers
from .providers.otx import OTXProvider
from .ratelimit import TokenBucket
from .recent import RecentLog
from .schema import InvalidIndicator, parse_request


def _http_client(settings: Settings, rate: float, burst: int) -> HttpClient:
    return HttpClient(
        timeout=settings.http_timeout,
        bucket=TokenBucket(rate, burst, max_wait=settings.rate_max_wait),
        max_retries=settings.max_retries, backoff_base=settings.backoff_base,
        backoff_max=settings.backoff_max, retry_after_cap=settings.retry_after_cap)


def build_enricher(settings: Settings, mock: bool = False) -> Enricher:
    if mock:
        primary, secondary = load_mock_providers()
    else:
        primary = AbuseChProvider(settings.abusech_auth_key,
                                  _http_client(settings, settings.abusech_rate, settings.abusech_burst))
        secondary = OTXProvider(settings.otx_api_key,
                                _http_client(settings, settings.otx_rate, settings.otx_burst))
    return Enricher(primary, secondary,
                    allowlist=Allowlist.from_file(settings.allowlist_path),
                    cache=Cache(settings.cache_path),
                    ttl_hit=settings.ttl_hit, ttl_miss=settings.ttl_miss, recent=RecentLog())


def create_app(settings: Optional[Settings] = None, enricher: Optional[Enricher] = None,
               mock: Optional[bool] = None) -> Flask:
    settings = settings or Settings.from_env()
    if mock is None:
        mock = os.environ.get("M4_MOCK_PROVIDERS") == "1"
    enricher = enricher or build_enricher(settings, mock=mock)
    jobs = JobManager(enricher, workers=settings.workers, max_jobs=settings.max_jobs)

    app = Flask(__name__)
    app.extensions["m4"] = {"enricher": enricher, "jobs": jobs}

    def parse_body():
        return parse_request(request.get_json(silent=True))

    @app.get("/health")
    def health():
        return jsonify(status="ok", mode="MOCK" if mock else "live",
                       abusech_key="set" if settings.abusech_auth_key else "missing",
                       otx_key="set" if settings.otx_api_key else "missing")

    @app.post("/enrich")
    def enrich_sync():
        try:
            alert_id, ioc_type, value = parse_body()
        except InvalidIndicator as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(enricher.enrich(alert_id, ioc_type, value))

    @app.post("/enrich/m5")
    def enrich_m5():
        try:
            alert_id, ioc_type, value = parse_body()
        except InvalidIndicator as exc:
            return jsonify(error=str(exc)), 400
        result = enricher.enrich(alert_id, ioc_type, value)
        record = to_m5_record(result, allow_synthetic=mock)   # mock data only in mock mode
        if record is not None and mock:
            record["synthetic"] = True        # every answer in mock mode is lab data
        if record is None:
            return jsonify(error="M5 only accepts sha256 hashes and IP addresses"), 422
        return jsonify(record)

    @app.post("/enrich/m6")
    def enrich_m6():
        try:
            alert_id, ioc_type, value = parse_body()
        except InvalidIndicator as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(to_m6_indicator(enricher.enrich(alert_id, ioc_type, value)))

    @app.get("/indicators")
    def indicators():
        try:
            limit = int(request.args.get("limit", 100))
        except ValueError:
            return jsonify(error="limit must be an integer"), 400
        if not 1 <= limit <= 500:
            return jsonify(error="limit must be between 1 and 500"), 400
        recent = getattr(enricher, "recent", None)
        items = [to_m6_indicator(r) for r in recent.items(limit)] if recent else []
        return jsonify(items=items, meta={"is_mock": mock, "role": "enrichment only"})

    @app.post("/enrich/async")
    def enrich_async():
        try:
            alert_id, ioc_type, value = parse_body()   # validated before queueing
        except InvalidIndicator as exc:
            return jsonify(error=str(exc)), 400
        job_id = jobs.submit(alert_id, ioc_type, value)
        status_url = url_for("job_status", job_id=job_id)
        return (jsonify(job_id=job_id, alert_id=alert_id, status="pending", status_url=status_url),
                202, {"Location": status_url})

    @app.get("/enrich/jobs/<job_id>")
    def job_status(job_id):
        job = jobs.get(job_id)
        if job is None:
            return jsonify(error="unknown job_id"), 404
        return jsonify(job)

    @app.get("/stats")
    def stats():
        cache = enricher.cache.stats() if enricher.cache else None
        return jsonify(cache=cache, jobs=jobs.stats())

    return app


def shutdown_app(app: Flask) -> None:
    """Stop workers and close the cache and HTTP sessions (used by tests and scripts)."""
    m4 = app.extensions["m4"]
    m4["jobs"].shutdown()
    enricher = m4["enricher"]
    for provider in (enricher.primary, enricher.secondary):
        if provider is not None:
            provider.close()
    if enricher.cache is not None:
        enricher.cache.close()


if __name__ == "__main__":
    # Default: localhost only. M4 has NO authentication, so only bind to
    # another address (M4_HOST) inside the isolated lab network.
    create_app().run(host=os.environ.get("M4_HOST", "127.0.0.1"),
                     port=int(os.environ.get("M4_PORT", "5004")))
