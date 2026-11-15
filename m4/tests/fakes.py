"""Test doubles: a fake requests.Session and fake providers. No network."""
import json

import requests

from m4_threat_intel.http import HttpClient
from m4_threat_intel.providers.base import Provider
from m4_threat_intel.schema import ProviderResult


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=None, headers=None):
        self.status_code = status_code
        self._body = body
        self.text = text if text is not None else json.dumps(body)
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            return json.loads(self.text)   # raises ValueError for non-JSON
        return self._body


class FakeSession:
    """Answers each request from a per-URL queue of responses or exceptions.

    routes = {url_substring: [FakeResponse | Exception, ...]}. The last item
    is repeated when the queue runs out.
    """

    def __init__(self, routes=None):
        self.routes = {k: list(v) for k, v in (routes or {}).items()}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        for key, queue in self.routes.items():
            if key in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(item, Exception):
                    raise item
                return item
        raise requests.ConnectionError(f"no fake route for {url}")

    def close(self):
        pass


def fake_http(routes=None):
    session = FakeSession(routes)
    return HttpClient(session=session, timeout=1), session


class StaticProvider(Provider):
    """Returns a fixed ProviderResult and counts calls."""

    def __init__(self, name="static", status="miss", score=0, tags=None, error=None,
                 context_only=False, types=("hash", "ip", "domain")):
        self.name = name
        self.supported_types = frozenset(types)
        self.context_only = context_only
        self._kw = dict(status=status, score=score, tags=tags or [], error=error)
        self.calls = []

    def _lookup(self, ioc_type, value):
        self.calls.append((ioc_type, value))
        return ProviderResult(provider=self.name, **self._kw)
