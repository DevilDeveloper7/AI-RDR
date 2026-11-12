"""HTTP client shared by the providers.

Every failure (timeout, network error, bad status, bad JSON) becomes a
ProviderError with a short, key-free message. Rate limiting and retries are
delegated to ratelimit.request_with_retry().
"""
import time
from typing import Any, Callable, Dict, Iterable, Optional

import requests

from .ratelimit import TokenBucket, request_with_retry
from .schema import ProviderError

__all__ = ["HttpClient", "ProviderError", "json_object"]


class HttpClient:
    def __init__(self, session: Optional[Any] = None, timeout: float = 10.0,
                 bucket: Optional[TokenBucket] = None, max_retries: int = 0,
                 backoff_base: float = 1.0, backoff_max: float = 30.0,
                 retry_after_cap: float = 30.0,
                 sleep: Callable[[float], None] = time.sleep):
        self.session = session if session is not None else requests.Session()
        self.timeout = timeout
        self.bucket = bucket
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.retry_after_cap = retry_after_cap
        self._sleep = sleep

    def request(self, method: str, url: str, accept: Iterable[int] = (200,),
                **kwargs: Any) -> requests.Response:
        return request_with_retry(
            self.session, method, url, timeout=self.timeout, accept=accept,
            bucket=self.bucket, max_retries=self.max_retries,
            backoff_base=self.backoff_base, backoff_max=self.backoff_max,
            retry_after_cap=self.retry_after_cap, sleep=self._sleep, **kwargs)

    def close(self) -> None:
        self.session.close()


def json_object(resp: requests.Response) -> Dict[str, Any]:
    """Parse a JSON object body or raise ProviderError."""
    try:
        body = resp.json()
    except ValueError:
        raise ProviderError("response is not valid JSON") from None
    if not isinstance(body, dict):
        raise ProviderError("response JSON is not an object")
    return body
