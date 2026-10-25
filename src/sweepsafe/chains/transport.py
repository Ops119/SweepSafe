"""HTTP transport abstraction. The default implementation uses only the standard library."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

USER_AGENT = "sweepsafe/0.1 (+https://github.com/Ops119/SweepSafe)"
MAX_RESPONSE_BYTES = 25_000_000
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class TransportError(Exception):
    """A network-level failure. ``retriable`` tells callers whether another provider may help."""

    def __init__(self, message: str, *, status: int | None = None, retriable: bool = True) -> None:
        super().__init__(message)
        self.status = status
        self.retriable = retriable


class Transport(Protocol):
    def post_json(self, url: str, payload: Any, *, timeout: float) -> Any: ...

    def get_json(self, url: str, *, timeout: float) -> Any: ...


def check_url(url: str) -> None:
    """Only HTTPS (or plain HTTP to localhost for development) is allowed."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname in _LOCAL_HOSTS:
        return
    raise TransportError(f"refusing non-HTTPS URL: {url!r}", retriable=False)


class UrllibTransport:
    """JSON over HTTPS using ``urllib`` with a response-size cap and a descriptive User-Agent."""

    def __init__(self, user_agent: str = USER_AGENT, max_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self.user_agent = user_agent
        self.max_bytes = max_bytes

    def post_json(self, url: str, payload: Any, *, timeout: float) -> Any:
        body = json.dumps(payload).encode()
        return self._send(url, body, timeout)

    def get_json(self, url: str, *, timeout: float) -> Any:
        return self._send(url, None, timeout)

    def _send(self, url: str, body: bytes | None, timeout: float) -> Any:
        check_url(url)
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                raw = response.read(self.max_bytes + 1)
        except urllib.error.HTTPError as exc:
            retriable = exc.code == 429 or exc.code >= 500
            raise TransportError(
                f"HTTP {exc.code} from {url}", status=exc.code, retriable=retriable
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"network error for {url}: {exc}") from exc
        if len(raw) > self.max_bytes:
            raise TransportError(f"response from {url} exceeded {self.max_bytes} bytes")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise TransportError(f"invalid JSON from {url}") from exc
