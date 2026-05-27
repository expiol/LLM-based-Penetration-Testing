"""Minimal HTTP wrapper for cybersecurity sources.

Uses the standard library so we don't introduce a new runtime dependency.
Body length is hard-capped to keep responses bounded.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from killchain_docker.intelligence.web.policy import (
    HTTP_TIMEOUT_S,
    MAX_BODY_BYTES,
    host_allowed,
)
from killchain_docker.logging_utils import get_logger


LOGGER = get_logger(__name__)


class WebFetchError(RuntimeError):
    """Raised when an outbound request cannot be executed safely."""


@dataclass(frozen=True)
class WebResponse:
    """Bounded view of a successful HTTP response."""

    url: str
    status: int
    body: bytes


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_s: float = HTTP_TIMEOUT_S,
    max_bytes: int = MAX_BODY_BYTES,
) -> dict[str, Any]:
    """Issue a GET request, enforcing host allowlist and body cap.

    Returns the parsed JSON body. Raises ``WebFetchError`` for any failure
    (host rejection, network error, bad status, oversized body, decode error).
    """

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebFetchError(f"unsupported scheme {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host_allowed(host):
        raise WebFetchError(f"host {host!r} is not on the cybersecurity allowlist")

    request_headers = {
        "Accept": "application/json",
        "User-Agent": "killchain-intelligence/1.0",
    }
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(url, headers=request_headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            status = int(getattr(response, "status", 0))
            body = response.read(max_bytes + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WebFetchError(f"request failed: {type(exc).__name__}: {exc}") from exc

    if len(body) > max_bytes:
        raise WebFetchError(
            f"response body exceeded {max_bytes} bytes; refusing to parse"
        )
    if status < 200 or status >= 300:
        raise WebFetchError(f"unexpected HTTP status {status}")
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebFetchError(f"non-utf8 response body: {exc}") from exc
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise WebFetchError(f"invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise WebFetchError("expected JSON object body")
    return payload
