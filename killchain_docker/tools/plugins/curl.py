"""curl — HTTP requests with cookie jar session persistence.

Supports:
  - Stateless single requests
  - Persistent sessions via session_id → shared cookie jar file
  - Redirect following (-L)
  - HTTP basic auth (-u)
  - One-shot cookies (-b "k=v")
  - Rich output parsing: Set-Cookie, redirect chains, Endpoint/Route/Session emission
"""

from __future__ import annotations
import os
import re
from typing import Any
from urllib.parse import urlparse
from killchain_docker.state.domain import Credential, Endpoint, Route, Session
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)

_JAR_DIR = "/tmp/_curl_sessions"
_SESSION_ID_RE = re.compile("[^a-zA-Z0-9_-]")
_MAX_SESSION_ID_LEN = 64
_HTTP_STATUS_RE = re.compile("HTTP/[\\d.]+ (\\d+)")
_SET_COOKIE_RE = re.compile("^set-cookie:\\s*(.+)", re.IGNORECASE)
_HEADER_KV_RE = re.compile("^([\\w-]+):\\s*(.+)")
_HTTP_SCHEMES = {"http", "https"}


def _sanitize_session_id(raw: str) -> str:
    """Strip unsafe characters and clamp length for filesystem safety."""
    cleaned = _SESSION_ID_RE.sub("", raw.strip())
    return cleaned[:_MAX_SESSION_ID_LEN]


def _parse_headers_block(headers_text: str) -> dict[str, str]:
    """Parse raw HTTP headers into a lowercase-key dict (last value wins)."""
    result: dict[str, str] = {}
    for line in headers_text.splitlines():
        m = _HEADER_KV_RE.match(line)
        if m:
            result[m.group(1).lower()] = m.group(2).strip()
    return result


def _parse_set_cookies(headers_text: str) -> list[str]:
    """Extract all Set-Cookie header values from raw headers."""
    cookies: list[str] = []
    for line in headers_text.splitlines():
        m = _SET_COOKIE_RE.match(line)
        if m:
            cookies.append(m.group(1).strip())
    return cookies


def _parse_redirect_chain(stdout: str) -> list[dict[str, Any]]:
    """Extract redirect chain from multi-response curl -i output."""
    chain: list[dict[str, Any]] = []
    for m in _HTTP_STATUS_RE.finditer(stdout):
        chain.append({"status": int(m.group(1)), "offset": m.start()})
    return chain


def _extract_base_url(url: str) -> str:
    """Extract scheme + netloc from a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else url


def unsupported_url_scheme_reason(url: str) -> str | None:
    """Return a block reason when an explicit URL scheme is not HTTP(S)."""
    parsed = urlparse(str(url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme and scheme not in _HTTP_SCHEMES:
        return f"curl supports only HTTP/HTTPS URLs, not {scheme}://; use script.exec with a bounded socket harness for raw TCP services"
    return None


class CurlPlugin:
    """HTTP client plugin with optional cookie jar session persistence.

    When metadata includes ``session_id``, the plugin maps it to a cookie
    jar file at ``/tmp/_curl_sessions/{id}.cookies``. All requests sharing
    the same session_id share the same cookie jar, enabling multi-step
    authenticated workflows (login → access protected resource → submit).
    """

    name = "curl"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])
        self._sessions: dict[str, str] = {}

    def _resolve_jar(self, session_id: str) -> str:
        """Return the cookie jar path for a session, creating dir if needed."""
        safe_id = _sanitize_session_id(session_id)
        if not safe_id:
            safe_id = "default"
        if safe_id in self._sessions:
            return self._sessions[safe_id]
        os.makedirs(_JAR_DIR, exist_ok=True)
        jar_path = os.path.join(_JAR_DIR, f"{safe_id}.cookies")
        self._sessions[safe_id] = jar_path
        return jar_path

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        meta = request.metadata
        url = _require(meta, "url", self.name)
        scheme_reason = unsupported_url_scheme_reason(url)
        if scheme_reason:
            return ToolExecutionResult(
                tool_name=self.name, mode=self.mode, exit_code=126, stderr=scheme_reason
            )
        method = str(meta.get("method") or "GET").upper()
        headers = meta.get("headers") or {}
        data = str(meta.get("data") or "")
        extra = str(meta.get("extra_args") or "")
        session_id = str(meta.get("session_id") or "").strip()
        cookies = str(meta.get("cookies") or "").strip()
        follow = meta.get("follow_redirects")
        auth = str(meta.get("auth") or "").strip()
        parts: list[str] = ["curl", "-s", "-S", "-i", "-X", method]
        if session_id:
            jar = self._resolve_jar(session_id)
            parts.extend(["-b", jar, "-c", jar])
        elif cookies:
            parts.extend(["-b", cookies])
        if follow and str(follow).lower() not in ("false", "0", "no", ""):
            parts.append("-L")
        if auth:
            parts.extend(["-u", auth])
        for k, v in headers.items() if isinstance(headers, dict) else []:
            parts.extend(["-H", f"{k}: {v}"])
        if data:
            parts.extend(["-d", data])
        if extra:
            cmd = " ".join((_shell_quote(p) for p in parts))
            cmd += f" {extra} {_shell_quote(url)}"
            return _run(
                self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
            )
        parts.append(url)
        return _run(self.name, [*self.argv_prefix, *parts], request.timeout_s)


def _shell_quote(s: str) -> str:
    """Minimal POSIX shell quoting."""
    if not s:
        return "''"
    if re.fullmatch("[a-zA-Z0-9_./:@=,-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    """Parse curl response: headers, cookies, redirects → ToolOutput."""
    meta = request.metadata
    url = str(meta.get("url") or "")
    method = str(meta.get("method") or "GET").upper()
    session_id = str(meta.get("session_id") or "").strip()
    auth = str(meta.get("auth") or "").strip()
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    parts = re.split("\\r?\\n\\r?\\n", stdout)
    if len(parts) >= 2:
        last_header_idx = 0
        for i, part in enumerate(parts[:-1]):
            if part.strip().upper().startswith("HTTP/"):
                last_header_idx = i
        headers_text = "\r\n\r\n".join(parts[: last_header_idx + 1])
        body = "\r\n\r\n".join(parts[last_header_idx + 1 :])
    else:
        headers_text, body = ("", stdout)
    http_status: int | None = None
    all_statuses = _HTTP_STATUS_RE.findall(stdout)
    if all_statuses:
        http_status = int(all_statuses[-1])
    parsed_headers = _parse_headers_block(headers_text)
    server = parsed_headers.get("server", "")
    content_type = parsed_headers.get("content-type", "")
    content_length = parsed_headers.get("content-length", "")
    location = parsed_headers.get("location", "")
    set_cookies = _parse_set_cookies(headers_text)
    redirect_chain = _parse_redirect_chain(stdout)
    flags = _flag_candidates_from(body, source="curl")
    summary = f"curl {method} {url}: HTTP {http_status or '?'}"
    if len(redirect_chain) > 1:
        summary += f" ({len(redirect_chain)} redirects)"
    if set_cookies:
        summary += f", {len(set_cookies)} cookie(s)"
    if session_id:
        summary += f" [session:{session_id}]"
    if status.value == "failure":
        summary = f"curl {method} {url} failed (exit {result.exit_code})"
    if result.exit_code == 126 and unsupported_url_scheme_reason(url):
        summary = f"curl blocked for non-HTTP URL: {url}"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "url": url,
        "method": method,
        "http_status": http_status,
        "server": server,
        "body_length": len(body),
    }
    if content_type:
        output_context["content_type"] = content_type
    if content_length:
        output_context["content_length"] = content_length
    if location:
        output_context["location"] = location
    if set_cookies:
        output_context["set_cookies"] = set_cookies
    if len(redirect_chain) > 1:
        output_context["redirect_chain"] = [
            {"status": hop["status"]} for hop in redirect_chain
        ]
    if session_id:
        output_context["session_id"] = session_id
    if result.exit_code == 126 and unsupported_url_scheme_reason(url):
        output_context["failure_kind"] = "non_http_url_blocked"
        output_context["failure_detail"] = (
            "curl handles HTTP/HTTPS only; use script.exec with socket timeouts for raw TCP"
        )
    endpoints: list[Endpoint] = []
    if url and output_context.get("failure_kind") != "non_http_url_blocked":
        base = _extract_base_url(url)
        parsed_url = urlparse(url)
        endpoints.append(
            Endpoint(
                url=base,
                hostname=parsed_url.hostname or None,
                port=parsed_url.port,
                protocol="https" if parsed_url.scheme == "https" else "http",
                status_code=http_status,
                metadata={"server": server} if server else {},
            )
        )
    routes: list[Route] = []
    if (
        url
        and http_status is not None
        and (output_context.get("failure_kind") != "non_http_url_blocked")
    ):
        parsed_url = urlparse(url)
        routes.append(
            Route(
                url=url,
                path=parsed_url.path or "/",
                method=method,
                status_code=http_status,
                source="curl",
            )
        )
    sessions: list[Session] = []
    if session_id and set_cookies:
        sessions.append(
            Session(
                session_type="http_cookie",
                status="active",
                metadata={"session_id": session_id, "cookies": set_cookies, "url": url},
            )
        )
    credentials: list[Credential] = []
    if auth and ":" in auth and http_status and (http_status < 400):
        username, secret = auth.split(":", 1)
        credentials.append(
            Credential(
                credential_id=f"curl-auth-{username[:32]}",
                username=username,
                secret_ref=f"basic-auth:{username}:***",
                credential_type="http_basic",
                source="curl",
                metadata={"url": url, "http_status": http_status},
            )
        )
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(body, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        endpoints=endpoints,
        routes=routes,
        sessions=sessions,
        credentials=credentials,
    )
