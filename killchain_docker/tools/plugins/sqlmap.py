"""sqlmap — SQL injection detection and exploitation.

Supports:
  - Cookie/session-based injection testing (--cookie, cookie jar from curl session)
  - Custom headers, POST data, form-based injection
  - Database enumeration (--dbs, --tables, --dump)
  - Rich output parsing: injection types, DBMS detection, extracted data
"""

from __future__ import annotations
import re
from typing import Any
from urllib.parse import urlparse
from killchain_docker.state.domain import Endpoint, Finding, Vulnerability
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
_INJECTION_TYPE_RE = re.compile("Type:\\s*(.+?)(?:\\n|$)", re.IGNORECASE)
_PARAM_RE = re.compile("Parameter:\\s*(.+?)(?:\\s*\\(|$)", re.IGNORECASE)
_TABLE_RE = re.compile("^\\[\\*\\]\\s+(.+)$", re.MULTILINE)
_DB_RE = re.compile(
    "available databases.*?:\\s*\\n((?:\\[\\*\\]\\s+.+\\n?)+)", re.IGNORECASE
)


class SqlmapPlugin:
    """SQL injection scanner with session/cookie support.

    When metadata includes ``session_id``, the plugin passes the
    corresponding cookie jar (shared with CurlPlugin) via ``--load-cookies``.
    This enables testing authenticated endpoints discovered during
    earlier curl-based exploration.
    """

    name = "sqlmap"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        meta = request.metadata
        url = _require(meta, "url", self.name)
        extra = str(meta.get("extra_args") or "")
        cookie = str(meta.get("cookie") or "").strip()
        session_id = str(meta.get("session_id") or "").strip()
        headers = meta.get("headers") or {}
        data = str(meta.get("data") or "").strip()
        method = str(meta.get("method") or "").strip().upper()
        parts: list[str] = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2"]
        if cookie:
            parts.extend(["--cookie", cookie])
        elif session_id:
            safe_id = re.sub("[^a-zA-Z0-9_-]", "", session_id)[:64] or "default"
            jar_path = f"{_JAR_DIR}/{safe_id}.cookies"
            parts.extend(["--load-cookies", jar_path])
        if isinstance(headers, dict):
            for k, v in headers.items():
                parts.extend(["--header", f"{k}: {v}"])
        if data:
            parts.extend(["--data", data])
        if method and method != "GET":
            parts.extend(["--method", method])
        if extra:
            cmd = " ".join((_shell_quote(p) for p in parts)) + f" {extra}"
            return _run(
                self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
            )
        return _run(self.name, [*self.argv_prefix, *parts], request.timeout_s)


def _shell_quote(s: str) -> str:
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
    """Parse sqlmap output: injection results, DBMS, tables, data."""
    meta = request.metadata
    url = str(meta.get("url") or "")
    session_id = str(meta.get("session_id") or "").strip()
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    stdout_lower = stdout.lower()
    injectable = "is vulnerable" in stdout_lower or "injectable" in stdout_lower
    dbms = ""
    for line in stdout.splitlines():
        if "back-end DBMS" in line and ":" in line:
            dbms = line.split(":", 1)[-1].strip()
    injection_types: list[str] = _INJECTION_TYPE_RE.findall(stdout)
    params: list[str] = list(dict.fromkeys(_PARAM_RE.findall(stdout)))
    db_match = _DB_RE.search(stdout)
    databases: list[str] = []
    if db_match:
        databases = [m.strip() for m in _TABLE_RE.findall(db_match.group(0))]
    tables: list[str] = []
    table_section = re.search(
        "Database:\\s*\\S+\\s*\\n((?:\\[\\d+ tables?\\]\\n)?(?:\\+[-+]+\\+\\n)?(?:\\|\\s*.+\\n?)+)",
        stdout,
    )
    if table_section:
        for line in table_section.group(0).splitlines():
            line = line.strip().strip("|").strip()
            if line and (not line.startswith("+")) and (not line.startswith("[")):
                tables.append(line)
    findings: list[Finding] = []
    vulnerabilities: list[Vulnerability] = []
    if injectable:
        desc_parts = [f"DBMS: {dbms or 'unknown'}"]
        if injection_types:
            desc_parts.append(f"Types: {', '.join(injection_types[:5])}")
        if params:
            desc_parts.append(f"Parameters: {', '.join(params[:5])}")
        findings.append(
            Finding(
                finding_id=f"sqli-{url[:80]}",
                title=f"SQL injection at {url}",
                severity="critical",
                description="; ".join(desc_parts),
            )
        )
        for param in params[:5]:
            vulnerabilities.append(
                Vulnerability(
                    title=f"SQLi in parameter '{param}' at {url[:80]}",
                    severity="critical",
                    description=f"DBMS: {dbms or 'unknown'}; Types: {', '.join(injection_types[:3]) or 'unknown'}",
                    source="sqlmap",
                )
            )
    flags = _flag_candidates_from(stdout, source="sqlmap")
    endpoints: list[Endpoint] = []
    if url:
        parsed_url = urlparse(url)
        base = (
            f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.scheme else url
        )
        endpoints.append(
            Endpoint(
                url=base,
                hostname=parsed_url.hostname or None,
                port=parsed_url.port,
                protocol="https" if parsed_url.scheme == "https" else "http",
                metadata={"sqlmap_tested": True, "injectable": injectable},
            )
        )
    summary = f"sqlmap {url}: {('INJECTABLE' if injectable else 'not injectable')}"
    if dbms:
        summary += f" ({dbms})"
    if params:
        summary += f", params: {', '.join(params[:3])}"
    if databases:
        summary += f", {len(databases)} db(s)"
    if session_id:
        summary += f" [session:{session_id}]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "url": url,
        "injectable": injectable,
        "dbms": dbms,
    }
    if injection_types:
        output_context["injection_types"] = injection_types[:10]
    if params:
        output_context["vulnerable_params"] = params[:10]
    if databases:
        output_context["databases"] = databases[:20]
    if tables:
        output_context["tables"] = tables[:30]
    if session_id:
        output_context["session_id"] = session_id
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        findings=findings,
        vulnerabilities=vulnerabilities,
        endpoints=endpoints,
    )
