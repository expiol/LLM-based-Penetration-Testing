"""nikto — web server vulnerability scanner.

Supports:
  - Cookie/session-based scanning (reuse curl session cookies)
  - Custom headers and authentication
  - Tuning profiles and specific test IDs
  - Rich output parsing: server info, findings categorization, Endpoint/Vulnerability emission
"""

from __future__ import annotations
import re
from typing import Any
from urllib.parse import urlparse
from killchain_docker.state.domain import Endpoint, Vulnerability
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
_FINDING_RE = re.compile("^\\+\\s+(.+)$", re.MULTILINE)
_SERVER_RE = re.compile("^\\+\\s+Server:\\s*(.+)", re.MULTILINE | re.IGNORECASE)
_TARGET_IP_RE = re.compile("^\\+\\s+Target IP:\\s*(.+)", re.MULTILINE)
_OSVDB_RE = re.compile("OSVDB-(\\d+)", re.IGNORECASE)
_HIGH_KEYWORDS = frozenset(
    {
        "remote code execution",
        "rce",
        "command injection",
        "sql injection",
        "file inclusion",
        "lfi",
        "rfi",
        "backdoor",
        "root",
        "admin password",
        "directory traversal",
        "path traversal",
        "shell",
    }
)
_MEDIUM_KEYWORDS = frozenset(
    {
        "xss",
        "cross-site",
        "csrf",
        "clickjacking",
        "information disclosure",
        "directory listing",
        "source code",
        "backup",
        "default credential",
        "phpinfo",
        ".git",
        ".svn",
        ".env",
    }
)


def _classify_severity(text: str) -> str:
    """Heuristic severity from nikto finding text."""
    lower = text.lower()
    if any((kw in lower for kw in _HIGH_KEYWORDS)):
        return "high"
    if any((kw in lower for kw in _MEDIUM_KEYWORDS)):
        return "medium"
    return "low"


def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    if re.fullmatch("[a-zA-Z0-9_./:@=,-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


class NiktoPlugin:
    """Web vulnerability scanner with session/cookie support.

    When metadata includes ``session_id``, the plugin reads the cookie
    jar file shared with CurlPlugin and passes cookies to nikto via
    ``-C`` flag, enabling scanning of authenticated areas.
    """

    name = "nikto"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        meta = request.metadata
        target = _require(meta, "target", self.name)
        extra = str(meta.get("extra_args") or "")
        cookie = str(meta.get("cookie") or "").strip()
        session_id = str(meta.get("session_id") or "").strip()
        tuning = str(meta.get("tuning") or "").strip()
        parts: list[str] = ["nikto", "-h", target, f"-maxtime", f"{request.timeout_s}s"]
        if cookie:
            parts.extend(["-C", cookie])
        elif session_id:
            safe_id = re.sub("[^a-zA-Z0-9_-]", "", session_id)[:64] or "default"
            jar_path = f"{_JAR_DIR}/{safe_id}.cookies"
            cookie_cmd = f"""cookies=$(awk -F'\\t' '!/^#/ && NF>=7 {{printf "%s=%s; ",$6,$7}}' {_shell_quote(jar_path)} 2>/dev/null); """
            base_cmd = " ".join((_shell_quote(p) for p in parts))
            if extra:
                base_cmd += f" {extra}"
            cmd = f"{cookie_cmd} {base_cmd}"
            if cookie_cmd.strip():
                cmd += ' -C "$cookies"'
            return _run(
                self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
            )
        if tuning:
            parts.extend(["-Tuning", tuning])
        if extra:
            cmd = " ".join((_shell_quote(p) for p in parts)) + f" {extra}"
            return _run(
                self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
            )
        return _run(self.name, [*self.argv_prefix, *parts], request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    """Parse nikto output: findings, server info, vulnerabilities."""
    meta = request.metadata
    target = str(meta.get("target") or "")
    session_id = str(meta.get("session_id") or "").strip()
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    finding_lines = [
        line.strip() for line in stdout.splitlines() if line.strip().startswith("+")
    ]
    info_lines: list[str] = []
    vuln_lines: list[str] = []
    for line in finding_lines:
        content = line.lstrip("+ ").strip()
        if any(
            (
                content.lower().startswith(prefix)
                for prefix in (
                    "server:",
                    "target",
                    "start time",
                    "end time",
                    "host(s) tested",
                    "statistics",
                    "scan terminated",
                )
            )
        ):
            info_lines.append(content)
        elif content:
            vuln_lines.append(content)
    server = ""
    m = _SERVER_RE.search(stdout)
    if m:
        server = m.group(1).strip()
    target_ip = ""
    m = _TARGET_IP_RE.search(stdout)
    if m:
        target_ip = m.group(1).strip()
    vulns: list[Vulnerability] = []
    for line in vuln_lines[:30]:
        severity = _classify_severity(line)
        osvdb_refs = _OSVDB_RE.findall(line)
        vuln_meta: dict[str, Any] = {}
        if osvdb_refs:
            vuln_meta["osvdb"] = osvdb_refs
        vulns.append(
            Vulnerability(
                title=line[:200], severity=severity, source="nikto", metadata=vuln_meta
            )
        )
    high_count = sum((1 for v in vulns if v.severity == "high"))
    medium_count = sum((1 for v in vulns if v.severity == "medium"))
    low_count = sum((1 for v in vulns if v.severity == "low"))
    endpoints: list[Endpoint] = []
    if target:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        endpoints.append(
            Endpoint(
                url=target if "://" in target else f"http://{target}",
                hostname=parsed.hostname or None,
                port=parsed.port,
                protocol="https" if parsed.scheme == "https" else "http",
                metadata={
                    "nikto_scanned": True,
                    "server": server,
                    "finding_count": len(vuln_lines),
                },
            )
        )
    flags = _flag_candidates_from(stdout, source="nikto")
    summary = f"nikto {target}: {len(vuln_lines)} finding(s)"
    if high_count:
        summary += f" ({high_count} high"
        if medium_count:
            summary += f", {medium_count} medium"
        summary += ")"
    elif medium_count:
        summary += f" ({medium_count} medium)"
    if server:
        summary += f" [{server}]"
    if session_id:
        summary += f" [session:{session_id}]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "target": target,
        "finding_count": len(vuln_lines),
        "severity_counts": {
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
    }
    if server:
        output_context["server"] = server
    if target_ip:
        output_context["target_ip"] = target_ip
    if vuln_lines:
        output_context["findings_preview"] = vuln_lines[:15]
    if session_id:
        output_context["session_id"] = session_id
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        vulnerabilities=vulns,
        endpoints=endpoints,
    )
