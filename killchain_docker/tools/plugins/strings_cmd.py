"""strings — extract printable strings from binary files.

Supports:
  - Configurable minimum length and encoding
  - Rich output parsing: string categorization (URLs, paths, crypto, flags)
  - Typed state signals: Artifact for analyzed file
"""

from __future__ import annotations

import re
from typing import Any

from killchain_docker.state import Artifact, Credential
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
    _truncate,
)

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_PATH_RE = re.compile(r"(/[a-zA-Z0-9_./-]{4,})")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CRYPTO_KEYWORDS = frozenset({
    "aes", "des", "rsa", "sha", "md5", "hmac", "cipher", "encrypt",
    "decrypt", "private", "public", "key", "certificate", "ssl", "tls",
})
_INTERESTING_KEYWORDS = frozenset({
    "password", "passwd", "secret", "token", "admin", "root", "flag",
    "login", "auth", "cookie", "session", "api_key", "apikey",
})


class StringsPlugin:
    name = "strings_cmd"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        min_len = str(request.metadata.get("min_length") or "6")
        encoding = str(request.metadata.get("encoding") or "s")
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"strings -n {min_len} -e {encoding} {path}"],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)

    lines = [line for line in stdout.splitlines() if line.strip()]

    # -- Categorize strings --------------------------------------------------
    urls: list[str] = []
    paths: list[str] = []
    emails: list[str] = []
    crypto_refs: list[str] = []
    interesting: list[str] = []

    for line in lines:
        line_s = line.strip()
        lower = line_s.lower()

        for m in _URL_RE.finditer(line_s):
            if m.group(0) not in urls:
                urls.append(m.group(0))

        for m in _EMAIL_RE.finditer(line_s):
            if m.group(0) not in emails:
                emails.append(m.group(0))

        if any(kw in lower for kw in _CRYPTO_KEYWORDS):
            crypto_refs.append(line_s[:200])

        if any(kw in lower for kw in _INTERESTING_KEYWORDS):
            interesting.append(line_s[:200])

    # Deduplicate
    urls = urls[:20]
    emails = emails[:10]
    crypto_refs = crypto_refs[:15]
    interesting = interesting[:20]

    # -- Artifact ------------------------------------------------------------
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(Artifact(
            path=path, kind="binary", source="strings",
            metadata={"string_count": len(lines)},
        ))

    # -- Credentials (heuristic: "user:pass" or "password=..." patterns) -----
    credentials: list[Credential] = []
    for line_s in interesting:
        # Look for "password=value" or "passwd: value" patterns
        m = re.search(r"(?:password|passwd|secret|token)\s*[:=]\s*(\S+)", line_s, re.IGNORECASE)
        if m:
            credentials.append(Credential(
                credential_id=f"strings-{path[:20]}-{m.group(1)[:20]}",
                username="(from strings)",
                secret_ref=f"strings:{m.group(1)}",
                credential_type="embedded",
                source="strings",
                metadata={"file": path, "context": line_s[:100]},
            ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="strings")

    # -- Summary -------------------------------------------------------------
    summary = f"strings {path}: {len(lines)} string(s)"
    tag_parts: list[str] = []
    if urls:
        tag_parts.append(f"{len(urls)} URL(s)")
    if emails:
        tag_parts.append(f"{len(emails)} email(s)")
    if crypto_refs:
        tag_parts.append("crypto refs")
    if interesting:
        tag_parts.append(f"{len(interesting)} interesting")
    if tag_parts:
        summary += f" ({', '.join(tag_parts)})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "string_count": len(lines),
    }
    if urls:
        output_context["urls"] = urls
    if emails:
        output_context["emails"] = emails
    if crypto_refs:
        output_context["crypto_refs"] = crypto_refs
    if interesting:
        output_context["interesting_strings"] = interesting

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
        credentials=credentials,
    )
