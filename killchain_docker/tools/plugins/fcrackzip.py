"""fcrackzip — ZIP password cracking.

Supports:
  - Dictionary and brute-force attacks on password-protected ZIPs
  - Rich output parsing: extracted password, auto-extract after crack
  - Typed state signals: Credential on cracked password, Artifact for extracted files
"""

from __future__ import annotations
import re
from typing import Any
from killchain_docker.state.domain import Artifact, Credential
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

_PW_RE = re.compile(
    "(?:PASSWORD FOUND|pw\\s*==)\\s*[\\\"']?(.+?)[\\\"']?\\s*$",
    re.IGNORECASE | re.MULTILINE,
)


class FcrackzipPlugin:
    name = "fcrackzip"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        wordlist = str(
            request.metadata.get("wordlist") or "/usr/share/wordlists/rockyou.txt"
        )
        extra = str(request.metadata.get("extra_args") or "")
        cmd = f"""fcrackzip -u -D -p {wordlist} {extra} {path} && pw=$(fcrackzip -u -D -p {wordlist} {path} 2>/dev/null | grep -ioP '(?:pw ==|PASSWORD FOUND)\\s*\\K\\S+'); [ -n "$pw" ] && unzip -o -P "$pw" {path} -d /tmp/fcrackzip_out 2>&1 || true"""
        return _run(
            self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
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
    password = ""
    m = _PW_RE.search(stdout)
    if m:
        password = m.group(1).strip().strip("'\"")
    extracted_files: list[str] = []
    for line in stdout.splitlines():
        line_s = line.strip()
        if line_s.startswith("inflating:") or line_s.startswith("extracting:"):
            fname = line_s.split(":", 1)[1].strip()
            if fname:
                extracted_files.append(fname)
    credentials: list[Credential] = []
    if password:
        credentials.append(
            Credential(
                credential_id=f"fcrackzip-{path[:40]}",
                username="(zip archive)",
                secret_ref=f"zip-password:{password}",
                credential_type="zip_password",
                source="fcrackzip",
                metadata={"archive": path},
            )
        )
    artifacts: list[Artifact] = []
    for fpath in extracted_files[:20]:
        artifacts.append(
            Artifact(
                path=fpath,
                kind="extracted",
                source="fcrackzip",
                metadata={"archive": path, "password": password},
            )
        )
    flags = _flag_candidates_from(stdout, source="fcrackzip")
    if password:
        flags.extend(_flag_candidates_from(password, source="fcrackzip"))
    if password:
        summary = f"fcrackzip {path}: PASSWORD FOUND '{password[:40]}'"
        if extracted_files:
            summary += f", {len(extracted_files)} file(s) extracted"
    else:
        summary = f"fcrackzip {path}: no password found"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "password_found": bool(password),
        "password": password,
    }
    if extracted_files:
        output_context["extracted_files"] = extracted_files[:20]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 4000),
        output_context=output_context,
        flag_candidates=flags,
        credentials=credentials,
        artifacts=artifacts,
    )
