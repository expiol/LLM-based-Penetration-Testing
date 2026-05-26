"""john — password cracking with John the Ripper.

Supports:
  - Hash file cracking with wordlists, format selection
  - Rich output parsing: cracked credentials, hash types
  - Typed state signals: Credential per cracked password
"""

from __future__ import annotations
import re
from typing import Any
from killchain_docker.state.domain import Credential
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

_CRACKED_RE = re.compile("^(.+?):(.+?)(?::.*)?$", re.MULTILINE)
_SUMMARY_RE = re.compile("(\\d+) password hash(?:es)? cracked", re.IGNORECASE)
_LOADED_RE = re.compile("Loaded (\\d+) password hash", re.IGNORECASE)
_FORMAT_RE = re.compile('(?:using default|Will run) .+ format "(.+?)"', re.IGNORECASE)
_NOISE = frozenset(
    {
        "password hash",
        "loaded",
        "will run",
        "using default",
        "proceeding",
        "press",
        "session",
        "cost ",
    }
)


class JohnPlugin:
    name = "john"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        wordlist = str(request.metadata.get("wordlist") or "")
        fmt = str(request.metadata.get("format") or "")
        extra = str(request.metadata.get("extra_args") or "")
        cmd = "john"
        if wordlist:
            cmd += f" --wordlist={wordlist}"
        if fmt:
            cmd += f" --format={fmt}"
        if extra:
            cmd += f" {extra}"
        cmd += f" {path} && john --show {path}"
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
    cracked: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _CRACKED_RE.finditer(stdout):
        user, passwd = (m.group(1).strip(), m.group(2).strip())
        if any((skip in user.lower() for skip in _NOISE)):
            continue
        key = f"{user}:{passwd}"
        if key not in seen:
            seen.add(key)
            cracked.append({"username": user, "password": passwd})
    loaded_count = 0
    m = _LOADED_RE.search(stdout + stderr)
    if m:
        loaded_count = int(m.group(1))
    cracked_count = len(cracked)
    m = _SUMMARY_RE.search(stdout + stderr)
    if m:
        cracked_count = max(cracked_count, int(m.group(1)))
    hash_format = ""
    m = _FORMAT_RE.search(stdout + stderr)
    if m:
        hash_format = m.group(1).strip()
    credentials: list[Credential] = []
    for entry in cracked[:50]:
        credentials.append(
            Credential(
                credential_id=f"john-{entry['username'][:32]}",
                username=entry["username"],
                secret_ref=f"cracked:{entry['password']}",
                credential_type=hash_format or "hash",
                source="john",
                metadata={"hash_file": path},
            )
        )
    flags = _flag_candidates_from(stdout, source="john")
    for entry in cracked:
        flags.extend(_flag_candidates_from(entry["password"], source="john"))
    summary = f"john {path}: {cracked_count} cracked"
    if loaded_count:
        summary += f" / {loaded_count} loaded"
    if hash_format:
        summary += f" ({hash_format})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "cracked_count": cracked_count,
        "loaded_count": loaded_count,
        "cracked": [
            {"username": e["username"], "password": e["password"]} for e in cracked[:20]
        ],
    }
    if hash_format:
        output_context["hash_format"] = hash_format
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        credentials=credentials,
    )
