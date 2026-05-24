"""ltrace — library call tracing for dynamic analysis.

Supports:
  - Tracing library function calls with arguments and return values
  - Structured extraction of strcmp/memcmp/strncmp comparisons (potential flags)
  - Call frequency summary
  - Typed state signals: Artifact, FlagCandidate, Credential
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from killchain_docker.state import Artifact, Credential, FlagCandidate
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _truncate,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command

# Parse ltrace output lines: function(args...) = return_value
_CALL_RE = re.compile(
    r"^(?:\[\w+\]\s+)?"         # optional [pid] prefix
    r"(\w+)\(([^)]*)\)"         # function_name(args)
    r"\s*=\s*(.+)$"             # = return_value
)
# Exit line: +++ exited (status N) +++
_EXIT_RE = re.compile(r"\+\+\+ exited \(status (\d+)\) \+\+\+")
# Comparison functions whose arguments are high-value
_COMPARE_FUNCS = frozenset({"strcmp", "strncmp", "memcmp", "strstr", "strcasecmp"})
# Crypto/interesting functions
_CRYPTO_FUNCS = frozenset({
    "EVP_EncryptInit", "EVP_DecryptInit", "EVP_CipherInit",
    "AES_set_encrypt_key", "AES_set_decrypt_key",
    "DES_set_key", "RC4", "MD5", "SHA1", "SHA256",
})


def _parse_arg_string(raw: str) -> str:
    """Extract the string content from a quoted ltrace argument."""
    raw = raw.strip()
    if raw.startswith('"') and (raw.endswith('"') or '",' in raw):
        # Remove surrounding quotes and unescape
        end = raw.rfind('"')
        if end > 0:
            return raw[1:end].replace("\\n", "\n").replace("\\t", "\t")
    return raw


def _split_args(args_str: str) -> list[str]:
    """Split ltrace argument string respecting quotes."""
    args: list[str] = []
    current = ""
    in_quotes = False
    for ch in args_str:
        if ch == '"' and (not current or current[-1] != '\\'):
            in_quotes = not in_quotes
            current += ch
        elif ch == ',' and not in_quotes:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args


class LtracePlugin:
    name = "ltrace"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        args = str(request.metadata.get("args") or "")
        filter_expr = str(request.metadata.get("filter") or "")
        input_data = str(request.metadata.get("input_data") or "")
        files_root = request.metadata.get("files_root")

        # Build ltrace command
        cmd_parts = ["ltrace", "-s", "200"]
        if filter_expr:
            cmd_parts.extend(["-e", shlex.quote(filter_expr)])
        cmd_parts.append(shlex.quote(path))
        if args:
            cmd_parts.append(args)

        cmd = " ".join(cmd_parts)
        # ltrace outputs to stderr; merge to stdout for parsing
        if input_data:
            full_cmd = f"printf %s {shlex.quote(input_data)} | {cmd} 2>&1"
        else:
            full_cmd = f"{cmd} 2>&1"

        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", protected_shell_command(full_cmd, files_root)],
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
    combined = stdout + stderr

    # ltrace often returns the traced program's exit code; do not treat that
    # as a tracing-tool failure.
    status = ToolOutputStatus.SUCCESS

    # Parse calls
    calls: list[dict[str, Any]] = []
    call_counts: dict[str, int] = {}
    interesting_comparisons: list[dict[str, str]] = []
    crypto_calls: list[dict[str, str]] = []
    exit_status: int | None = None

    for line in combined.splitlines():
        line = line.strip()

        # Check for exit status
        m = _EXIT_RE.search(line)
        if m:
            exit_status = int(m.group(1))
            continue

        # Parse function call
        m = _CALL_RE.match(line)
        if m:
            func_name = m.group(1)
            args_raw = m.group(2)
            ret_val = m.group(3).strip()

            args = _split_args(args_raw)
            call_counts[func_name] = call_counts.get(func_name, 0) + 1

            call_entry: dict[str, Any] = {
                "function": func_name,
                "args": [_parse_arg_string(a) for a in args[:4]],
                "return": ret_val[:100],
            }
            calls.append(call_entry)

            # Extract interesting comparisons
            if func_name in _COMPARE_FUNCS and len(args) >= 2:
                arg1 = _parse_arg_string(args[0])
                arg2 = _parse_arg_string(args[1])
                if arg1 and arg2 and len(arg1) >= 2 and len(arg2) >= 2:
                    interesting_comparisons.append({
                        "function": func_name,
                        "arg1": arg1[:200],
                        "arg2": arg2[:200],
                    })

            # Track crypto calls
            if func_name in _CRYPTO_FUNCS:
                crypto_calls.append({
                    "function": func_name,
                    "args": [_parse_arg_string(a) for a in args[:3]],
                })

    # Artifact
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(Artifact(
            path=path, kind="binary", source="ltrace",
            metadata={"call_count": len(calls), "unique_functions": len(call_counts)},
        ))

    # Flag candidates — check comparison args and full output
    flags = _flag_candidates_from(combined, source="ltrace")
    for comp in interesting_comparisons:
        for arg_key in ("arg1", "arg2"):
            val = comp[arg_key]
            extra = _flag_candidates_from(val, source=f"ltrace:{comp['function']}")
            flags.extend(extra)

    # Credentials from comparisons (password-like patterns)
    credentials: list[Credential] = []
    for comp in interesting_comparisons:
        for arg_key in ("arg1", "arg2"):
            val = comp[arg_key]
            if len(val) >= 4 and not val.startswith("0x"):
                credentials.append(Credential(
                    credential_id=f"ltrace-{comp['function']}-{val[:20]}",
                    username="(from ltrace comparison)",
                    secret_ref=f"ltrace:{val}",
                    credential_type="comparison_arg",
                    source="ltrace",
                    metadata={"function": comp["function"], "value": val[:100]},
                ))

    # Summary
    summary = f"ltrace {path}: {len(calls)} call(s), {len(call_counts)} unique function(s)"
    if interesting_comparisons:
        summary += f", {len(interesting_comparisons)} comparison(s)"
    if crypto_calls:
        summary += " [crypto]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # output_context — structured data for LLM
    output_context: dict[str, Any] = {
        "path": path,
        "total_calls": len(calls),
        "unique_functions": len(call_counts),
    }
    if call_counts:
        # Top 20 most frequent calls
        sorted_calls = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)
        output_context["call_summary"] = dict(sorted_calls[:20])
    if interesting_comparisons:
        output_context["interesting_comparisons"] = interesting_comparisons[:20]
    if crypto_calls:
        output_context["crypto_calls"] = crypto_calls[:10]
    if calls:
        output_context["calls"] = calls[:50]
    if exit_status is not None:
        output_context["exit_status"] = exit_status

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(combined, 4000),
        raw_log=_truncate(combined, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
        credentials=credentials,
    )
