"""script.exec — write LLM-generated code to a temp file and execute it."""

from __future__ import annotations

import ast
import re
import shlex

from killchain_docker.state.constants import DEFAULT_FILES_ROOT, bare_token_shape
from killchain_docker.state import Artifact, ExploitAttempt
from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    loopback_reference_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ParsedToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _run,
    _status,
    _flag_candidates_from,
    _truncate,
    _err_tail,
    _infrastructure_failure_signal,
    ToolExecutionError,
)
from killchain_docker.tools.plugins.workspace import disposable_script_command

_INTERPRETER_MAP = {
    "python": ["python3", "-u"], "bash": ["bash"], "sh": ["sh"],
    "javascript": ["node"], "node": ["node"], "ruby": ["ruby"], "perl": ["perl"],
}
_GRAPHIC_CHARS = set("#$%&*+-/:;<=>?@[\\]^_`{|}~")
_MIN_READABLE_NEAR_MISS_LEN = 240
_PYTHON_RANGE_LIMIT = 5_000_000
_PYTHON_SCRIPT_RUNTIME_LIMIT_S = 0
_PYTHON_SOCKET_DEFAULT_TIMEOUT_S = 5
_NETWORK_SCRIPT_TIMEOUT_CAP_S = 45
_NETWORK_SCRIPT_RE = re.compile(
    r"\b(?:socket|telnetlib|http\.client|urllib|requests|pexpect|pwntools|"
    r"pwn|remote|create_connection|connect|nc|netcat|socat)\b",
    re.IGNORECASE,
)
_PLAINTEXT_LABEL_RE = re.compile(
    r"\b(?:best\s+result|plaintext|plain\s+text|decrypted|decoded|preview|"
    r"first\s+\d+\s+(?:bytes|chars)|output)\b\s*:?",
    re.IGNORECASE,
)
_STATUS_PREFIX_RE = re.compile(r"^\s*(?:\[[^\]]{1,16}\]\s*|[-+*!]\s*)+")
_DIAGNOSTIC_LINE_RE = re.compile(
    r"^(?:"
    r"\d+\.\s+"
    r"|=+\s*(?:top|best|testing)"
    r"|analyzing|attempting|checking|connecting|connected|connection\s+closed"
    r"|banner|context\s+around|ciphertexts?\s+found"
    r"|disassembl|dynamic\s+symbols|extract(?:ed|ing)?|file\s+not\s+found"
    r"|file\s+size|file\s+type|found|header|initial\s+response|magic"
    r"|interesting\s+strings|line\s+\d+|looking\s+for"
    r"|received|reading|running|saved|scanner|search(?:ed|ing)?|sent"
    r"|source|symbol\s+table|target|total|warning|welcome|wrote|writing"
    r"|ct\s+size|raw\s+tap|seed|skip|tap"
    r"|ciphertext|printable|ratio|score|braces|flags|first\s+bytes"
    r"|case\s+\d+|trying|testing|using|skipping|candidate"
    r"|actual|error|stdout|stderr|returncode|length|num\s*:"
    r")\b",
    re.IGNORECASE,
)
_HEXDUMP_LINE_RE = re.compile(
    r"^\s*(?:0x)?[0-9a-fA-F]{1,10}\s*[:|]\s*"
    r"(?:[0-9a-fA-F]{2}(?:\s+|$)){6,}(?:\s{2,}.*)?$"
)
_ASSEMBLY_LINE_RE = re.compile(
    r"^\s*(?:0x)?[0-9a-fA-F]{4,16}:\s+"
    r"(?:[0-9a-fA-F]{2}\s+){1,12}(?:[A-Za-z_.][\w.$@<>+-]*)?"
)
_SYMBOL_TABLE_ENTRY_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]{6,}\s+\d+\s+"
    r"(?:FUNC|OBJECT|NOTYPE|SECTION|FILE|TLS)\b"
)
_BYTES_REPR_LINE_RE = re.compile(r"^\s*b[\"'].{40,}[\"']\s*$")
_PATH_LISTING_LINE_RE = re.compile(r"^\s*(?:\.{0,2}/)?(?:[\w.+@-]+/){1,}\S+\s*$")
_INDEXED_HEX_VALUE_RE = re.compile(r"^\s*\w+\[\d+\]:\s*[0-9a-fA-F]{24,}\b")
_DIAGNOSTIC_REPORT_RE = re.compile(
    r"(?im)^\s*(?:\[[^\]]+\]\s*)?"
    r"(?:=+\s*top\s+|=+\s*local\s+self-test|=+\s*differential\s+test|"
    r"score\s*=|\d+\.\s+seed=|testing\s+\d+.+candidates|braces\s*=|"
    r"first\s+bytes:|all\s+tests\s+passed|solver\s+function|sum\s+verification|"
    r"=+\s*png\s+chunk\s+analysis|=+\s*string\s+search\s+in\s+decrypted\s+png|"
    r"chunk\s+'(?:ihdr|idat|iend|itxt|text|ztxt)'|found\s+\d+\s+printable\s+strings|"
    r"offset\s+\d+\s*:)"
)
_SCRIPT_ARTIFACTS_START = "__KILLCHAIN_SCRIPT_ARTIFACTS__"
_SCRIPT_ARTIFACTS_END = "__KILLCHAIN_SCRIPT_ARTIFACTS_END__"


def _script_uses_network_io(code: str, language: str) -> bool:
    if language in {"python", "bash", "sh"}:
        return bool(_NETWORK_SCRIPT_RE.search(code))
    return False


def _effective_timeout_s(request_timeout_s: int, code: str, language: str) -> int:
    timeout_s = max(1, int(request_timeout_s))
    if _script_uses_network_io(code, language):
        return min(timeout_s, _NETWORK_SCRIPT_TIMEOUT_CAP_S)
    return timeout_s


def _python_runtime_guard_wrapper(timeout_s: int) -> str:
    runtime_limit_s = 0
    if timeout_s > 2:
        runtime_limit_s = timeout_s - 1
        if _PYTHON_SCRIPT_RUNTIME_LIMIT_S > 0:
            runtime_limit_s = min(runtime_limit_s, _PYTHON_SCRIPT_RUNTIME_LIMIT_S)
    socket_timeout_s = min(
        _PYTHON_SOCKET_DEFAULT_TIMEOUT_S,
        max(1, timeout_s - 2),
    )

    return f"""\
import builtins as _kc_builtins
import itertools as _kc_itertools
import linecache as _kc_linecache
import runpy as _kc_runpy
import signal as _kc_signal
import socket as _kc_socket
import sys as _kc_sys
_kc_original_range = _kc_builtins.range
_kc_original_product = _kc_itertools.product
_kc_range_limit = {_PYTHON_RANGE_LIMIT}
_kc_runtime_limit_s = {runtime_limit_s}
_kc_socket.setdefaulttimeout({socket_timeout_s})

def _kc_int_locals(_kc_frame):
    if _kc_frame is None:
        return ""
    _kc_items = []
    for _kc_name, _kc_value in sorted(_kc_frame.f_locals.items()):
        if isinstance(_kc_value, int) and abs(_kc_value) >= _kc_range_limit:
            _kc_items.append(f"{{_kc_name}}={{_kc_value}}")
        if len(_kc_items) >= 8:
            break
    return ", ".join(_kc_items)

def _kc_callsite(_kc_frame):
    if _kc_frame is None:
        return ""
    _kc_line = _kc_linecache.getline(
        _kc_frame.f_code.co_filename, _kc_frame.f_lineno
    ).strip()
    _kc_locals = _kc_int_locals(_kc_frame)
    _kc_parts = [f"line {{_kc_frame.f_lineno}}"]
    if _kc_line:
        _kc_parts.append(f"code={{_kc_line!r}}")
    if _kc_locals:
        _kc_parts.append(f"large_int_locals={{_kc_locals}}")
    return "; ".join(_kc_parts)

def _kc_timeout(_signum, _frame):
    _kc_where = _kc_callsite(_frame)
    _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
    raise RuntimeError(
        "script.exec Python time limit exceeded"
        f"{{_kc_suffix}}; use bounded loops or fast-forward math"
    )

_kc_original_signal = _kc_signal.signal
_kc_original_alarm = getattr(_kc_signal, "alarm", None)
_kc_original_setitimer = getattr(_kc_signal, "setitimer", None)
_kc_user_sigalrm_handler = None

def _kc_dispatch_sigalrm(_kc_signum, _kc_frame):
    _kc_handler = _kc_user_sigalrm_handler
    if _kc_handler not in (None, _kc_signal.SIG_DFL, _kc_signal.SIG_IGN):
        _kc_handler(_kc_signum, _kc_frame)
    _kc_timeout(_kc_signum, _kc_frame)

def _kc_clamped_alarm_seconds(_kc_seconds):
    if not _kc_runtime_limit_s:
        return _kc_seconds
    try:
        _kc_seconds_f = float(_kc_seconds)
    except (TypeError, ValueError):
        return _kc_seconds
    if _kc_seconds_f <= 0:
        return _kc_seconds
    _kc_cap = max(1, _kc_runtime_limit_s - 1)
    if _kc_seconds_f >= _kc_runtime_limit_s:
        return _kc_cap
    return _kc_seconds

def _kc_guarded_alarm(_kc_seconds):
    return _kc_original_alarm(_kc_clamped_alarm_seconds(_kc_seconds))

def _kc_guarded_setitimer(_kc_which, _kc_seconds, _kc_interval=0.0):
    if _kc_which == _kc_signal.ITIMER_REAL:
        _kc_seconds = _kc_clamped_alarm_seconds(_kc_seconds)
    return _kc_original_setitimer(_kc_which, _kc_seconds, _kc_interval)

def _kc_guarded_signal(_kc_signum, _kc_handler):
    global _kc_user_sigalrm_handler
    if _kc_signum == _kc_signal.SIGALRM and _kc_runtime_limit_s:
        _kc_previous = _kc_user_sigalrm_handler
        _kc_user_sigalrm_handler = _kc_handler
        _kc_original_signal(_kc_signum, _kc_dispatch_sigalrm)
        return _kc_previous if _kc_previous is not None else _kc_timeout
    return _kc_original_signal(_kc_signum, _kc_handler)

if _kc_runtime_limit_s:
    _kc_signal.signal(_kc_signal.SIGALRM, _kc_timeout)
    _kc_signal.setitimer(_kc_signal.ITIMER_REAL, _kc_runtime_limit_s)
    _kc_signal.signal = _kc_guarded_signal
    if _kc_original_alarm is not None:
        _kc_signal.alarm = _kc_guarded_alarm
    if _kc_original_setitimer is not None:
        _kc_signal.setitimer = _kc_guarded_setitimer

def _kc_guarded_range(*args):
    _kc_range = _kc_original_range(*args)
    _kc_frame = _kc_sys._getframe(1)
    if _kc_frame.f_code.co_filename != globals().get("_kc_script_path"):
        return _kc_range
    try:
        _kc_size = len(_kc_range)
    except OverflowError as _kc_exc:
        _kc_where = _kc_callsite(_kc_frame)
        _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
        raise RuntimeError(
            "range too large for script.exec"
            f"{{_kc_suffix}}; use fast-forward math or bounded sampling"
        ) from _kc_exc
    if _kc_size > _kc_range_limit:
        _kc_where = _kc_callsite(_kc_frame)
        _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
        raise RuntimeError(
            f"range too large for script.exec: {{_kc_size}} > {{_kc_range_limit}}; "
            f"{{_kc_suffix}}; "
            "use fast-forward math or bounded sampling"
        )
    return _kc_range

_kc_builtins.range = _kc_guarded_range

def _kc_guarded_product(*_kc_iterables, repeat=1):
    _kc_frame = _kc_sys._getframe(1)
    if _kc_frame.f_code.co_filename != globals().get("_kc_script_path"):
        return _kc_original_product(*_kc_iterables, repeat=repeat)
    try:
        _kc_repeat = int(repeat)
    except (TypeError, ValueError) as _kc_exc:
        raise RuntimeError("itertools.product repeat must be an integer") from _kc_exc
    if _kc_repeat < 0:
        raise ValueError("repeat argument cannot be negative")
    _kc_lengths = []
    for _kc_iterable in _kc_iterables:
        try:
            _kc_lengths.append(len(_kc_iterable))
        except TypeError:
            return _kc_original_product(*_kc_iterables, repeat=repeat)
    _kc_size = 1
    for _ in _kc_original_range(_kc_repeat):
        for _kc_length in _kc_lengths:
            _kc_size *= _kc_length
            if _kc_size > _kc_range_limit:
                _kc_where = _kc_callsite(_kc_frame)
                _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
                raise RuntimeError(
                    f"product too large for script.exec: {{_kc_size}} > {{_kc_range_limit}}; "
                    f"{{_kc_suffix}}; "
                    "use fast-forward math or bounded sampling"
                )
    return _kc_original_product(*_kc_iterables, repeat=repeat)

_kc_itertools.product = _kc_guarded_product
del _kc_guarded_range, _kc_guarded_product, _kc_builtins, _kc_itertools

if len(_kc_sys.argv) < 2:
    raise RuntimeError("script.exec wrapper missing script path")
_kc_script_path = _kc_sys.argv[1]
_kc_sys.argv = [_kc_script_path, *_kc_sys.argv[2:]]
_kc_runpy.run_path(_kc_script_path, run_name="__main__")

"""


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:12000]
    printable = sum(1 for ch in sample if ch in "\n\r\t" or 32 <= ord(ch) <= 126)
    return printable / len(sample)


def _graphic_density(line: str) -> float:
    visible = [ch for ch in line if not ch.isspace()]
    if not visible:
        return 0.0
    graphic = sum(1 for ch in visible if ch in _GRAPHIC_CHARS)
    return graphic / len(visible)


def _collapse_visual_runs(line: str) -> str:
    return re.sub(r"([^\s])\1{2,}", r"\1", line.strip())


def _escaped_repr_density(text: str) -> float:
    if not text:
        return 0.0
    escaped = re.findall(
        r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0abfnrtv]",
        text,
    )
    return len(escaped) / len(text)


def _diagnostic_line_ratio(lines: list[str]) -> float:
    non_empty = [line.strip() for line in lines if line.strip()]
    if not non_empty:
        return 1.0
    diagnostic = sum(1 for line in non_empty if _is_diagnostic_line(line))
    return diagnostic / len(non_empty)


def _is_diagnostic_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped in {_SCRIPT_ARTIFACTS_START, _SCRIPT_ARTIFACTS_END}:
        return True

    normalized = _STATUS_PREFIX_RE.sub("", stripped).strip().strip("=- ")
    if not normalized:
        return True

    return bool(
        _DIAGNOSTIC_LINE_RE.match(normalized)
        or _HEXDUMP_LINE_RE.match(stripped)
        or _HEXDUMP_LINE_RE.match(normalized)
        or _ASSEMBLY_LINE_RE.match(stripped)
        or _ASSEMBLY_LINE_RE.match(normalized)
        or _SYMBOL_TABLE_ENTRY_RE.match(stripped)
        or _SYMBOL_TABLE_ENTRY_RE.match(normalized)
        or _BYTES_REPR_LINE_RE.match(stripped)
        or _PATH_LISTING_LINE_RE.match(stripped)
        or _INDEXED_HEX_VALUE_RE.match(stripped)
    )


def _strip_script_artifact_manifest(stdout: str) -> str:
    lines = stdout.replace("\r", "\n").splitlines()
    kept: list[str] = []
    in_manifest = False
    for line in lines:
        stripped = line.strip()
        if stripped == _SCRIPT_ARTIFACTS_START:
            in_manifest = True
            continue
        if in_manifest:
            if stripped == _SCRIPT_ARTIFACTS_END:
                in_manifest = False
            continue
        kept.append(line)
    return "\n".join(kept)


def _looks_like_visual_art_block(lines: list[str]) -> bool:
    non_empty = [line for line in lines if line.strip()]
    if len(non_empty) < 3:
        return False
    if any(_is_diagnostic_line(line) for line in non_empty):
        return False
    graphic_lines = [
        line for line in non_empty
        if len(line) >= 20 and _graphic_density(line) >= 0.25
    ]
    banner_text_lines = [
        line for line in non_empty
        if _looks_like_visual_banner_text_line(line)
    ]
    visual_lines = len(graphic_lines) + len(banner_text_lines)
    return visual_lines >= 3 and visual_lines / len(non_empty) >= 0.50


def _looks_like_visual_banner_text_line(line: str) -> bool:
    if len(line) < 60:
        return False
    letters = [ch for ch in line if ch.isalpha()]
    if len(letters) < 20:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    whitespace = sum(1 for ch in line if ch.isspace())
    return uppercase / len(letters) >= 0.80 and whitespace / len(line) >= 0.18


def _plaintext_blocks(stdout: str) -> list[str]:
    lines = stdout.replace("\r", "\n").splitlines()
    blocks: list[str] = []

    for index, line in enumerate(lines):
        match = _PLAINTEXT_LABEL_RE.search(line)
        if not match:
            continue

        inline = line[match.end():].strip(" :")
        if inline:
            blocks.append(inline)

        following: list[str] = []
        for next_line in lines[index + 1:index + 12]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if stripped.startswith("=" * 8) or stripped.startswith("-" * 8):
                if following:
                    break
                continue
            if (
                _PLAINTEXT_LABEL_RE.search(next_line)
                or _is_diagnostic_line(stripped)
            ):
                if following:
                    break
                continue
            following.append(next_line.rstrip())
        if following:
            blocks.append("\n".join(following))

    if blocks:
        return blocks
    if _DIAGNOSTIC_REPORT_RE.search(stdout):
        return []
    if _diagnostic_line_ratio(lines) >= 0.45:
        return []
    return []


def _readable_near_misses(stdout: str) -> list[str]:
    stdout = _strip_script_artifact_manifest(stdout)
    if len(stdout) < _MIN_READABLE_NEAR_MISS_LEN:
        return []

    labelled_blocks = _plaintext_blocks(stdout)
    blocks = [(block, False) for block in labelled_blocks]
    if not blocks:
        stdout_lines = [line.rstrip() for line in stdout.replace("\r", "\n").splitlines()]
        if _looks_like_visual_art_block(stdout_lines):
            blocks = [(stdout, True)]

    for block, require_visual in blocks:
        if _DIAGNOSTIC_REPORT_RE.search(block):
            continue
        if len(block) < _MIN_READABLE_NEAR_MISS_LEN:
            continue
        if _printable_ratio(block) < 0.92:
            continue
        if _escaped_repr_density(block) > 0.03:
            continue

        lines = [line.rstrip() for line in block.replace("\r", "\n").splitlines()]
        non_empty = [line for line in lines if line.strip()]
        if _diagnostic_line_ratio(non_empty) >= 0.45:
            continue
        graphic_lines = [
            line for line in non_empty
            if len(line) >= 20 and _graphic_density(line) >= 0.25
        ]
        banner_text_lines = [
            line for line in non_empty
            if _looks_like_visual_banner_text_line(line)
        ]
        long_text_lines = [line for line in non_empty if len(line) >= 60]
        if require_visual:
            if len(graphic_lines) + len(banner_text_lines) < 3:
                continue
        elif len(graphic_lines) < 3 and len(long_text_lines) < 3:
            continue

        compact_lines: list[str] = []
        seen: set[str] = set()
        for line in non_empty[:24]:
            compact = _collapse_visual_runs(line)
            if compact in seen:
                continue
            seen.add(compact)
            compact_lines.append(compact[:180])
            if len("\n".join(compact_lines)) >= 900:
                break

        preview = _truncate("\n".join(compact_lines), 900)
        if preview:
            return [f"readable/plaintext-or-ascii-art preview:\n{preview}"]
    return []


def _script_failure_signal(output_text: str, exit_code: int | None) -> tuple[str, str]:
    infrastructure = _infrastructure_failure_signal(output_text, "", exit_code)
    if infrastructure is not None:
        return infrastructure
    text = output_text.lower()
    if "brokenpipeerror" in text or "broken pipe" in text:
        return "network_pipe_closed", "remote endpoint closed the socket while the script was writing"
    if "connectionreseterror" in text or "connection reset by peer" in text:
        return "connection_reset", "remote endpoint reset the connection"
    if "connectionrefusederror" in text or "connection refused" in text:
        return "connection_refused", "remote endpoint refused the connection"
    if "scope_violation_blocked" in text or "outside authorized_scope" in text:
        return "scope_violation_blocked", "script attempted to leave authorized_scope or files_root"
    if (
        "no space left on device" in text
        or "mktemp: failed to create directory" in text
        or "workspace budget exceeded" in text
    ):
        return "scratch_space_exhausted", "script scratch workspace could not be created or filled the container overlay"
    if "range too large for script.exec" in text or "product too large for script.exec" in text:
        return "unbounded_loop_guard", "script attempted an oversized range/search; use fast-forward math or bounded sampling"
    if "script.exec python time limit exceeded" in text:
        return "unbounded_loop_guard", "script exceeded Python runtime guard; use bounded loops or fast-forward math"
    hard_timeout = "[timeout after" in text or "timed out" in text
    runtime_timeout = (
        "timeouterror" in text
        or "socket timeout" in text
        or "timeout during" in text
    )
    if hard_timeout or (runtime_timeout and exit_code not in (None, 0)):
        return "timeout", "script exceeded its execution or socket timeout"
    if (
        "failed to parse" in text
        or "could not parse" in text
        or "parse error" in text
        or "invalid literal for int" in text
        or "binascii.error: odd-length string" in text
        or "binascii.error: non-hexadecimal digit found" in text
    ):
        return "parse_error", "script parsing logic rejected tool or service output; validate delimiters and exact field shape"
    if (
        ("struct.error" in text and "buffer" in text)
        or "unpack requires a buffer" in text
        or "unpack_from requires a buffer" in text
        or "not enough values to unpack" in text
        or "unexpected end of data" in text
        or "truncated file" in text
    ):
        return (
            "binary_structure_error",
            "script parsed binary structures without sufficient bounds checks",
        )
    if (
        "a bytes-like object is required" in text
        or "can't concat str to bytes" in text
        or "can't concat bytes to str" in text
        or "must be str, not bytes" in text
        or "must be bytes, not str" in text
        or "byte indices must be integers or slices" in text
        or "ord() expected string of length 1, but int found" in text
        or "unicodedecodeerror" in text
        or "unicodeencodeerror" in text
    ):
        return "bytes_text_mismatch", "script mixed bytes and text across an IO boundary"
    if (
        "unsupported operand type(s) for /: 'str' and 'str'" in text
        or "unsupported operand type(s) for /: \"str\" and \"str\"" in text
        or "'str' object has no attribute 'glob'" in text
        or "'str' object has no attribute 'iterdir'" in text
    ):
        return "path_type_mismatch", "script mixed string paths with pathlib operations"
    if "nameerror:" in text and "is not defined" in text:
        return (
            "undefined_name",
            "script referenced a variable, function, or module before assignment",
        )
    if "attributeerror:" in text and "object has no attribute" in text:
        return (
            "type_error",
            "script used a method on an incompatible value type; inspect and convert the value deliberately",
        )
    if "typeerror:" in text:
        return (
            "type_error",
            "script used incompatible value types or an invalid operator",
        )
    if "syntaxerror" in text:
        return "syntax_error", "script failed Python or shell syntax validation"
    return "nonzero_exit", f"script exited with status {exit_code}"


def _traceback_excerpt(output_text: str, *, width: int = 4000) -> str:
    marker = "Traceback (most recent call last):"
    index = output_text.find(marker)
    if index < 0:
        return ""
    return _truncate(output_text[index:].strip(), width)


def _flag_candidates_from_script_stdout(stdout: str, *, source: str):
    candidates = _flag_candidates_from(stdout, source=source)
    if not candidates:
        return []
    has_visual_text = bool(_readable_near_misses(stdout))
    filtered = [
        candidate for candidate in candidates
        if _candidate_has_readable_context(
            stdout,
            candidate.value,
            allow_derived_visual=has_visual_text,
        )
    ]
    if has_visual_text:
        filtered.sort(key=lambda candidate: _script_candidate_rank(candidate.value, stdout))
    return filtered


def _script_candidate_rank(candidate: str, stdout: str) -> tuple[int, int]:
    if "{" in candidate and candidate in stdout:
        return (0, 0)
    if candidate not in stdout and _looks_like_visual_text_candidate(candidate):
        return (1, 0)
    return (2, 0)


def _candidate_has_readable_context(
    stdout: str,
    candidate: str,
    *,
    allow_derived_visual: bool = False,
) -> bool:
    if allow_derived_visual and _looks_like_visual_text_candidate(candidate):
        return True

    if "{" in candidate and candidate not in stdout:
        if _candidate_body_has_readable_context(stdout, candidate):
            return True

    labels = (
        "flag found", "candidate flag", "possible flag", "valid flag",
        "recovered flag", "validated flag",
    )
    start = 0
    while True:
        index = stdout.find(candidate, start)
        if index < 0:
            return False
        line_start = stdout.rfind("\n", 0, index) + 1
        line_end = stdout.find("\n", index)
        if line_end < 0:
            line_end = len(stdout)
        window_start = max(line_start, index - 120)
        window_end = min(line_end, index + len(candidate) + 120)
        window = stdout[window_start:window_end]
        lowered = window.lower()
        if any(label in lowered for label in labels):
            return True
        if "\ufffd" not in window and _printable_ratio(window) >= 0.90:
            return True
        start = index + len(candidate)


def _candidate_body_has_readable_context(stdout: str, candidate: str) -> bool:
    prefix, _sep, body_with_brace = candidate.partition("{")
    body = body_with_brace[:-1] if body_with_brace.endswith("}") else ""
    if not prefix or not body:
        return False

    labels = (
        "answer",
        "flag",
        "key",
        "plaintext",
        "recovered",
        "secret",
        "validated",
    )
    negative = ("no flag", "not found", "mismatch", "invalid", "rejected")
    for needle in (f"{{{body}}}", body):
        start = 0
        while True:
            index = stdout.find(needle, start)
            if index < 0:
                break
            line_start = stdout.rfind("\n", 0, index) + 1
            line_end = stdout.find("\n", index)
            if line_end < 0:
                line_end = len(stdout)
            window_start = max(line_start, index - 160)
            window_end = min(line_end, index + len(needle) + 160)
            context = stdout[window_start:window_end].lower()
            if any(label in context for label in labels) and not any(
                item in context for item in negative
            ):
                return True
            start = index + len(needle)
    return False


def _looks_like_visual_text_candidate(candidate: str) -> bool:
    text = str(candidate or "").strip()
    if "{" in text or "}" in text:
        return False
    if "_" not in text:
        return False
    if not bare_token_shape(text):
        return False
    parts = [part for part in text.split("_") if part]
    if len(parts) < 2:
        return False
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    return uppercase / len(letters) >= 0.70


class ScriptPlugin:
    """Write LLM-generated code to a temp file and execute it."""

    name = "script_exec"
    mode = ExecutionMode.LOCAL_COMMAND
    python_executable: str = "python3"

    def __init__(self, *, argv_prefix: list[str] | None = None, python_executable: str | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])
        if python_executable:
            self.python_executable = python_executable

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        script_code = str(request.metadata.get("script_code") or "").strip()
        if not script_code:
            raise ToolExecutionError("script.exec requires metadata.script_code")

        language = str(request.metadata.get("script_language") or "python").lower()
        interpreter = _INTERPRETER_MAP.get(language, [self.python_executable])
        if language == "python":
            interpreter = [self.python_executable, "-u"]

        # Syntax check before execution — fail fast without wasting container time
        syntax_error = self._check_syntax(script_code, language)
        if syntax_error:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=1,
                stdout="",
                stderr=syntax_error,
            )

        files_root = request.metadata.get("files_root") or DEFAULT_FILES_ROOT
        scope_reason = scratch_path_reference_block_reason(script_code)
        if _script_uses_network_io(script_code, language):
            scope_reason = scope_reason or loopback_reference_block_reason(
                script_code,
                request.metadata.get("authorized_scope"),
            )
        scope_reason = scope_reason or ambient_filesystem_block_reason(
            script_code,
            files_root=files_root,
            authorized_scope=request.metadata.get("authorized_scope"),
        )
        if scope_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stdout="",
                stderr=(
                    f"scope_violation_blocked: {scope_reason}; stay within "
                    "authorized_scope, files_root, and CTF_TEMP_DIR."
                ),
            )
        timeout_s = _effective_timeout_s(request.timeout_s, script_code, language)
        interpreter_cmd = shlex.join(interpreter)
        shell_cmd = disposable_script_command(
            files_root=files_root,
            interpreter_cmd=interpreter_cmd,
            max_workspace_mb=request.metadata.get("max_workspace_mb"),
            max_memory_mb=request.metadata.get("max_memory_mb"),
            max_cpu_s=request.metadata.get("max_cpu_s"),
            guard_source=(
                _python_runtime_guard_wrapper(timeout_s)
                if language == "python"
                else None
            ),
        )
        input_text = script_code
        argv = [*self.argv_prefix, "bash", "-c", shell_cmd]
        return _run(self.name, argv, timeout_s, input_text=input_text)

    @staticmethod
    def _check_syntax(code: str, language: str) -> str | None:
        """Return an error message if the script has syntax errors, else None."""
        if language == "python":
            try:
                ast.parse(code)
            except SyntaxError as exc:
                lineno = f" (line {exc.lineno})" if exc.lineno else ""
                return f"SyntaxError{lineno}: {exc.msg}"
        elif language in ("bash", "sh"):
            try:
                result = _run(
                    "script_syntax_check",
                    [language, "-n"],
                    5,
                    input_text=code,
                    max_output_bytes=4000,
                )
                if result.exit_code != 0:
                    return result.stderr.strip() or f"bash -n failed (exit {result.exit_code})"
            except ToolExecutionError:
                pass  # Cannot check locally — let it run in container
        return None


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    language = str(request.metadata.get("script_language") or "python")
    status = _status(result)
    stdout, stderr = result.stdout or "", result.stderr or ""
    artifact_records = _script_artifact_records(stdout)

    summary = f"script ({language})"
    if status.value == "failure":
        summary = f"script failed: {_err_tail(stderr) or f'exit {result.exit_code}'}"

    flags = _flag_candidates_from_script_stdout(stdout, source=f"script:{language}")
    near_misses = [] if flags else _readable_near_misses(stdout)
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    elif near_misses:
        summary += " — readable near-miss output"

    output_context: dict = {
        "stdout": _truncate(stdout, 4000),
        "stderr": _truncate(stderr, 1500),
        "returncode": result.exit_code,
        "flag_candidates": [fc.value for fc in flags],
    }
    traceback = _traceback_excerpt("\n".join(part for part in (stderr, stdout) if part))
    if traceback:
        output_context["traceback"] = traceback
    artifacts = _script_artifacts(artifact_records)
    if artifact_records:
        output_context["generated_artifact_records"] = artifact_records[:40]
        output_context["generated_artifacts_durable"] = True
    if near_misses:
        output_context["near_miss_candidates"] = near_misses
    if status.value == "failure":
        failure_text = "\n".join(part for part in (stderr, stdout) if part)
        failure_kind, failure_detail = _script_failure_signal(failure_text, result.exit_code)
        output_context["failure_kind"] = failure_kind
        output_context["failure_detail"] = failure_detail
    if status.value == "success" and not flags:
        if near_misses:
            output_context["result_quality"] = "near_miss"
        else:
            output_text = "\n".join(part for part in (stderr, stdout) if part)
            failure_kind, failure_detail = _script_failure_signal(output_text, result.exit_code)
            output_context["result_quality"] = "partial_no_candidate"
            if failure_kind != "nonzero_exit":
                output_context["partial_reason"] = failure_detail
                output_context["failure_kind"] = failure_kind
                output_context["failure_detail"] = failure_detail
            else:
                output_context["partial_reason"] = "script exited successfully but no flag candidate was recovered"
                output_context["failure_kind"] = "no_candidate"
                output_context["failure_detail"] = output_context["partial_reason"]

    exploit_attempts: list[ExploitAttempt] = []
    if flags or status.value == "failure":
        exploit_attempts.append(ExploitAttempt(
            technique=f"script:{language}", success=bool(flags),
            summary=summary,
            flag_candidate_refs=[fc.value for fc in flags],
            metadata={"returncode": result.exit_code},
        ))

    return ToolOutput(
        status=status, summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        artifacts=artifacts,
        flag_candidates=flags,
        exploit_attempts=exploit_attempts,
    )


def _script_artifact_records(stdout: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    in_section = False
    for line in stdout.splitlines():
        if line.strip() == _SCRIPT_ARTIFACTS_START:
            in_section = True
            continue
        if line.strip() == _SCRIPT_ARTIFACTS_END:
            break
        if not in_section:
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        path, size_text, origin, relative_path = parts[:4]
        if not path.startswith("/"):
            continue
        try:
            size = int(size_text)
        except ValueError:
            size = None
        digest = parts[4].strip() if len(parts) >= 5 else ""
        file_type = parts[5].strip() if len(parts) >= 6 else ""
        mime_type = parts[6].strip() if len(parts) >= 7 else ""
        records.append(
            {
                "path": path,
                "size": size,
                "origin": origin,
                "relative_path": relative_path,
                "digest": digest or None,
                "file_type": file_type or None,
                "mime_type": mime_type or None,
            }
        )
        if len(records) >= 40:
            break
    return records


def _script_artifacts(records: list[dict[str, object]]) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for record in records[:40]:
        path = str(record.get("path") or "")
        if not path:
            continue
        size = record.get("size")
        file_type = str(record.get("file_type") or "")
        mime_type = str(record.get("mime_type") or "")
        kind = _script_artifact_kind(file_type=file_type, mime_type=mime_type)
        digest = record.get("digest")
        artifacts.append(
            Artifact(
                path=path,
                kind=kind,
                source="script_exec",
                size=size if isinstance(size, int) else None,
                digest=str(digest) if digest else None,
                metadata={
                    "origin": record.get("origin"),
                    "relative_path": record.get("relative_path"),
                    "file_type": file_type or None,
                    "mime_type": mime_type or None,
                },
            )
        )
    return artifacts


def _script_artifact_kind(*, file_type: str = "", mime_type: str = "") -> str:
    text = " ".join([file_type.lower(), mime_type.lower()])
    if "image/png" in text or "png image" in text:
        return "script_artifact_png"
    if "image/jpeg" in text or "jpeg image" in text:
        return "script_artifact_jpeg"
    if "image/gif" in text or "gif image" in text:
        return "script_artifact_gif"
    if "zip" in text or "archive" in text:
        return "script_artifact_archive"
    if "sqlite" in text or "database" in text:
        return "script_artifact_database"
    if "text/" in text or "ascii text" in text or "unicode text" in text:
        return "script_artifact_text"
    return "script_artifact"
