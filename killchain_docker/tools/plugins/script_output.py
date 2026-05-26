"""Output interpretation for script.exec."""

from __future__ import annotations

import re

from killchain_docker.state.constants import bare_token_shape
from killchain_docker.tools.core import _truncate
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _infrastructure_failure_signal,
)
from killchain_docker.tools.plugins.generated_artifacts import (
    ARTIFACTS_END,
    ARTIFACTS_START,
)


GRAPHIC_CHARS = set("#$%&*+-/:;<=>?@[\\]^_`{|}~")
MIN_READABLE_NEAR_MISS_LEN = 240

PLAINTEXT_LABEL_RE = re.compile(
    r"^\s*(?:\[[^\]\n]{1,24}\]\s*|[>*+-]\s*)*(?:best\s+result|plaintext|plain\s+text|decrypted|decoded|preview|first\s+\d+\s+(?:bytes|chars)|output)\b\s*:?",
    re.IGNORECASE,
)
STATUS_PREFIX_RE = re.compile(r"^\s*(?:\[[^\]]{1,16}\]\s*|[-+*!]\s*)+")
DIAGNOSTIC_LINE_RE = re.compile(
    r"^(?:\d+\.\s+|=+\s*(?:top|best|testing)|analyzing|attempting|checking|connecting|connected|connection\s+closed|banner|context\s+around|ciphertexts?\s+found|decoded\s+preview|hex\s+dump|disassembl|dynamic\s+symbols|extract(?:ed|ing)?|file\s+not\s+found|file\s+size|file\s+type|found|header|initial\s+response|magic|interesting\s+strings|line\s+\d+|looking\s+for|no\s+flag|flag\s+pattern|received|reading|running|saved|scanner|search(?:ed|ing)?|sent|source|string\s+dump|symbol\s+table|target|total|warning|welcome|wrote|writing|ct\s+size|raw\s+tap|seed|skip|tap|ciphertext|printable|ratio|score|braces|flags|first\s+bytes|case\s+\d+|trying|testing|using|skipping|candidate|actual|error|stdout|stderr|returncode|length|num\s*:)\b",
    re.IGNORECASE,
)
HEXDUMP_LINE_RE = re.compile(
    r"^\s*(?:0x)?[0-9a-fA-F]{1,10}\s*[:|]\s*(?:[0-9a-fA-F]{2}(?:\s+|$)){6,}(?:\s{2,}.*)?$"
)
ASSEMBLY_LINE_RE = re.compile(
    r"^\s*(?:0x)?[0-9a-fA-F]{4,16}:\s+(?:[0-9a-fA-F]{2}\s+){1,12}(?:[A-Za-z_.][\w.$@<>+-]*)?"
)
SYMBOL_TABLE_ENTRY_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]{6,}\s+\d+\s+(?:FUNC|OBJECT|NOTYPE|SECTION|FILE|TLS)\b"
)
BYTES_REPR_LINE_RE = re.compile(r"^\s*b[\"'].{40,}[\"']\s*$")
PATH_LISTING_LINE_RE = re.compile(r"^\s*(?:\.{0,2}/)?(?:[\w.+@-]+/){1,}\S+\s*$")
INDEXED_HEX_VALUE_RE = re.compile(r"^\s*\w+\[\d+\]:\s*[0-9a-fA-F]{24,}\b")
LONG_HEX_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]{64,}\s*$")
PROTOCOL_DUMP_TOKEN_RE = re.compile(
    r"\b(?:banner|command|connect(?:ion|ed)?|error|listen|login|pass(?:word)?|port|request|response|retr|socket|stor|tcp|transfer|udp|user)\b",
    re.IGNORECASE,
)
DIAGNOSTIC_REPORT_RE = re.compile(
    r"(?im)^\s*(?:\[[^\]]+\]\s*)?(?:=+\s*top\s+|=+\s*local\s+self-test|=+\s*differential\s+test|score\s*=|\d+\.\s+seed=|testing\s+\d+.+candidates|braces\s*=|first\s+bytes:|all\s+tests\s+passed|solver\s+function|sum\s+verification|=+\s*png\s+chunk\s+analysis|=+\s*string\s+search\s+in\s+decrypted\s+png|chunk\s+'(?:ihdr|idat|iend|itxt|text|ztxt)'|found\s+\d+\s+printable\s+strings|offset\s+\d+\s*:)"
)
SELF_TEST_CANDIDATE_CONTEXT_RE = re.compile(
    r"\b(?:self[- ]?test|round[- ]?trip|unit\s+test|test\s+vector|"
    r"known\s+plaintext|fixture|all\s+tests\s+passed|test\s+(?:passed|failed)|"
    r"expected\s*:|got\s*:)\b",
    re.IGNORECASE,
)
SELF_TEST_RESULT_LINE_RE = re.compile(
    r"\b(?:encrypt(?:ion|ed)?|decrypt(?:ion|ed)?|result|plaintext|ciphertext|"
    r"round[- ]?trip|verify|verification|expected|got|pass(?:ed)?|fail(?:ed)?)\b",
    re.IGNORECASE,
)


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:12000]
    printable = sum(1 for ch in sample if ch in "\n\r\t" or 32 <= ord(ch) <= 126)
    return printable / len(sample)


def graphic_density(line: str) -> float:
    visible = [ch for ch in line if not ch.isspace()]
    if not visible:
        return 0.0
    graphic = sum(1 for ch in visible if ch in GRAPHIC_CHARS)
    return graphic / len(visible)


def collapse_visual_runs(line: str) -> str:
    return re.sub(r"([^\s])\1{2,}", r"\1", line.strip())


def escaped_repr_density(text: str) -> float:
    if not text:
        return 0.0
    escaped = re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0abfnrtv]", text)
    return len(escaped) / len(text)


def diagnostic_line_ratio(lines: list[str]) -> float:
    non_empty = [line.strip() for line in lines if line.strip()]
    if not non_empty:
        return 1.0
    diagnostic = sum(1 for line in non_empty if is_diagnostic_line(line))
    return diagnostic / len(non_empty)


def is_diagnostic_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped in {ARTIFACTS_START, ARTIFACTS_END}:
        return True
    normalized = STATUS_PREFIX_RE.sub("", stripped).strip().strip("=- ")
    if not normalized:
        return True
    protocol_dump_tokens = PROTOCOL_DUMP_TOKEN_RE.findall(normalized)
    return bool(
        DIAGNOSTIC_LINE_RE.match(normalized)
        or HEXDUMP_LINE_RE.match(stripped)
        or HEXDUMP_LINE_RE.match(normalized)
        or ASSEMBLY_LINE_RE.match(stripped)
        or ASSEMBLY_LINE_RE.match(normalized)
        or SYMBOL_TABLE_ENTRY_RE.match(stripped)
        or SYMBOL_TABLE_ENTRY_RE.match(normalized)
        or BYTES_REPR_LINE_RE.match(stripped)
        or PATH_LISTING_LINE_RE.match(stripped)
        or INDEXED_HEX_VALUE_RE.match(stripped)
        or LONG_HEX_LINE_RE.match(stripped)
        or (len(protocol_dump_tokens) >= 2)
    )


def strip_script_artifact_manifest(stdout: str) -> str:
    lines = stdout.replace("\r", "\n").splitlines()
    kept: list[str] = []
    in_manifest = False
    for line in lines:
        stripped = line.strip()
        if stripped == ARTIFACTS_START:
            in_manifest = True
            continue
        if in_manifest:
            if stripped == ARTIFACTS_END:
                in_manifest = False
            continue
        kept.append(line)
    return "\n".join(kept)


def looks_like_visual_art_block(lines: list[str]) -> bool:
    non_empty = [line for line in lines if line.strip()]
    if len(non_empty) < 3:
        return False
    if any(is_diagnostic_line(line) for line in non_empty):
        return False
    graphic_lines = [
        line for line in non_empty if len(line) >= 20 and graphic_density(line) >= 0.25
    ]
    banner_text_lines = [
        line for line in non_empty if looks_like_visual_banner_text_line(line)
    ]
    visual_lines = len(graphic_lines) + len(banner_text_lines)
    return visual_lines >= 3 and visual_lines / len(non_empty) >= 0.5


def looks_like_visual_banner_text_line(line: str) -> bool:
    if len(line) < 60:
        return False
    letters = [ch for ch in line if ch.isalpha()]
    if len(letters) < 20:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    whitespace = sum(1 for ch in line if ch.isspace())
    return uppercase / len(letters) >= 0.8 and whitespace / len(line) >= 0.18


def plaintext_blocks(stdout: str) -> list[str]:
    lines = stdout.replace("\r", "\n").splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = PLAINTEXT_LABEL_RE.match(line)
        if not match:
            continue
        inline = line[match.end() :].strip(" :")
        if inline:
            blocks.append(inline)
        following: list[str] = []
        for next_line in lines[index + 1 : index + 12]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if stripped.startswith("=" * 8) or stripped.startswith("-" * 8):
                if following:
                    break
                continue
            if PLAINTEXT_LABEL_RE.match(next_line) or is_diagnostic_line(stripped):
                if following:
                    break
                continue
            following.append(next_line.rstrip())
        if following:
            blocks.append("\n".join(following))
    if blocks:
        return blocks
    if DIAGNOSTIC_REPORT_RE.search(stdout):
        return []
    if diagnostic_line_ratio(lines) >= 0.45:
        return []
    return []


def readable_near_misses(stdout: str) -> list[str]:
    stdout = strip_script_artifact_manifest(stdout)
    if len(stdout) < MIN_READABLE_NEAR_MISS_LEN:
        return []
    labelled_blocks = plaintext_blocks(stdout)
    blocks = [(block, False) for block in labelled_blocks]
    if not blocks:
        stdout_lines = [
            line.rstrip() for line in stdout.replace("\r", "\n").splitlines()
        ]
        if looks_like_visual_art_block(stdout_lines):
            blocks = [(stdout, True)]
    for block, require_visual in blocks:
        if DIAGNOSTIC_REPORT_RE.search(block):
            continue
        if len(block) < MIN_READABLE_NEAR_MISS_LEN:
            continue
        if printable_ratio(block) < 0.92:
            continue
        if escaped_repr_density(block) > 0.03:
            continue
        lines = [line.rstrip() for line in block.replace("\r", "\n").splitlines()]
        non_empty = [line for line in lines if line.strip()]
        if diagnostic_line_ratio(non_empty) >= 0.45:
            continue
        graphic_lines = [
            line
            for line in non_empty
            if len(line) >= 20 and graphic_density(line) >= 0.25
        ]
        banner_text_lines = [
            line for line in non_empty if looks_like_visual_banner_text_line(line)
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
            compact = collapse_visual_runs(line)
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


def script_failure_signal(output_text: str, exit_code: int | None) -> tuple[str, str]:
    infrastructure = _infrastructure_failure_signal(output_text, "", exit_code)
    if infrastructure is not None:
        return infrastructure
    text = output_text.lower()
    if "brokenpipeerror" in text or "broken pipe" in text:
        return (
            "network_pipe_closed",
            "remote endpoint closed the socket while the script was writing",
        )
    if "connectionreseterror" in text or "connection reset by peer" in text:
        return ("connection_reset", "remote endpoint reset the connection")
    if "connectionrefusederror" in text or "connection refused" in text:
        return ("connection_refused", "remote endpoint refused the connection")
    if (
        "socket.gaierror" in text
        or "name or service not known" in text
        or "nodename nor servname provided" in text
        or ("temporary failure in name resolution" in text)
    ):
        return (
            "host_resolution_error",
            "script could not resolve the target hostname; parse URLs into scheme, hostname, port, and path before connecting",
        )
    if "scope_violation_blocked" in text or "outside authorized_scope" in text:
        return (
            "scope_violation_blocked",
            "script attempted to leave authorized_scope or files_root",
        )
    if (
        "no space left on device" in text
        or "mktemp: failed to create directory" in text
        or "workspace budget exceeded" in text
    ):
        return (
            "scratch_space_exhausted",
            "script scratch workspace could not be created or filled the container overlay",
        )
    if (
        "modulenotfounderror:" in text
        or "importerror:" in text
        or "no module named" in text
    ):
        return (
            "missing_tool",
            "script imported a Python module unavailable in the execution environment; use stdlib or guard optional imports",
        )
    if (
        "range too large for script.exec" in text
        or "product too large for script.exec" in text
    ):
        return (
            "unbounded_loop_guard",
            "script attempted an oversized range/search; use fast-forward math or bounded sampling",
        )
    if "script.exec python time limit exceeded" in text:
        return (
            "unbounded_loop_guard",
            "script exceeded Python runtime guard; use bounded loops or fast-forward math",
        )
    hard_timeout = "[timeout after" in text
    runtime_timeout = (
        "timed out" in text
        or "timeouterror" in text
        or "socket timeout" in text
        or ("timeout during" in text)
    )
    if hard_timeout or (runtime_timeout and exit_code not in (None, 0)):
        return ("timeout", "script exceeded its execution or socket timeout")
    if (
        "failed to parse" in text
        or "cannot parse" in text
        or "could not parse" in text
        or ("parse error" in text)
        or ("re.error:" in text)
        or ("invalid literal for int" in text)
        or ("binascii.error: odd-length string" in text)
        or ("binascii.error: non-hexadecimal digit found" in text)
        or ("fromhex()" in text and "non-hexadecimal" in text)
    ):
        return (
            "parse_error",
            "script parsing logic rejected tool or service output; validate delimiters, regex quoting, and exact field shape",
        )
    if "filenotfounderror" in text or "no such file or directory" in text:
        return (
            "path_resolution_error",
            "script referenced a path that was not present in the execution workspace",
        )
    if (
        "struct.error" in text
        and "buffer" in text
        or "unpack requires a buffer" in text
        or "unpack_from requires a buffer" in text
        or ("not enough values to unpack" in text)
        or ("unexpected end of data" in text)
        or ("truncated file" in text)
    ):
        return (
            "binary_structure_error",
            "script parsed binary structures without sufficient bounds checks",
        )
    if (
        "a bytes-like object is required" in text
        or "can't concat str to bytes" in text
        or "can't concat bytes to str" in text
        or ("must be str, not bytes" in text)
        or ("must be bytes, not str" in text)
        or ("byte indices must be integers or slices" in text)
        or ("ord() expected string of length 1, but int found" in text)
        or ("unicodedecodeerror" in text)
        or ("unicodeencodeerror" in text)
    ):
        return (
            "bytes_text_mismatch",
            "script mixed bytes and text across an IO boundary",
        )
    if (
        "unsupported operand type(s) for /: 'str' and 'str'" in text
        or 'unsupported operand type(s) for /: "str" and "str"' in text
        or "'str' object has no attribute 'glob'" in text
        or ("'str' object has no attribute 'iterdir'" in text)
    ):
        return (
            "path_type_mismatch",
            "script mixed string paths with pathlib operations",
        )
    if (
        "nameerror:" in text
        and "is not defined" in text
        or ("unboundlocalerror:" in text and "referenced before assignment" in text)
    ):
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
        return ("syntax_error", "script failed Python or shell syntax validation")
    if network_incomplete_read_signal(text):
        return (
            "network_incomplete_read",
            "remote endpoint closed or stopped sending before the script received expected data",
        )
    subcommand_error = subcommand_error_line(output_text)
    if subcommand_error:
        return (
            "subcommand_error",
            f"script completed but an invoked command reported an error: {subcommand_error}",
        )
    diagnostic = script_reported_error_line(output_text)
    if diagnostic:
        return ("nonzero_exit", f"script exited with status {exit_code}: {diagnostic}")
    return ("nonzero_exit", f"script exited with status {exit_code}")


def network_incomplete_read_signal(text: str) -> bool:
    if not text:
        return False
    missing_expected_data = bool(
        re.search(
            r"\b(?:no|missing|failed\s+to\s+receive|unable\s+to\s+receive|did\s+not\s+receive|could\s+not\s+read|unexpected\s+eof|eof)\b.{0,80}\b(?:data|response|banner|header|line|prompt|message|round|payload|final|bytes?)\b",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    )
    if not missing_expected_data:
        missing_expected_data = bool(
            re.search(
                r"\b(?:connection|socket|server|remote|endpoint)\b.{0,80}\b(?:closed|disconnected|dropped)\b.{0,80}\b(?:before|while|during|expected|missing|no\s+data)\b",
                text,
                re.IGNORECASE | re.DOTALL,
            )
        )
    if not missing_expected_data:
        return False
    return bool(
        re.search(
            r"\b(?:connect(?:ed|ing|ion)?|socket|tcp|server|remote|endpoint|send(?:ing)?|sent|recv|receive(?:d|ing)?|read(?:ing)?|response|banner|header|prompt|round)\b",
            text,
            re.IGNORECASE,
        )
    )


def script_reported_error_line(output_text: str) -> str:
    for line in reversed((output_text or "").splitlines()):
        text = line.strip()
        if not text:
            continue
        if re.match(r"(?i)^(?:error|failed|failure|fatal|warning)\b\s*:?", text):
            return _truncate(text, 300)
        if re.search(r"(?i)\b(?:error|failed|failure|fatal)\b", text):
            return _truncate(text, 300)
    return ""


def subcommand_error_line(output_text: str) -> str:
    for line in reversed((output_text or "").splitlines()):
        text = line.strip()
        if not text:
            continue
        return_code = re.search(r"(?i)\breturn\s+code\s*:\s*(-?\d+)\b", text)
        if return_code and return_code.group(1) not in {"0", "+0"}:
            return _truncate(text, 300)
        if re.search(r"(?i)\b(?:error|failed|failure|fatal)\b", text) and re.search(
            r"(?i)(?:\bmake\b|\bgcc\b|\bclang\b|\bld\b|\btar\b|\bunzip\b|\bzip\b|\bjava\b|\bnode\b|\bruby\b|\bgo\b|\bcargo\b|\bcmake\b|\bninja\b|\bperl\b|\bbash\b|\bsh\b|\bpython\b|\bpython3\b|\*\*\*)",
            text,
        ):
            return _truncate(text, 300)
    return ""


def traceback_excerpt(output_text: str, *, width: int = 4000) -> str:
    marker = "Traceback (most recent call last):"
    index = output_text.find(marker)
    if index < 0:
        return ""
    return _truncate(output_text[index:].strip(), width)


def flag_candidates_from_script_stdout(stdout: str, *, source: str):
    candidates = _flag_candidates_from(stdout, source=source)
    if not candidates:
        return []
    has_visual_text = bool(readable_near_misses(stdout))
    filtered = [
        candidate
        for candidate in candidates
        if candidate_has_readable_context(
            stdout,
            candidate.value,
            allow_derived_visual=has_visual_text,
        )
    ]
    if has_visual_text:
        filtered.sort(
            key=lambda candidate: script_candidate_rank(candidate.value, stdout)
        )
    return filtered


def script_candidate_rank(candidate: str, stdout: str) -> tuple[int, int]:
    if "{" in candidate and candidate in stdout:
        return (0, 0)
    if candidate not in stdout and looks_like_visual_text_candidate(candidate):
        return (1, 0)
    return (2, 0)


def candidate_has_readable_context(
    stdout: str,
    candidate: str,
    *,
    allow_derived_visual: bool = False,
) -> bool:
    if allow_derived_visual and looks_like_visual_text_candidate(candidate):
        return True
    if "{" in candidate and candidate not in stdout:
        if candidate_body_has_readable_context(stdout, candidate):
            return True
    labels = (
        "flag found",
        "candidate flag",
        "possible flag",
        "valid flag",
        "recovered flag",
        "validated flag",
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
        surrounding = surrounding_line_context(stdout, line_start, line_end)
        if candidate_is_in_self_test_context(window, surrounding, candidate):
            start = index + len(candidate)
            continue
        if "�" not in window and printable_ratio(window) >= 0.9:
            return True
        start = index + len(candidate)


def surrounding_line_context(
    text: str,
    line_start: int,
    line_end: int,
    *,
    before: int = 2,
    after: int = 2,
) -> str:
    start = line_start
    for _ in range(before):
        previous = text.rfind("\n", 0, max(0, start - 1))
        if previous < 0:
            start = 0
            break
        start = previous + 1
    end = line_end
    for _ in range(after):
        next_newline = text.find("\n", end + 1)
        if next_newline < 0:
            end = len(text)
            break
        end = next_newline
    return text[start:end]


def candidate_is_in_self_test_context(
    line_context: str, surrounding_context: str, candidate: str
) -> bool:
    if SELF_TEST_CANDIDATE_CONTEXT_RE.search(line_context or ""):
        return True
    if not (
        SELF_TEST_RESULT_LINE_RE.search(line_context or "")
        and SELF_TEST_CANDIDATE_CONTEXT_RE.search(surrounding_context or "")
    ):
        return False
    for line in (surrounding_context or "").splitlines():
        if candidate in line and SELF_TEST_CANDIDATE_CONTEXT_RE.search(line):
            return True
    return False


def candidate_body_has_readable_context(stdout: str, candidate: str) -> bool:
    prefix, _sep, body_with_brace = candidate.partition("{")
    body = body_with_brace[:-1] if body_with_brace.endswith("}") else ""
    if not prefix or not body:
        return False
    labels = ("answer", "flag", "key", "plaintext", "recovered", "secret", "validated")
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


def looks_like_visual_text_candidate(candidate: str) -> bool:
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
    return uppercase / len(letters) >= 0.7


def success_output_failure_kind_is_primary(
    failure_kind: str,
    output_text: str,
    *,
    stdout: str,
) -> bool:
    """Return true when a zero-exit script's diagnostic is the main outcome."""
    if failure_kind == "nonzero_exit":
        return False
    if failure_kind != "path_resolution_error":
        return True
    text = output_text.strip()
    if not text:
        return True
    if "traceback (most recent call last)" in text.lower():
        return True
    lines = [
        line.strip() for line in stdout.replace("\r", "\n").splitlines() if line.strip()
    ]
    if not lines:
        return True
    path_error_lines = [
        line
        for line in lines
        if re.search(r"(?i)(filenotfounderror|no such file or directory)", line)
    ]
    progress_lines = [
        line
        for line in lines
        if line not in path_error_lines and is_diagnostic_line(line)
    ]
    return not progress_lines
