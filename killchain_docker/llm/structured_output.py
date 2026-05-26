"""Lenient structured-output helpers for LLM responses.

The gateway owns transport, retries, and failure classification.  This module
owns the messy but deterministic work of recovering JSON objects from model
text and exception payloads.
"""

from __future__ import annotations

import ast
import json
from typing import Any


def extract_json_object_text(text: str) -> str:
    """Return the first balanced JSON object from model output text."""

    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].lstrip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    start = stripped.find("{")
    if start < 0:
        return stripped

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        char = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : index + 1]
    return stripped[start:]


def escape_control_chars_in_json_strings(text: str) -> str:
    """Escape bare control characters only while inside JSON strings."""

    out: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                out.append(char)
                escaped = False
            elif char == "\\":
                out.append(char)
                escaped = True
            elif char == '"':
                out.append(char)
                in_string = False
            elif ord(char) < 0x20:
                if char == "\n":
                    out.append("\\n")
                elif char == "\r":
                    out.append("\\r")
                elif char == "\t":
                    out.append("\\t")
                else:
                    out.append(f"\\u{ord(char):04x}")
            else:
                out.append(char)
            continue

        out.append(char)
        if char == '"':
            in_string = True
            escaped = False
    return "".join(out)


def escape_source_backslashes_in_json_strings(text: str) -> str:
    r"""Preserve source-code backslashes that models often emit inside JSON strings.

    JSON accepts only a small escape alphabet.  LLM-generated script bodies often
    contain Python/regex escapes such as ``\w`` or ``\b`` without JSON-escaping
    the backslash first.  This pass repairs those source-code escapes before
    JSON decoding, while leaving structural JSON escapes for quotes, newlines,
    and unicode intact.
    """

    out: list[str] = []
    in_string = False
    escaped = False
    index = 0
    valid_json_escapes = {'"', "\\", "/", "n", "r", "t", "u"}
    source_code_escapes = {"b", "f"}

    while index < len(text):
        char = text[index]
        if in_string:
            if escaped:
                if char in valid_json_escapes:
                    out.append(char)
                elif char in source_code_escapes:
                    out.append("\\")
                    out.append(char)
                else:
                    out.append("\\")
                    out.append(char)
                escaped = False
                index += 1
                continue
            if char == "\\":
                out.append(char)
                escaped = True
                index += 1
                continue
            if char == '"':
                in_string = False
            out.append(char)
            index += 1
            continue

        out.append(char)
        if char == '"':
            in_string = True
            escaped = False
        index += 1
    if escaped:
        out.append("\\")
    return "".join(out)


def close_array_before_object_field(text: str) -> str:
    """Close an array when a model starts the next object field too early."""

    out: list[str] = []
    stack: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char in "{[":
            stack.append(char)
            out.append(char)
            index += 1
            continue
        if char in "}]":
            if stack:
                stack.pop()
            out.append(char)
            index += 1
            continue
        if (
            char == ","
            and stack
            and stack[-1] == "["
            and _object_field_follows(text, index + 1)
        ):
            stack.pop()
            out.append("],")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _object_field_follows(text: str, index: int) -> bool:
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != '"':
        return False

    escaped = False
    index += 1
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            index += 1
            break
        index += 1

    while index < len(text) and text[index].isspace():
        index += 1
    return index < len(text) and text[index] == ":"


def escape_unescaped_inner_quotes_in_json_strings(text: str) -> str:
    """Escape quote characters that are clearly part of a JSON string value.

    Models sometimes emit prose or source code containing quotes inside a JSON
    string without escaping them.  A quote can end a JSON string only when the
    following non-space character is a structural delimiter.  When a quote is
    followed by ordinary text, keep the surrounding JSON string open and escape
    that quote instead.
    """

    out: list[str] = []
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                out.append(char)
                escaped = False
                continue
            if char == "\\":
                out.append(char)
                escaped = True
                continue
            if char == '"':
                if _quote_can_end_json_string(text, index):
                    out.append(char)
                    in_string = False
                else:
                    out.append('\\"')
                continue
            out.append(char)
            continue

        out.append(char)
        if char == '"':
            in_string = True
            escaped = False
    return "".join(out)


def normalize_bare_hex_integer_values(text: str) -> str:
    """Convert unquoted hexadecimal integer values into JSON decimal integers."""

    out: list[str] = []
    stack: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char in "{[":
            stack.append(char)
            out.append(char)
            index += 1
            continue
        if char in "}]":
            if stack:
                stack.pop()
            out.append(char)
            index += 1
            continue

        replacement = _bare_hex_integer_replacement(text, index, stack)
        if replacement is not None:
            decimal_text, next_index = replacement
            out.append(decimal_text)
            index = next_index
            continue

        out.append(char)
        index += 1
    return "".join(out)


def _bare_hex_integer_replacement(
    text: str,
    index: int,
    stack: list[str],
) -> tuple[str, int] | None:
    if not _is_value_position_for_bare_token(text, index, stack):
        return None
    sign = ""
    cursor = index
    if text[cursor] in "+-":
        sign = text[cursor]
        cursor += 1
    if cursor + 2 > len(text) or text[cursor : cursor + 2].lower() != "0x":
        return None
    digit_start = cursor + 2
    cursor = digit_start
    while cursor < len(text) and text[cursor] in "0123456789abcdefABCDEF":
        cursor += 1
    if cursor == digit_start:
        return None
    if cursor < len(text) and (text[cursor].isalnum() or text[cursor] in "._"):
        return None
    try:
        value = int(f"{sign}{text[digit_start:cursor]}", 16)
    except ValueError:
        return None
    return str(value), cursor


def _is_value_position_for_bare_token(text: str, index: int, stack: list[str]) -> bool:
    if text[index] not in "+-0":
        return False
    cursor = index - 1
    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    if cursor < 0:
        return False
    previous = text[cursor]
    if previous == ":":
        return True
    if previous == "[":
        return True
    return previous == "," and bool(stack) and stack[-1] == "["


def _quote_can_end_json_string(text: str, quote_index: int) -> bool:
    index = quote_index + 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return True
    char = text[index]
    if char in ":}]":
        return True
    if char != ",":
        return False

    index += 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return True
    return text[index] in '"{[-0123456789tfn'


def strip_stray_backslashes_outside_strings(text: str) -> str:
    """Drop lone backslashes that appear in structural (not string) positions.

    Models occasionally emit a stray ``\\`` between two object fields when
    line-continuing source code escaped into a JSON value, e.g.
    ``"...code...",\\    "next_field": ...``.  These backslashes have no valid
    JSON interpretation outside a string and would otherwise leave the parser
    looking for a key where there is none.
    """

    out: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == "\\":
            continue
        out.append(char)
        if char == '"':
            in_string = True
            escaped = False
    return "".join(out)


def loads_lenient_json_object(text: str) -> Any:
    """Load model JSON, repairing common deterministic JSON syntax drift."""

    candidate = extract_json_object_text(text)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        repaired = candidate
        repaired = strip_stray_backslashes_outside_strings(repaired)
        repaired = normalize_bare_hex_integer_values(repaired)
        repaired = escape_source_backslashes_in_json_strings(repaired)
        repaired = escape_unescaped_inner_quotes_in_json_strings(repaired)
        repaired = close_array_before_object_field(repaired)
        repaired = escape_control_chars_in_json_strings(repaired)
        return json.loads(repaired)


def completion_content(completion: Any) -> str | None:
    if completion is None:
        return None
    if isinstance(completion, str):
        return completion
    if isinstance(completion, dict):
        choices = completion.get("choices")
        if isinstance(choices, list) and choices:
            message = (
                (choices[0] or {}).get("message")
                if isinstance(choices[0], dict)
                else None
            )
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
        content = completion.get("content")
        return content if isinstance(content, str) else None

    choices = getattr(completion, "choices", None)
    if choices:
        first = choices[0]
        message = getattr(first, "message", None)
        content = getattr(message, "content", None)
        if isinstance(content, str):
            return content
    content = getattr(completion, "content", None)
    return content if isinstance(content, str) else None


def python_string_literal_after(text: str, marker: str) -> str | None:
    search_from = 0
    while True:
        marker_index = text.find(marker, search_from)
        if marker_index < 0:
            return None
        start = marker_index + len(marker)
        while start < len(text) and text[start].isspace():
            start += 1
        if start >= len(text) or text[start] not in {"'", '"'}:
            search_from = start
            continue

        quote = text[start]
        escaped = False
        for end in range(start + 1, len(text)):
            char = text[end]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                try:
                    value = ast.literal_eval(text[start : end + 1])
                except (SyntaxError, ValueError):
                    break
                return value if isinstance(value, str) else None
        search_from = start + 1
