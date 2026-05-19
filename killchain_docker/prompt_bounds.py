"""Shared prompt-size guards for LLM-facing state snapshots."""

from __future__ import annotations

from typing import Any


def trim_text(value: object, *, width: int) -> str:
    text = str(value or "")
    if len(text) <= width:
        return text
    return text[:width].rstrip() + f"... [truncated {len(text) - width} chars]"


def bounded_value(
    value: Any,
    *,
    width: int = 500,
    list_limit: int = 8,
    dict_limit: int = 12,
    depth: int = 0,
    max_depth: int = 2,
) -> Any:
    """Return a JSON-safe value with bounded text, lists, dicts, and nesting."""

    if value in (None, "", [], {}):
        return value
    if isinstance(value, str):
        return trim_text(value, width=width)
    if isinstance(value, (int, float, bool)):
        return value
    if depth >= max_depth:
        return trim_text(value, width=width)
    if isinstance(value, list):
        return [
            bounded_value(
                item,
                width=width,
                list_limit=list_limit,
                dict_limit=dict_limit,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item in value[:list_limit]
        ]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= dict_limit:
                break
            out[str(key)] = bounded_value(
                item,
                width=width,
                list_limit=list_limit,
                dict_limit=dict_limit,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return out
    return trim_text(value, width=width)
