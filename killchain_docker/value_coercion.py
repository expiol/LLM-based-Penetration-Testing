"""Dependency-light coercion helpers for schema-facing JSON values."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def coerce_llm_bool(value: Any) -> Any:
    """Normalize LLM quirks (e.g. ``[]`` for false) ahead of ``bool`` fields.

    Containers use truthiness; unknown values pass through unchanged.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return bool(value)
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1", "on"):
            return True
        if lowered in ("false", "no", "0", "off", ""):
            return False
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 0:
            return False
        if value == 1:
            return True
        return bool(value)
    return value


def coerce_string_mapping(value: Any) -> Any:
    """Normalize JSON-like fact maps to ``dict[str, str]``.

    LLM structured outputs often carry grounded facts as JSON scalars or small
    nested values even when downstream state stores prompt-facing text.  Keep
    the contract narrow at the durable boundary without making schema recovery
    depend on particular field names or fact names.
    """

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        return value
    return {str(key): _stringify_json_value(item) for key, item in value.items()}


def _stringify_json_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


COMPACT_TEXT_LIMIT = 360
COMPACT_GOAL_LIMIT = 260
COMPACT_TIMELINE_LIMIT = 80


def compact_text(value: object, *, limit: int = COMPACT_TEXT_LIMIT) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"
