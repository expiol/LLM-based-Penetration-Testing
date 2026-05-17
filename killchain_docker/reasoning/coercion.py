"""Schema-friendly value coercion shared by LLM-output Pydantic models.

Models occasionally emit qualitative labels or non-standard values where
schemas declare typed fields.  These helpers translate them so that a
minor stylistic deviation does not abort an entire run.
"""

from __future__ import annotations

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
