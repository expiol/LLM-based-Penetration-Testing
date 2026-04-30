"""Schema-friendly value coercion shared by LLM-output Pydantic models.

Models occasionally emit qualitative labels (``"high"``, ``"low"``, ...) where
schemas declare numeric fields.  These helpers translate the labels so that a
minor stylistic deviation does not abort an entire run.
"""

from __future__ import annotations

from typing import Any

_CONFIDENCE_WORD_TO_FLOAT: dict[str, float] = {
    "lowest": 0.05, "very_low": 0.1, "very low": 0.1,
    "low": 0.25, "minor": 0.25,
    "medium": 0.5, "med": 0.5, "moderate": 0.5, "normal": 0.5, "default": 0.5,
    "high": 0.75, "important": 0.75,
    "very_high": 0.85, "very high": 0.85, "urgent": 0.9,
    "critical": 0.95, "highest": 1.0,
}


def coerce_confidence(value: Any) -> Any:
    """Translate qualitative confidence labels into ``float`` in [0, 1].

    Numeric input (``int``/``float``) and well-formed strings (e.g. ``"0.8"``)
    pass through unchanged; only the qualitative labels documented above are
    rewritten.  Unknown strings are returned as-is so Pydantic still raises a
    clear validation error.
    """
    if isinstance(value, str):
        mapped = _CONFIDENCE_WORD_TO_FLOAT.get(value.strip().lower())
        if mapped is not None:
            return mapped
        try:
            return float(value.strip())
        except ValueError:
            return value
    return value
