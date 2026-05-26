"""Shared state-model primitives."""

from __future__ import annotations

import ast
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def make_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def parse_text_sequence(text: str) -> Any | None:
    if not text:
        return None
    if text[0] not in "[(" or text[-1] not in "])":
        return None
    try:
        parsed = ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return None
    if isinstance(parsed, (list, tuple, set)):
        return parsed
    return None


def coerce_text_items(values: Any) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in (None, "", [], {}, ()):
            continue
        if isinstance(value, (list, tuple, set)):
            nested = coerce_text_items(value)
        else:
            text = str(value).strip()
            parsed = parse_text_sequence(text)
            nested = (
                coerce_text_items(parsed)
                if parsed is not None
                else ([text] if text else [])
            )
        for item in nested:
            if item not in seen:
                items.append(item)
                seen.add(item)
    return items
