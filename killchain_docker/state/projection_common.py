"""Shared projection constants and compact text helpers."""

from __future__ import annotations

COMPACT_TEXT_LIMIT = 360
COMPACT_GOAL_LIMIT = 260
COMPACT_TIMELINE_LIMIT = 80


def compact_text(value: object, *, limit: int = COMPACT_TEXT_LIMIT) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"
