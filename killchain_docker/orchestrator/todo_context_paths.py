"""Todo context path helpers."""

from __future__ import annotations

from typing import Any


def context_path(context: dict[str, Any]) -> str:
    for key in ("artifact_path", "path", "file_path"):
        value = context.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    paths = context.get("paths")
    if isinstance(paths, list) and paths:
        first = paths[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    return ""


__all__ = ["context_path"]
