"""Generic string and list normalization helpers used by workers."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse


def merge_unique_strings(
    *groups: Iterable[str] | None,
    limit: int | None = None,
) -> list[str]:
    """Merge string groups while preserving order and removing empties."""

    merged: list[str] = []
    for group in groups:
        if not group:
            continue
        for item in group:
            text = str(item).strip()
            if not text or text in merged:
                continue
            merged.append(text)
            if limit is not None and len(merged) >= limit:
                return merged
    return merged


def normalize_probe_paths(
    paths: Iterable[str] | None,
    *,
    limit: int = 12,
) -> list[str]:
    """Normalize worker-discovered paths into forms suitable for web.path_probe tasks."""

    normalized: list[str] = []
    for raw_path in paths or ():
        text = str(raw_path).strip()
        if not text:
            continue

        if text.startswith(("http://", "https://")):
            parsed = urlparse(text)
            text = parsed.path or "/"
            if parsed.query:
                text = f"{text}?{parsed.query}"
        else:
            if any(character.isspace() for character in text):
                continue
            if not text.startswith("/"):
                if "/" in text or any(
                    token in text.lower()
                    for token in ("admin", "api", "debug", "flag", "login", "upload", "cgi-bin")
                ):
                    text = f"/{text.lstrip('/')}"
                else:
                    continue

        if any(character.isspace() for character in text):
            continue

        if text not in normalized:
            normalized.append(text)
        if len(normalized) >= limit:
            break
    return normalized
