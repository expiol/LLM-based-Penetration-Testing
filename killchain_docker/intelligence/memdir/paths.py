"""Memory directory layout helpers."""

from __future__ import annotations

import re
from pathlib import Path


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str, *, fallback: str = "memory") -> str:
    cleaned = _SLUG_RE.sub("-", str(text).lower()).strip("-")
    return cleaned[:80] or fallback


def web_cache_dir(memory_root: Path) -> Path:
    """Return the directory where opt-in web retrieval caches are stored."""

    return Path(memory_root) / "cache" / "web"
