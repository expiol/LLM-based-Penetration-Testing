"""RAG mode and environment configuration."""

from __future__ import annotations

import os


RAG_MODE_ENV = "AUTOPENTEST_RAG_MODE"
RAG_MODE_ORACLE = "oracle"
RAG_MODE_STRICT = "strict"
RAG_MODE_DISABLED = "disabled"
RAG_MODES = frozenset({RAG_MODE_ORACLE, RAG_MODE_STRICT, RAG_MODE_DISABLED})


def env_flag(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def rag_mode(override: str | None = None) -> str:
    """Return the active RAG policy mode."""

    raw = (
        (override if override is not None else os.getenv(RAG_MODE_ENV) or "")
        .strip()
        .lower()
    )
    if raw in RAG_MODES:
        return raw
    if raw:
        choices = ", ".join(sorted(RAG_MODES))
        raise ValueError(f"unknown RAG mode {raw!r}; expected one of: {choices}")
    if env_flag("AUTOPENTEST_RAG_DISABLED"):
        return RAG_MODE_DISABLED
    if env_flag("AUTOPENTEST_RAG_STRICT_EXCLUDE"):
        return RAG_MODE_STRICT
    return RAG_MODE_ORACLE


def default_top_k() -> int:
    raw = (os.getenv("AUTOPENTEST_RAG_TOP_K") or "").strip()
    if not raw:
        return 3
    try:
        value = int(raw)
    except ValueError:
        return 3
    return max(1, min(value, 8))


def strict_event_exclusion_enabled() -> bool:
    """Return whether the current RAG mode excludes same-event context."""

    return rag_mode() == RAG_MODE_STRICT

