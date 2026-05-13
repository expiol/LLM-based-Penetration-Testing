"""Flag validation worker group."""

from __future__ import annotations

from killchain_docker.agents.flag import FlagValidationAgent

FLAG_WORKERS: tuple[type, ...] = (FlagValidationAgent,)


__all__ = [
    "FLAG_WORKERS",
    "FlagValidationAgent",
]
