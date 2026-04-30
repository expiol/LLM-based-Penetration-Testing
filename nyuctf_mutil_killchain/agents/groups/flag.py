"""Flag validation worker group."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.flag import FlagValidationAgent

FLAG_WORKERS: tuple[type, ...] = (FlagValidationAgent,)


__all__ = [
    "FLAG_WORKERS",
    "FlagValidationAgent",
]
