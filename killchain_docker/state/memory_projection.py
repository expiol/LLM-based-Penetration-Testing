"""Prompt-facing run-memory projection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.prompt_bounds import trim_text
from killchain_docker.state.memory_store import RunMemoryStore

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class RunMemoryProjection:
    """Read-only prompt and numeric-hint views over run memory."""

    def __init__(self, state: "RunState") -> None:
        self.store = RunMemoryStore(state.run_memory)

    def prompt_entries(self, *, limit: int = 20, width: int = 360) -> dict[str, str]:
        return {
            str(key): trim_text(value, width=width)
            for key, value in self.store.prompt_entries(limit=limit).items()
        }

    def numeric_hints(
        self, *, limit: int = 100000000, max_hints: int = 12
    ) -> list[dict[str, object]]:
        return self.store.numeric_hints(limit=limit, max_hints=max_hints)
