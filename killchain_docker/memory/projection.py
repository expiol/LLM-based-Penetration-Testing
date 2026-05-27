"""Prompt-facing run-memory projection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.intelligence.session import SESSION_SUMMARY_KEY
from killchain_docker.memory.store import RunMemoryStore
from killchain_docker.prompt_bounds import trim_text

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class RunMemoryProjection:
    """Read-only prompt and numeric-hint views over run memory."""

    def __init__(self, state: "RunState") -> None:
        self._data = state.run_memory
        self.store = RunMemoryStore(state.run_memory)

    def prompt_entries(
        self,
        *,
        limit: int = 20,
        width: int = 360,
        session_summary_width: int = 1800,
    ) -> dict[str, str]:
        entries = {
            str(key): trim_text(value, width=width)
            for key, value in self.store.prompt_entries(limit=limit).items()
        }
        if SESSION_SUMMARY_KEY in self._data:
            summary = trim_text(
                self._data[SESSION_SUMMARY_KEY],
                width=max(width, session_summary_width),
            )
            entries = {
                SESSION_SUMMARY_KEY: summary,
                **{
                    key: value
                    for key, value in entries.items()
                    if key != SESSION_SUMMARY_KEY
                },
            }
        return entries

    def numeric_hints(
        self, *, limit: int = 100000000, max_hints: int = 12
    ) -> list[dict[str, object]]:
        return self.store.numeric_hints(limit=limit, max_hints=max_hints)
