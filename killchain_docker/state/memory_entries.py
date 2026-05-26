"""Run-memory entry and prompt-index models."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_RUN_MEMORY_LIMIT = 20
MEMORY_ENTRYPOINT_NAME = "MEMORY.md"


@dataclass(frozen=True)
class MemoryEntry:
    """One grounded run-memory entry."""

    key: str
    value: str

    @property
    def title(self) -> str:
        return self.key.replace("_", " ").strip().title() or self.key


@dataclass(frozen=True)
class MemoryIndexSnapshot:
    """A bounded, prompt-ready memory index."""

    entries: tuple[MemoryEntry, ...]
    index_markdown: str
    entrypoint_name: str = MEMORY_ENTRYPOINT_NAME

    def as_prompt_mapping(self) -> dict[str, str]:
        return {entry.key: entry.value for entry in self.entries}
