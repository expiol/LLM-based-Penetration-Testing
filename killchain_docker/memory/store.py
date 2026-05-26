"""Mutable run-memory store over the durable RunState payload."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from killchain_docker.memory.entries import (
    DEFAULT_RUN_MEMORY_LIMIT,
    MemoryEntry,
    MemoryIndexSnapshot,
)
from killchain_docker.memory.recall import (
    memory_index_snapshot,
    memory_numeric_hints,
    memory_prompt_mapping,
    recall_memory_entries,
)
from killchain_docker.value_coercion import coerce_string_mapping


class RunMemoryStore:
    """Mutable write facade for ``RunState.run_memory``."""

    def __init__(
        self, data: MutableMapping[str, str], *, limit: int = DEFAULT_RUN_MEMORY_LIMIT
    ) -> None:
        self._data = data
        self._limit = max(1, limit)

    def upsert_many(self, updates: Any) -> tuple[MemoryEntry, ...]:
        """Coerce, write, and bound trusted updates."""
        normalized = coerce_string_mapping(updates)
        if not normalized:
            return ()
        self._data.update(normalized)
        self._enforce_limit()
        return tuple(MemoryEntry(key, value) for key, value in normalized.items())

    def recall(self, *, limit: int | None = None) -> tuple[MemoryEntry, ...]:
        """Return recent entries in insertion order."""
        return recall_memory_entries(
            self._data,
            limit=self._limit if limit is None else max(1, limit),
        )

    def index_snapshot(self, *, title: str = "Run Memory") -> MemoryIndexSnapshot:
        return memory_index_snapshot(self._data, title=title, limit=self._limit)

    def prompt_entries(self, *, limit: int | None = None) -> dict[str, str]:
        """Return the bounded key/value view used by LLM prompt builders."""
        return memory_prompt_mapping(
            self._data,
            limit=self._limit if limit is None else max(1, limit),
        )

    def numeric_hints(
        self, *, limit: int = 100000000, max_hints: int = 12
    ) -> list[dict[str, object]]:
        return memory_numeric_hints(
            self._data,
            limit=limit,
            max_hints=max_hints,
            recall_limit=self._limit,
        )

    def _enforce_limit(self) -> None:
        while len(self._data) > self._limit:
            first_key = next(iter(self._data))
            del self._data[first_key]

