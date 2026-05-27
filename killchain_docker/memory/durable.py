"""Durable cross-run memory schema."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from killchain_docker.state.common import utc_now


class DurableMemoryScope(StrEnum):
    """Where a durable memory entry applies.

    Note: only ``GLOBAL`` and ``CATEGORY`` are accepted. Per-challenge memory
    is intentionally disallowed — durable lessons must abstract experience
    into category-wide or globally-applicable patterns rather than pinning
    answers to a specific challenge identity.
    """

    GLOBAL = "global"
    CATEGORY = "category"


class DurableMemoryUpdate(BaseModel):
    """Pending durable memory write produced by a worker or planner."""

    model_config = ConfigDict(extra="ignore")

    key: str
    value: str
    scope: DurableMemoryScope = DurableMemoryScope.CATEGORY
    title: str | None = None

    @field_validator("key", "value")
    @classmethod
    def _strip(cls, value: str) -> str:
        return str(value).strip()


class DurableMemoryRecord(BaseModel):
    """One durable memory entry as loaded from disk."""

    model_config = ConfigDict(extra="ignore")

    slug: str
    key: str
    value: str
    scope: DurableMemoryScope
    category: str | None = None
    title: str = ""
    run_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge_run(self, run_id: str) -> None:
        if run_id and run_id not in self.run_ids:
            self.run_ids.append(run_id)


def coerce_durable_updates(value: Any) -> list[DurableMemoryUpdate]:
    """Coerce loose dicts/lists to typed DurableMemoryUpdate items.

    Note: any incoming ``challenge`` scope is coerced to ``category``.
    Durable memory is intentionally not allowed at challenge granularity —
    lessons must generalise so future runs cannot retrieve a previous run's
    answer for the same challenge.
    """
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, dict):
        items = [{"key": key, "value": val} for key, val in value.items()]
    else:
        return []
    out: list[DurableMemoryUpdate] = []
    for item in items:
        if isinstance(item, DurableMemoryUpdate):
            out.append(item)
            continue
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        val = str(item.get("value") or "").strip()
        if not key or not val:
            continue
        scope_raw = str(item.get("scope") or DurableMemoryScope.CATEGORY).strip().lower()
        if scope_raw == "challenge":
            scope_raw = DurableMemoryScope.CATEGORY.value
        try:
            scope = DurableMemoryScope(scope_raw)
        except ValueError:
            scope = DurableMemoryScope.CATEGORY
        title = item.get("title")
        out.append(
            DurableMemoryUpdate(
                key=key,
                value=val,
                scope=scope,
                title=str(title).strip() if title else None,
            )
        )
    return out
