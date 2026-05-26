"""Pydantic schemas for structured LLM helper outputs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from killchain_docker.memory.durable import DurableMemoryUpdate, coerce_durable_updates
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.value_coercion import coerce_string_mapping


class ToolUseDecision(BaseModel):
    """LLM-selected lower-level tool capability and arguments."""

    capability: ToolCapability | str
    metadata: dict[str, object] = Field(default_factory=dict)
    rationale: str = ""
    expected_signal: str = ""
    hypothesis: str | None = None
    memory_updates: dict[str, str] = Field(default_factory=dict)
    durable_memory_updates: list[DurableMemoryUpdate] = Field(default_factory=list)

    @field_validator("memory_updates", mode="before")
    @classmethod
    def _coerce_memory_updates(cls, value: Any) -> Any:
        return coerce_string_mapping(value)

    @field_validator("durable_memory_updates", mode="before")
    @classmethod
    def _coerce_durable_memory_updates(cls, value: Any) -> Any:
        return coerce_durable_updates(value)
