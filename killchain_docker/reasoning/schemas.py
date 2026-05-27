"""Pydantic schemas for structured LLM helper outputs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from killchain_docker.memory.durable import DurableMemoryUpdate, coerce_durable_updates
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import _first_string
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

    @model_validator(mode="after")
    def _check_required_metadata(self) -> "ToolUseDecision":
        # Local import: contracts/catalog.py belongs to the worker layer and
        # imports nothing from reasoning, but we keep the import lazy so that
        # the schema module remains usable in contexts where the worker
        # tooling package is not loaded (e.g. minimal unit tests).
        from killchain_docker.workers.tooling.contracts.catalog import (
            TOOL_METADATA_CONTRACT_CATALOG,
        )

        try:
            cap = ToolCapability(self.capability)
        except ValueError:
            return self
        contract = TOOL_METADATA_CONTRACT_CATALOG.get(cap)
        if not contract:
            return self
        missing = [
            field
            for field in contract.get("required", [])
            if not _first_string(self.metadata.get(field))
        ]
        if missing:
            fields = ", ".join(f"metadata.{name}" for name in missing)
            raise ValueError(
                f"{cap.value} is missing required {fields}; "
                f"populate metadata with non-empty values for: {', '.join(missing)}"
            )
        return self
