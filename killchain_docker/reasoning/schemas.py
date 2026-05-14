"""Pydantic schemas for structured LLM helper outputs."""

from __future__ import annotations

from pydantic import BaseModel, Field

from killchain_docker.tools import ToolCapability


class ToolUseDecision(BaseModel):
    """LLM-selected lower-level tool capability and arguments."""

    capability: ToolCapability | str
    metadata: dict[str, object] = Field(default_factory=dict)
    rationale: str = ""
    expected_signal: str = ""
