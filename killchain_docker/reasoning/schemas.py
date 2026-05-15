"""Pydantic schemas for structured LLM helper outputs."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from killchain_docker.tools import ToolCapability


class ToolUseDecision(BaseModel):
    """LLM-selected lower-level tool capability and arguments."""

    capability: ToolCapability | str
    metadata: dict[str, object] = Field(default_factory=dict)
    rationale: str = ""
    expected_signal: str = ""
    hypothesis: str | None = None
    memory_updates: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_script_code(self) -> "ToolUseDecision":
        if str(self.capability) == "script.execute" and not self.metadata.get("script_code"):
            raise ValueError(
                "script.execute requires 'script_code' in metadata containing "
                "the full executable source code, not a description."
            )
        return self


class ContinueDecision(BaseModel):
    """Worker inner-loop decision: run another tool or return results."""

    continue_loop: bool
    reason: str = ""
    next_hint: str = ""
    error_analysis: str = ""
    fix_strategy: str = ""
