"""Pydantic schemas for structured LLM helper outputs."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from killchain_docker.reasoning.coercion import coerce_confidence, coerce_llm_bool
from killchain_docker.tools import ToolCapability


class EvidenceReviewGuidance(BaseModel):
    """Grounded LLM synthesis for evidence-heavy local analysis."""

    summary: str
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    promote_runtime_probe: bool = False
    promote_computation_analysis: bool = False

    _coerce_llm_bools_evidence = field_validator(
        "promote_runtime_probe", "promote_computation_analysis", mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class ToolUseDecision(BaseModel):
    """LLM-selected lower-level tool capability and arguments."""

    capability: ToolCapability | str
    metadata: dict[str, object] = Field(default_factory=dict)
    rationale: str = ""
    expected_signal: str = ""


class ScriptCodeGuidance(BaseModel):
    """LLM-generated script for one bounded tool experiment."""

    summary: str
    script_code: str
    script_language: str = "python"
    reasoning: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    dependencies: list[str] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    should_retry_on_failure: bool = True

    _coerce_confidence = field_validator("confidence", mode="before")(
        lambda cls, v: coerce_confidence(v)
    )
    _coerce_retry_bool = field_validator("should_retry_on_failure", mode="before")(
        lambda cls, v: coerce_llm_bool(v)
    )
