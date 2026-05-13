"""Pydantic schemas describing structured LLM outputs.

Each guidance model is tied to a specific kill-chain stage.  Workers ask the
LLM to return JSON matching one of these schemas, and the reasoning helpers
in this package merge the result back into the worker output.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, Field, field_validator

from killchain_docker.agents._helpers.coercion import coerce_confidence, coerce_llm_bool
from killchain_docker.state import Task


class ArtifactTriageGuidance(BaseModel):
    """LLM ranking and synthesis for top-level artifact triage."""

    summary: str
    prioritized_task_types: list[str] = Field(default_factory=list)
    prioritized_analysis_kinds: list[str] = Field(default_factory=list)
    source_routing_intent: str | None = None
    preferred_source_workers: list[str] = Field(default_factory=list)
    extra_flag_candidates: list[str] = Field(default_factory=list)
    focus_files: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)


class EvidenceReviewGuidance(BaseModel):
    """Grounded LLM synthesis for evidence-heavy local analysis workers."""

    summary: str
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    promote_runtime_probe: bool = False
    promote_computation_analysis: bool = False

    _coerce_llm_bools_evidence = field_validator(
        "promote_runtime_probe", "promote_computation_analysis", mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class StageAnalysisGuidance(BaseModel):
    """Grounded LLM synthesis for recon, host, service, vuln, and flag stages."""

    summary: str
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_flag_hunt: bool = False
    should_schedule_credential_hunt: bool = False
    should_schedule_exploit_hypothesis: bool = False

    _coerce_llm_bools_stage = field_validator(
        "should_schedule_flag_hunt",
        "should_schedule_credential_hunt",
        "should_schedule_exploit_hypothesis",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class CredentialHarvestGuidance(BaseModel):
    """Grounded LLM synthesis for credential-centric CTF pivots."""

    summary: str
    prioritized_credential_ids: list[str] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_exploit_hypothesis: bool = False

    _coerce_llm_bools_cred_harvest = field_validator(
        "should_schedule_exploit_hypothesis",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class ExploitHypothesisGuidance(BaseModel):
    """LLM output for CTF exploit/pivot reasoning."""

    summary: str
    hypotheses: list[str] = Field(default_factory=list)
    focus_asset_ids: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_flag_hunt: bool = False
    should_schedule_credential_hunt: bool = False
    should_schedule_credential_test: bool = False
    should_schedule_cve_probe: bool = False

    _coerce_llm_bools_exploit_hypothesis = field_validator(
        "should_schedule_flag_hunt",
        "should_schedule_credential_hunt",
        "should_schedule_credential_test",
        "should_schedule_cve_probe",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class CredentialTestGuidance(BaseModel):
    """LLM plan for credential reuse against web targets."""

    summary: str
    prioritized_credential_ids: list[str] = Field(default_factory=list)
    login_paths: list[str] = Field(default_factory=list)
    privileged_paths: list[str] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_cve_probe: bool = False

    _coerce_llm_bools_cred_test = field_validator(
        "should_schedule_cve_probe",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class ExploitProbeGuidance(BaseModel):
    """LLM plan for targeted web/pwn exploit probing."""

    summary: str
    prioritized_credential_ids: list[str] = Field(default_factory=list)
    preferred_protocol: str | None = None
    http_paths: list[str] = Field(default_factory=list)
    tcp_inputs: list[str] = Field(default_factory=list)
    focus_ports: list[int] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_flag_hunt: bool = False

    _coerce_llm_bools_exploit_probe = field_validator(
        "should_schedule_flag_hunt",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class FormProbeGuidance(BaseModel):
    """LLM plan for generalized web-form interaction and upload probing."""

    summary: str
    query_variants: list[str] = Field(default_factory=list)
    text_payloads: list[str] = Field(default_factory=list)
    filename_variants: list[str] = Field(default_factory=list)
    grounded_flag_candidates: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    should_schedule_exploit_hypothesis: bool = False

    _coerce_llm_bools_form_probe = field_validator(
        "should_schedule_exploit_hypothesis",
        mode="before",
    )(lambda cls, v: coerce_llm_bool(v))


class SolverCodeGuidance(BaseModel):
    """LLM-generated solver script for a CTF challenge."""

    summary: str
    solver_code: str
    solver_language: str = "python"
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


def boost_prioritized_tasks(
    tasks: Iterable[Task],
    prioritized_task_types: list[str] | None,
    prioritized_analysis_kinds: list[str] | None = None,
) -> None:
    """Apply bounded priority boosts based on an LLM-supplied ranking."""

    ranking = {
        task_type: index
        for index, task_type in enumerate(prioritized_task_types or [])
        if task_type
    }
    analysis_ranking = {
        analysis_kind: index
        for index, analysis_kind in enumerate(prioritized_analysis_kinds or [])
        if analysis_kind
    }
    for task in tasks:
        if task.task_type not in ranking:
            boost = 0
        else:
            boost = max(0, 12 - 2 * ranking[task.task_type])
        analysis_kind = str(task.input_context.get("analysis_kind") or task.metadata.get("analysis_kind") or "")
        if analysis_kind in analysis_ranking:
            boost += max(0, 10 - 2 * analysis_ranking[analysis_kind])
        if boost <= 0:
            continue
        task.priority = min(100, task.priority + boost)
