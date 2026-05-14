"""Candidate flag validation worker.

This worker is hot path during NYU-CTF batch runs: every flag candidate that
gets past :func:`build_flag_validation_tasks` ends up here.  We optimize for
two regimes:

1. ``expected_flag`` is configured (benchmark mode).  We can answer the
   question with a string compare; the LLM call is purely decorative and we
   skip it entirely.
2. ``expected_flag`` is ``None`` (real-world use).  We have no oracle, so the
   most we can do is light normalization (strip transport noise like quotes
   and whitespace) and report a non-validation finding.  In this case the LLM
   is consulted, but only when the candidate has the right shape — gibberish
   that slipped through earlier filters short-circuits the same way.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, Field, field_validator

from killchain_docker.workers._helpers.coercion import coerce_confidence
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.llm import LLMClient
from killchain_docker.state import (
    Finding,
    FlagCandidate,
    GlobalState,
    Severity,
    StateDelta,
    Task,
    TaskErrorCode,
    WorkerReport,
)
from killchain_docker.state.task_factory import is_validatable_flag_candidate


# Common "transport noise" wrappers that obscure an otherwise correct flag.
_TRANSPORT_NOISE_RE = re.compile(r"^[\s\"'`<>\[\(]+|[\s\"'`>\]\)]+$")


def _normalize_transport(candidate: str) -> str:
    """Strip wrapping quotes/brackets/whitespace that often surround pasted flags."""
    return _TRANSPORT_NOISE_RE.sub("", candidate.strip())


class FlagValidationAssessment(BaseModel):
    """LLM-assisted assessment of a candidate flag (normalization-only)."""

    summary: str
    normalized_candidate: str | None = None
    likely_valid: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    _coerce_confidence = field_validator("confidence", mode="before")(
        lambda cls, v: coerce_confidence(v)
    )


class FlagValidationAgent(WorkerAgent):
    """Validates candidate flags against the expected challenge flag."""

    name = "flag-validation-agent"
    supported_task_types = ("flag.validate",)
    required_context_keys = ("candidate_flag",)

    def __init__(self, *, llm_client: LLMClient | None = None, expected_flag: str | None = None):
        super().__init__(llm_client=llm_client, execution_plane=None)
        self.expected_flag = expected_flag

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        candidate = str(task.input_context.get("candidate_flag") or "").strip()
        candidate_source = str(task.input_context.get("candidate_source") or "unknown")
        if not candidate:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing candidate flag.",
                error="candidate_flag is required in task.input_context",
                retryable=False,
                error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
            )

        # Benchmark mode (oracle present): equality is the truth, do it first
        # and ignore everything else.  This is also the regime where wasting a
        # cycle on shape-rejection actually matters — we just want a yes/no.
        if self.expected_flag is not None:
            return self._validate_against_oracle(task, candidate, candidate_source)

        # No oracle: shape-check before any LLM round-trip so junk strings
        # (``FileNotFoundError: ...``, ``with open(...) as f:`` and friends)
        # don't burn a validation call.
        normalized_for_shape = _normalize_transport(candidate)
        if not is_validatable_flag_candidate(normalized_for_shape):
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=True,
                summary=f"Candidate from {candidate_source} rejected: not a flag-shaped token.",
                output_context={
                    "candidate_flag": candidate,
                    "candidate_source": candidate_source,
                    "validated": False,
                    "validation_skipped": True,
                    "rejection_reason": "shape_mismatch",
                },
                state_delta=StateDelta(
                    flag_candidates=[
                        FlagCandidate(
                            value=candidate,
                            source=candidate_source,
                            confidence=0.1,
                            validated=False,
                            rejected_reason="shape_mismatch",
                        )
                    ]
                ),
                notes=[
                    f"{self.name} skipped LLM validation: candidate is not a plausible flag shape."
                ],
            )
        return self._validate_without_oracle(task, candidate, candidate_source, state)

    def _validate_against_oracle(
        self,
        task: Task,
        candidate: str,
        candidate_source: str,
    ) -> WorkerReport:
        """Fast path used during benchmark runs: equality + cheap normalization."""

        normalized = _normalize_transport(candidate)
        is_correct = candidate == self.expected_flag or normalized == self.expected_flag
        if is_correct:
            normalized = self.expected_flag

        candidate_id = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]
        finding = Finding(
            finding_id=f"finding-flag-validation-{candidate_id}",
            title="Candidate flag validation result",
            severity=Severity.INFO if is_correct else Severity.LOW,
            description=(
                f"Validated candidate from {candidate_source}: "
                + ("correct flag." if is_correct else "candidate did not match expected flag.")
            ),
            asset_refs=["challenge"],
            evidence_refs=[normalized],
            metadata={
                "source_task_id": task.task_id,
                "candidate_source": candidate_source,
                "candidate_flag": candidate,
                "normalized_candidate": normalized,
                "validated": is_correct,
            },
            status="closed" if is_correct else "open",
        )

        notes = [f"{self.name} validated candidate from {candidate_source} via equality check."]
        if is_correct:
            notes.append(f"Correct flag validated: {normalized}")

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=(
                "Correct flag validated."
                if is_correct
                else f"Candidate flag from {candidate_source} was not correct."
            ),
            finding_updates=[finding],
            state_delta=StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value=normalized,
                        source=candidate_source,
                        confidence=1.0 if is_correct else 0.2,
                        validated=is_correct,
                        rejected_reason=None if is_correct else "oracle_mismatch",
                        evidence_refs=[normalized],
                    )
                ]
            ),
            notes=notes,
            solved=is_correct,
            validated_flag=normalized if is_correct else None,
            output_context={
                "candidate_flag": candidate,
                "normalized_candidate": normalized,
                "candidate_source": candidate_source,
                "validated": is_correct,
            },
        )

    def _validate_without_oracle(
        self,
        task: Task,
        candidate: str,
        candidate_source: str,
        state: GlobalState,
    ) -> WorkerReport:
        """No oracle: ask the LLM to opine, but only as advisory metadata."""

        llm_assessment = self.generate_structured_output(
            system_prompt=(
                "You assess whether a candidate flag from an authorized CTF workflow looks plausible. "
                "Return only JSON matching the FlagValidationAssessment schema. "
                "Do not invent a new flag. Only normalize obvious transport noise such as quotes, whitespace, or wrappers."
            ),
            user_prompt=(
                f"Objective: {state.objective}\n"
                f"Task ID: {task.task_id}\n"
                f"Candidate source: {candidate_source}\n"
                f"Candidate flag: {candidate}\n"
                f"Expected flag format: {state.metadata.get('challenge', {}).get('flag_format')}\n"
                "Expected flag available: False\n"
            ),
            schema=FlagValidationAssessment,
        )
        normalized = (
            (llm_assessment.normalized_candidate or "").strip()
            or _normalize_transport(candidate)
        )

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary="Flag validation skipped; expected flag is not configured.",
            output_context={
                "candidate_flag": candidate,
                "normalized_candidate": normalized,
                "candidate_source": candidate_source,
                "validated": False,
                "validation_skipped": True,
                "llm_summary": llm_assessment.summary,
                "llm_likely_valid": llm_assessment.likely_valid,
                "llm_confidence": llm_assessment.confidence,
            },
            state_delta=StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value=normalized,
                        source=candidate_source,
                        confidence=llm_assessment.confidence,
                        validated=False,
                        rejected_reason="no_oracle",
                    )
                ]
            ),
            notes=["Flag validation skipped because no expected flag is configured."],
        )


GROUP = "flag"
WORKER_CLASSES: tuple[type, ...] = (FlagValidationAgent,)


def _build_flag_validator(context: WorkerBuildContext) -> WorkerAgent:
    return FlagValidationAgent(
        llm_client=context.llm_client,
        expected_flag=context.expected_flag,
    )


WORKER_SPECS = (
    WorkerSpec(
        key=FlagValidationAgent.__name__,
        group=GROUP,
        factory=_build_flag_validator,
        description=(FlagValidationAgent.__doc__ or "").strip().splitlines()[0],
    ),
)
