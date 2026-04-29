"""Candidate flag validation worker."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClient
from nyuctf_mutil_killchain.state import GlobalState, Severity, Task, TaskErrorCode, WorkerReport, Finding


class FlagValidationAssessment(BaseModel):
    """LLM-assisted assessment of a candidate flag."""

    summary: str
    normalized_candidate: str | None = None
    likely_valid: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


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

        worker_notes: list[str] = []
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
                f"Expected flag available: {bool(self.expected_flag)}\n"
            ),
            schema=FlagValidationAssessment,
        )
        if llm_assessment.normalized_candidate is not None:
            normalized = str(llm_assessment.normalized_candidate).strip()
        else:
            normalized = ""
        candidate_to_check = (normalized or candidate).strip()

        if not self.expected_flag:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=True,
                summary="Flag validation skipped; expected flag is not configured.",
                output_context={
                    "candidate_flag": candidate,
                    "normalized_candidate": candidate_to_check,
                    "candidate_source": candidate_source,
                    "validated": False,
                    "validation_skipped": True,
                    "llm_summary": llm_assessment.summary,
                    "llm_likely_valid": llm_assessment.likely_valid,
                    "llm_confidence": llm_assessment.confidence,
                },
                notes=worker_notes + ["Flag validation skipped because no expected flag is configured."],
            )

        raw_stripped = candidate.strip()
        is_correct = raw_stripped == self.expected_flag or candidate_to_check == self.expected_flag
        if is_correct:
            candidate_to_check = self.expected_flag
        candidate_id = hashlib.sha1(candidate_to_check.encode("utf-8")).hexdigest()[:12]
        finding = Finding(
            finding_id=f"finding-flag-validation-{candidate_id}",
            title="Candidate flag validation result",
            severity=Severity.INFO if is_correct else Severity.LOW,
            description=(
                f"Validated candidate from {candidate_source}: "
                + ("correct flag." if is_correct else "candidate did not match expected flag.")
            ),
            asset_refs=["challenge"],
            evidence_refs=[candidate_to_check],
            metadata={
                "source_task_id": task.task_id,
                "candidate_source": candidate_source,
                "candidate_flag": candidate,
                "normalized_candidate": candidate_to_check,
                "validated": is_correct,
                "llm_summary": llm_assessment.summary,
                "llm_likely_valid": llm_assessment.likely_valid,
                "llm_confidence": llm_assessment.confidence,
            },
            status="closed" if is_correct else "open",
        )

        notes = worker_notes + [f"{self.name} validated candidate from {candidate_source}."]
        if is_correct:
            notes.append(f"Correct flag validated: {candidate_to_check}")

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
            notes=notes,
            solved=is_correct,
            validated_flag=candidate_to_check if is_correct else None,
            output_context={
                "candidate_flag": candidate,
                "normalized_candidate": candidate_to_check,
                "candidate_source": candidate_source,
                "validated": is_correct,
                "llm_summary": llm_assessment.summary,
                "llm_likely_valid": llm_assessment.likely_valid,
                "llm_confidence": llm_assessment.confidence,
            },
        )
