"""Candidate flag validation worker."""

from __future__ import annotations

import hashlib

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Severity, Task, WorkerReport, Finding


class FlagValidationAgent(WorkerAgent):
    """Validates candidate flags against the expected challenge flag."""

    name = "flag-validation-agent"
    supported_task_types = ("flag.validate",)

    def __init__(self, *, expected_flag: str | None = None):
        super().__init__(llm_client=None, execution_plane=None)
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
            )

        if not self.expected_flag:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=True,
                summary="Flag validation skipped; expected flag is not configured.",
                output_context={
                    "candidate_flag": candidate,
                    "candidate_source": candidate_source,
                    "validated": False,
                    "validation_skipped": True,
                },
                notes=["Flag validation skipped because no expected flag is configured."],
            )

        is_correct = candidate == self.expected_flag
        candidate_id = hashlib.sha1(candidate.encode("utf-8")).hexdigest()[:12]
        finding = Finding(
            finding_id=f"finding-flag-validation-{candidate_id}",
            title="Candidate flag validation result",
            severity=Severity.INFO if is_correct else Severity.LOW,
            description=(
                f"Validated candidate from {candidate_source}: "
                + ("correct flag." if is_correct else "candidate did not match expected flag.")
            ),
            asset_refs=["challenge"],
            evidence_refs=[candidate],
            metadata={
                "source_task_id": task.task_id,
                "candidate_source": candidate_source,
                "candidate_flag": candidate,
                "validated": is_correct,
            },
            status="closed" if is_correct else "open",
        )

        notes = [f"{self.name} validated candidate from {candidate_source}."]
        if is_correct:
            notes.append(f"Correct flag validated: {candidate}")

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
            validated_flag=candidate if is_correct else None,
            output_context={
                "candidate_flag": candidate,
                "candidate_source": candidate_source,
                "validated": is_correct,
            },
        )
