"""Solver retry decisions.

Decides whether to schedule a follow-up ``solve.generate_script`` task and
constructs the retry context (concrete failure fingerprint + diagnosis).

This is the **only** retry path for the solver: :class:`SolverAgent` reports
``retryable=False`` so the orchestrator never re-dispatches a failed solver
task with the same task_id. Each retry creates a brand-new task whose
``input_context.previous_attempts`` carries the structured failure signal we
synthesise here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.evidence import (
    SolverEvidence,
    compact_previous_attempt,
    compact_previous_attempts,
)
from nyuctf_mutil_killchain.agents.solver.executor import SolverExecutionOutcome
from nyuctf_mutil_killchain.agents.solver.failure import (
    SolverFailureClassifier,
    SolverFailureSignal,
)
from nyuctf_mutil_killchain.agents.solver.parser import SolverFlagSet
from nyuctf_mutil_killchain.state import Task


@dataclass
class SolverRetryPlan:
    """Outcome of the retry policy."""

    retry_task: Task | None = None
    notes: list[str] = field(default_factory=list)
    signal: SolverFailureSignal | None = None

    @property
    def should_retry(self) -> bool:
        return self.retry_task is not None


class SolverRetryPolicy:
    """Decide whether the solver should retry, and prepare retry context."""

    def __init__(self, *, max_retries: int = 4) -> None:
        self.max_retries = max_retries

    def decide(
        self,
        *,
        task: Task,
        evidence: SolverEvidence,
        outcome: SolverExecutionOutcome,
        flags: SolverFlagSet,
        guidance: SolverCodeGuidance,
    ) -> SolverRetryPlan:
        # ALWAYS classify the failure first.  Cross-chain memory needs a
        # semantic fingerprint on the failed report's ``output_context``
        # even when the solver decided not to retry (`has_real_flag` or
        # `should_retry_on_failure=False`); without it the caller falls
        # back to the generic "last stderr line" derivation and dedup
        # collapses unrelated failures together.
        attempt = evidence.attempt_number
        stderr = outcome.stderr[:1500]
        stdout = outcome.stdout[:1500]
        returncode = outcome.returncode
        near_miss = flags.near_miss_raw

        signal = SolverFailureClassifier.classify(
            attempt=attempt,
            returncode=returncode,
            stderr=stderr,
            stdout=stdout,
            near_miss=near_miss,
            timeout_s=evidence.timeout_s,
            previous_solver_code=guidance.solver_code,
        )

        if flags.has_real_flag:
            # No retry needed (we found the flag), but still surface the
            # classifier signal so any partial-failure context stays usable.
            return SolverRetryPlan(signal=signal)
        if not guidance.should_retry_on_failure:
            return SolverRetryPlan(signal=signal)

        if attempt >= self.max_retries:
            return SolverRetryPlan(
                notes=[
                    f"Solver attempt {attempt} produced no flags; max retries reached."
                ],
                signal=signal,
            )

        retry_timeout = evidence.timeout_s + 30 if near_miss else evidence.timeout_s
        prior_attempts = compact_previous_attempts(
            list(task.input_context.get("previous_attempts") or []),
            limit=max(1, self.max_retries - 1),
            include_latest_code=False,
        )
        current_attempt = compact_previous_attempt(
            {
                "attempt": attempt,
                "solver_code_preview": guidance.solver_code,
                "returncode": returncode,
                "stderr": stderr,
                "stdout": stdout,
                "near_miss_candidates": near_miss[:5],
                "error_summary": f"Attempt {attempt} failed: exit code {returncode}",
                "error_diagnosis": signal.diagnosis,
                "error_fingerprint": signal.error_fingerprint,
                "failure_class": signal.failure_class,
            },
            include_code=True,
        )
        retry_task = Task(
            title=f"Solver retry (attempt {attempt + 1})",
            description="Retry solver generation with previous failure context.",
            task_type="solve.generate_script",
            priority=97,
            input_context={
                "files_root": evidence.files_root,
                "attempt_number": attempt + 1,
                "solver_timeout_s": retry_timeout,
                "previous_attempts": prior_attempts + [current_attempt],
                "failure_class": signal.failure_class,
                "must_avoid": signal.must_avoid,
                "required_checks": signal.required_checks,
            },
            dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt + 1}",
            metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
        )

        notes = [f"Solver attempt {attempt} produced no flags; scheduling retry."]
        if signal.error_fingerprint:
            notes.append(f"Failure fingerprint: {signal.error_fingerprint}")
        if signal.failure_class:
            notes.append(f"Failure class: {signal.failure_class}")
        if near_miss:
            notes.append(f"Near-miss flag patterns detected: {near_miss[:3]}")
        return SolverRetryPlan(retry_task=retry_task, notes=notes, signal=signal)
