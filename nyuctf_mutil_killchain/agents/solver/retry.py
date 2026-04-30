"""Solver retry decisions.

Decides whether to schedule a follow-up ``solve.generate_script`` task and
constructs the retry context (previous attempt summary + strategy hint).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidence
from nyuctf_mutil_killchain.agents.solver.executor import SolverExecutionOutcome
from nyuctf_mutil_killchain.agents.solver.parser import SolverFlagSet
from nyuctf_mutil_killchain.state import Task


_RETRY_STRATEGIES = [
    "Try a completely different algorithm or technique.",
    "Re-read all challenge files from disk with open() and inspect the raw bytes. "
    "Check file headers, magic bytes, and structure before applying transforms.",
    "Use subprocess to run system tools (strings, xxd, file, tshark, objdump) "
    "and parse the output instead of implementing the analysis in Python.",
    "Try the simplest possible approach first: search for flag patterns directly "
    "in all files with strings/grep, or try known decryption with obvious keys.",
]


@dataclass
class SolverRetryPlan:
    """Outcome of the retry policy."""

    retry_task: Task | None = None
    notes: list[str] = field(default_factory=list)

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
        if flags.has_real_flag:
            return SolverRetryPlan()
        if not guidance.should_retry_on_failure:
            return SolverRetryPlan()

        attempt = evidence.attempt_number
        if attempt >= self.max_retries:
            return SolverRetryPlan(notes=[
                f"Solver attempt {attempt} produced no flags; max retries reached."
            ])

        stderr = outcome.stderr[:1500]
        stdout = outcome.stdout[:1500]
        returncode = outcome.returncode
        near_miss = flags.near_miss_raw

        strategy_hint = _RETRY_STRATEGIES[
            min(attempt - 1, len(_RETRY_STRATEGIES) - 1)
        ]
        diagnosis = self._diagnose(
            attempt=attempt,
            returncode=returncode,
            stderr=stderr,
            stdout=stdout,
            near_miss=near_miss,
            timeout_s=evidence.timeout_s,
            strategy_hint=strategy_hint,
        )

        retry_timeout = evidence.timeout_s + 30 if near_miss else evidence.timeout_s
        retry_task = Task(
            title=f"Solver retry (attempt {attempt + 1})",
            description="Retry solver generation with previous failure context.",
            task_type="solve.generate_script",
            priority=97,
            input_context={
                "files_root": evidence.files_root,
                "attempt_number": attempt + 1,
                "solver_timeout_s": retry_timeout,
                "previous_attempts": (task.input_context.get("previous_attempts") or []) + [
                    {
                        "attempt": attempt,
                        "solver_code_preview": guidance.solver_code[:2000],
                        "returncode": returncode,
                        "stderr": stderr,
                        "stdout": stdout,
                        "near_miss_candidates": near_miss[:5],
                        "error_summary": f"Attempt {attempt} failed: exit code {returncode}",
                        "error_diagnosis": diagnosis,
                    }
                ],
            },
            dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt + 1}",
            metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
        )

        notes = [f"Solver attempt {attempt} produced no flags; scheduling retry."]
        if near_miss:
            notes.append(f"Near-miss flag patterns detected: {near_miss[:3]}")
        return SolverRetryPlan(retry_task=retry_task, notes=notes)

    @staticmethod
    def _diagnose(
        *,
        attempt: int,
        returncode: int,
        stderr: str,
        stdout: str,
        near_miss: list[str],
        timeout_s: int,
        strategy_hint: str,
    ) -> str:
        if returncode == -1 and "timed out" in stderr.lower():
            return (
                f"Attempt {attempt}: script TIMED OUT after {timeout_s}s. "
                f"The script likely hung on a network connection or infinite loop. "
                f"If connecting to a remote service, add a timeout parameter to your "
                f"connection (e.g. r = remote(host, port, timeout=10)). "
                f"If doing computation, optimize the algorithm or reduce iterations. "
                f"{strategy_hint}"
            )
        if near_miss:
            return (
                f"Attempt {attempt}: solver output contained flag-like pattern(s) "
                f"with non-printable characters ({near_miss[:3]}), suggesting the "
                f"decryption/decode approach was partially correct but key recovery "
                f"or transform was incomplete. Refine the algorithm - do NOT repeat "
                f"the same approach. {strategy_hint}"
            )
        if returncode == 0 and not stdout.strip():
            return (
                f"Attempt {attempt}: script exited 0 but produced no output. "
                f"Ensure the script prints the flag to stdout. {strategy_hint}"
            )
        if returncode != 0:
            return (
                f"Attempt {attempt}: script crashed with exit code {returncode}. "
                f"Fix the runtime error. {strategy_hint}"
            )
        return (
            f"Attempt {attempt}: script exited 0 but no valid flag found in output. "
            f"The output may contain garbled data - review the algorithm. {strategy_hint}"
        )
