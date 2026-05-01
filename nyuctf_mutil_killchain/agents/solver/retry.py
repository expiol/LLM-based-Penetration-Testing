"""Solver retry decisions.

Decides whether to schedule a follow-up ``solve.generate_script`` task and
constructs the retry context (concrete failure fingerprint + strategy hint).

This is the **only** retry path for the solver: :class:`SolverAgent` reports
``retryable=False`` so the orchestrator never re-dispatches a failed solver
task with the same task_id.  Each retry creates a brand new task whose
``input_context.previous_attempts`` carries the concrete error fingerprint we
synthesise here, so the LLM can correct the specific bug instead of starting
over with no context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidence
from nyuctf_mutil_killchain.agents.solver.executor import SolverExecutionOutcome
from nyuctf_mutil_killchain.agents.solver.parser import SolverFlagSet
from nyuctf_mutil_killchain.state import Task


_RETRY_STRATEGIES = (
    "Try a completely different algorithm or technique - your previous approach is wrong, not just buggy.",
    "Re-read all challenge files from disk with open() and inspect the raw bytes. "
    "Check file headers, magic bytes, and structure before applying transforms.",
    "Use subprocess to run system tools (strings, xxd, file, tshark, objdump) "
    "and parse the output instead of implementing the analysis in Python.",
    "Try the simplest possible approach first: search for flag patterns directly "
    "in all files with strings/grep, or try known decryption with obvious keys.",
)

# Last-line traceback pattern: ``ExceptionType: message`` after the trailing
# stack frame.  Captured into the retry diagnosis so the next prompt includes
# the actual error rather than a generic "script crashed" message.
_TRACEBACK_LAST_LINE_RE = re.compile(
    r"^(?P<exc>[A-Z][A-Za-z0-9_]*Error|[A-Z][A-Za-z0-9_]*Exception|"
    r"SystemExit|KeyboardInterrupt|StopIteration|StopAsyncIteration)"
    r"(:\s*(?P<msg>.+))?$",
    re.MULTILINE,
)
# ``  File "/tmp/_solver_xxx.py", line 17, in <module>``
_TRACEBACK_FRAME_RE = re.compile(
    r'^\s*File "(?P<path>[^"]+)", line (?P<lineno>\d+)(?:, in (?P<func>\S+))?',
    re.MULTILINE,
)


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
        diagnosis, error_fingerprint = self._diagnose(
            attempt=attempt,
            returncode=returncode,
            stderr=stderr,
            stdout=stdout,
            near_miss=near_miss,
            timeout_s=evidence.timeout_s,
            strategy_hint=strategy_hint,
            previous_solver_code=guidance.solver_code,
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
                        "error_fingerprint": error_fingerprint,
                    }
                ],
            },
            dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt + 1}",
            metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
        )

        notes = [f"Solver attempt {attempt} produced no flags; scheduling retry."]
        if error_fingerprint:
            notes.append(f"Failure fingerprint: {error_fingerprint}")
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
        previous_solver_code: str,
    ) -> tuple[str, str]:
        """Return ``(diagnosis_text, error_fingerprint)`` for the retry prompt.

        ``error_fingerprint`` is a short, prompt-safe summary of the concrete
        error (exception type + message + offending source line when available)
        so the LLM can fix the specific bug.
        """
        if returncode == -1 and "timed out" in stderr.lower():
            fingerprint = f"timeout after {timeout_s}s"
            diagnosis = (
                f"Attempt {attempt}: script TIMED OUT after {timeout_s}s "
                f"({fingerprint}). The script likely hung on a network "
                f"connection or infinite loop. If connecting to a remote service, add a timeout "
                f"parameter to your connection (e.g. r = remote(host, port, timeout=10)). "
                f"If doing computation, optimize the algorithm or reduce iterations. {strategy_hint}"
            )
            return diagnosis, fingerprint

        if near_miss:
            fingerprint = f"near-miss flags {near_miss[:2]}"
            diagnosis = (
                f"Attempt {attempt}: solver output contained flag-like pattern(s) "
                f"with non-printable characters ({near_miss[:3]}), suggesting the "
                f"decryption/decode approach was partially correct but key recovery "
                f"or transform was incomplete. Refine the algorithm - do NOT repeat "
                f"the same approach. {strategy_hint}"
            )
            return diagnosis, fingerprint

        if returncode == 0 and not stdout.strip():
            fingerprint = "exit 0 with empty stdout"
            diagnosis = (
                f"Attempt {attempt}: script exited 0 but produced no output ({fingerprint}). "
                f"Ensure the script prints the flag to stdout. {strategy_hint}"
            )
            return diagnosis, fingerprint

        if returncode != 0:
            exc_match = _TRACEBACK_LAST_LINE_RE.search(stderr)
            frame_match = list(_TRACEBACK_FRAME_RE.finditer(stderr))
            if exc_match:
                exc_type = exc_match.group("exc")
                exc_msg = (exc_match.group("msg") or "").strip()
                if frame_match:
                    last_frame = frame_match[-1]
                    lineno_str = last_frame.group("lineno")
                    func = last_frame.group("func") or "<module>"
                    fingerprint = f"{exc_type}: {exc_msg} at line {lineno_str} in {func}"
                    offending = _extract_source_line(previous_solver_code, int(lineno_str))
                else:
                    fingerprint = f"{exc_type}: {exc_msg}".strip(": ")
                    offending = ""
                diagnosis = (
                    f"Attempt {attempt}: script crashed with {fingerprint}. "
                    f"The next solver MUST avoid this specific error. "
                )
                if offending:
                    diagnosis += f"Offending line: ``{offending.strip()}``. "
                diagnosis += strategy_hint
                return diagnosis, fingerprint

            fingerprint = f"exit code {returncode}"
            diagnosis = (
                f"Attempt {attempt}: script crashed with {fingerprint}. "
                f"Fix the runtime error. {strategy_hint}"
            )
            return diagnosis, fingerprint

        fingerprint = "exit 0 without flag"
        diagnosis = (
            f"Attempt {attempt}: script exited 0 but no valid flag found in output ({fingerprint}). "
            f"The output may contain garbled data - review the algorithm. {strategy_hint}"
        )
        return diagnosis, fingerprint


def _extract_source_line(source: str, lineno: int) -> str:
    """Return the (1-indexed) source line referenced by a traceback frame."""
    if lineno < 1:
        return ""
    lines = source.splitlines()
    if lineno > len(lines):
        return ""
    return lines[lineno - 1]
