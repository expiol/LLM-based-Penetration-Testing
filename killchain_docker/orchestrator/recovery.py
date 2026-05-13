"""Recovery policy for solver failures that RAG can calibrate.

Dispatch selection should stay deterministic and local to the ready queue.
This module owns the cross-cycle interpretation: solver streaks, RAG
confidence, and failure fingerprints.  When the current writeup hit is
strong but solver attempts keep failing, it schedules one high-priority
calibrated solver task instead of letting dispatch simply suppress solve.*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from killchain_docker.agents.solver.failure import (
    SolverFailureClassifier,
    SolverFailureSignal,
)
from killchain_docker.knowledge import KnowledgeAugmenter, RagContext
from killchain_docker.state import (
    ExecutionRecord,
    GlobalState,
    Task,
    TaskAttemptMemory,
    TaskStatus,
)


_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"
_EXIT_CODE_RE = re.compile(r"\bexit code\s+(-?\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class RecoveryResult:
    """Result of running recovery analysis before dispatch."""

    task: Task | None = None
    created: bool = False
    reason: str = ""


class RecoveryPolicy:
    """Create calibrated solver recovery tasks for high-confidence RAG streaks."""

    _SOLVER_FAILURE_STREAK_LIMIT = 8

    def __init__(
        self,
        *,
        augmenter: KnowledgeAugmenter | None,
        emit: Callable[[str], None] = print,
        solver_failure_limit: int = _SOLVER_FAILURE_STREAK_LIMIT,
    ) -> None:
        self.augmenter = augmenter
        self.emit = emit
        self.solver_failure_limit = solver_failure_limit

    def apply(self, state: GlobalState) -> RecoveryResult:
        """Inspect *state* and queue a calibrated recovery task when warranted."""

        if state.solved:
            return RecoveryResult(reason="already_solved")
        rag_context = self._rag_context(state)
        if not rag_context.high_confidence:
            return RecoveryResult(reason="rag_not_high_confidence")
        if self._has_recovery_task(state):
            return RecoveryResult(reason="recovery_already_exists")

        streak = self._solver_failure_streak(state)
        if streak < self.solver_failure_limit:
            return RecoveryResult(reason=f"solver_streak_below_limit:{streak}")

        signal = self._last_failure_signal(state)
        task = self._build_recovery_task(
            state=state,
            rag_context=rag_context,
            signal=signal,
            streak=streak,
        )
        queued = state.queue_task(task)
        created = queued.task_id == task.task_id
        if created:
            note = (
                "recovery: queued solver task after "
                f"{streak} consecutive solver failures with RAG top score "
                f"{rag_context.top_score:.3f}."
            )
            state.orchestration_notes.append(note)
            self.emit(
                "[recovery] queued solver recovery task: "
                f"{queued.task_id} (streak={streak}, "
                f"rag={rag_context.top_score:.3f}, "
                f"failure_class={signal.failure_class})"
            )
        return RecoveryResult(
            task=queued,
            created=created,
            reason="created" if created else "deduped",
        )

    def _rag_context(self, state: GlobalState) -> RagContext:
        if self.augmenter is None or not getattr(self.augmenter, "enabled", False):
            return RagContext(enabled=False, hits=[])
        try:
            return self.augmenter.context_for(state)
        except Exception:
            return RagContext(enabled=True, hits=[])

    @staticmethod
    def _has_recovery_task(state: GlobalState) -> bool:
        for task in state.task_chain.tasks:
            if task.task_type != "solve.generate_script":
                continue
            if task.input_context.get("solver_mode") != "recovery":
                continue
            if task.status != TaskStatus.CANCELLED:
                return True
        return False

    @staticmethod
    def _solver_failure_streak(state: GlobalState) -> int:
        streak = 0
        for record in reversed(state.execution_log):
            if record.worker_name != "solver-agent":
                continue
            if record.success:
                return 0
            streak += 1
        return streak

    def _build_recovery_task(
        self,
        *,
        state: GlobalState,
        rag_context: RagContext,
        signal: SolverFailureSignal,
        streak: int,
    ) -> Task:
        required_checks = _dedupe(
            [
                *signal.required_checks,
                "Compare the implementation against the top RAG solution sketch before coding.",
            ]
        )[:16]
        must_avoid = _dedupe(
            [
                *signal.must_avoid,
                "Do not repeat the previous broad solver approach without new diagnostics.",
            ]
        )[:12]

        top_hit = (rag_context.hits or [None])[0]
        top_name = top_hit.name if top_hit is not None else rag_context.top_challenge_id
        return Task(
            title="RAG-driven solver recovery",
            description=(
                "Generate a solver using the high-confidence RAG hit "
                f"({top_name}) and previous failure fingerprints."
            ),
            task_type="solve.generate_script",
            priority=100,
            input_context={
                "files_root": self._files_root(state),
                "attempt_number": 1,
                "solver_timeout_s": 180,
                "solver_mode": "recovery",
                "failure_class": signal.failure_class,
                "must_avoid": must_avoid,
                "required_checks": required_checks,
                "previous_attempts": self._previous_attempts(state),
            },
            dedupe_key=f"solver-recovery:rag:{rag_context.top_challenge_id or 'unknown'}",
            metadata={
                "planned_by": "recovery-policy",
                "rag_top_score": rag_context.top_score,
                "rag_top_challenge_id": rag_context.top_challenge_id,
                "rag_exact_self_hit": rag_context.exact_self_hit,
                "solver_failure_streak": streak,
            },
        )

    @staticmethod
    def _files_root(state: GlobalState) -> str:
        for task in reversed(state.task_chain.tasks):
            if task.task_type == "solve.generate_script":
                files_root = task.input_context.get("files_root")
                if files_root:
                    return str(files_root)
        challenge_meta = state.metadata.get("challenge", {}) or {}
        return str(challenge_meta.get("files_root") or _DEFAULT_FILES_ROOT)

    def _previous_attempts(self, state: GlobalState) -> list[dict[str, object]]:
        # Use the shared dedup helper so recovery does not surface 3 copies
        # of the same fingerprint (which used to happen with the old raw
        # ``memory[-3:]`` slice when retries kept hitting the same error).
        picked = state.recent_attempt_memory_for(
            "solve.generate_script", limit=3,
        )
        if picked:
            return [self._attempt_from_memory(item, idx) for idx, item in enumerate(picked, start=1)]

        records = [
            record
            for record in state.execution_log
            if record.worker_name == "solver-agent" and not record.success
        ][-3:]
        return [
            self._attempt_from_record(record, idx)
            for idx, record in enumerate(records, start=1)
        ]

    def _attempt_from_memory(
        self,
        item: TaskAttemptMemory,
        idx: int,
    ) -> dict[str, object]:
        combined = "\n".join(
            part
            for part in (
                item.stderr_preview,
                item.stdout_preview,
                item.error,
                item.summary,
            )
            if part
        )
        signal = self._classify_text(idx, combined, stdout=item.stdout_preview, stderr=item.stderr_preview)
        return {
            "attempt": idx,
            "task_id": item.task_id,
            "title": item.title,
            "summary": item.summary,
            "error": item.error,
            "stdout": item.stdout_preview,
            "stderr": item.stderr_preview,
            "solver_code_preview": item.solver_code_preview,
            "failure_class": signal.failure_class,
            "error_fingerprint": signal.error_fingerprint,
            "source": "recovery_memory",
        }

    def _attempt_from_record(
        self,
        record: ExecutionRecord,
        idx: int,
    ) -> dict[str, object]:
        combined = "\n".join(part for part in (record.error, record.summary) if part)
        signal = self._classify_text(idx, combined, stdout="", stderr=combined)
        return {
            "attempt": idx,
            "task_id": record.task_id,
            "summary": record.summary,
            "error": record.error,
            "stdout": "",
            "stderr": combined[:1500],
            "failure_class": signal.failure_class,
            "error_fingerprint": signal.error_fingerprint,
            "source": "recovery_execution_log",
        }

    def _last_failure_signal(self, state: GlobalState) -> SolverFailureSignal:
        memory = list(state.task_type_memory.get("solve.generate_script") or [])
        if memory:
            last = memory[-1]
            combined = "\n".join(
                part
                for part in (
                    last.stderr_preview,
                    last.stdout_preview,
                    last.error,
                    last.summary,
                )
                if part
            )
            return self._classify_text(
                len(memory),
                combined,
                stdout=last.stdout_preview,
                stderr=last.stderr_preview or combined,
                previous_solver_code=last.solver_code_preview,
            )
        for record in reversed(state.execution_log):
            if record.worker_name == "solver-agent" and not record.success:
                combined = "\n".join(part for part in (record.error, record.summary) if part)
                return self._classify_text(
                    self._solver_failure_streak(state),
                    combined,
                    stdout="",
                    stderr=combined,
                )
        return SolverFailureSignal(
            failure_class="solver_streak_no_progress",
            error_fingerprint="solver failure streak without detailed output",
            diagnosis="Solver failed repeatedly without detailed stdout/stderr.",
            must_avoid=["Do not repeat the same broad solver approach."],
            required_checks=["Add explicit diagnostics before attempting decryption or execution."],
        )

    @staticmethod
    def _classify_text(
        attempt: int,
        combined: str,
        *,
        stdout: str,
        stderr: str,
        previous_solver_code: str = "",
    ) -> SolverFailureSignal:
        returncode = _parse_returncode(combined)
        return SolverFailureClassifier.classify(
            attempt=max(1, attempt),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr or combined,
            timeout_s=_parse_timeout(combined),
            near_miss=[],
            previous_solver_code=previous_solver_code,
        )


def _parse_returncode(text: str) -> int:
    match = _EXIT_CODE_RE.search(text)
    if match is not None:
        return int(match.group(1))
    if "timed out" in text.lower() or "timeout" in text.lower():
        return -1
    if "traceback" in text.lower():
        return 1
    return 0


def _parse_timeout(text: str) -> int:
    match = re.search(r"timeout after\s+(\d+)s|timed out after\s+(\d+)s", text, re.IGNORECASE)
    if match is None:
        return 180
    return int(match.group(1) or match.group(2))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        value = str(item).strip()
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
