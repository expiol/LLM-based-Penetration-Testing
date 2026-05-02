"""Dispatch policy helpers for orchestrator task execution.

Responsibilities (only these):
- Validate task context (asset_id reference must exist in state.assets)
- Conservative context repair (fill missing required keys from challenge_files / assets)
- Ready-task batch selection (priority order, capped per task-type prefix).
- Bounded batching / streak-suppression shortcuts that temporarily skip rows
  in the ready-set so stalled workers do not hog the orchestrator cycles.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import (
    FileKind,
    GlobalState,
    Task,
    TaskErrorCode,
    files_by_kind,
)

_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"


@dataclass(frozen=True)
class DispatchValidation:
    valid: bool
    reason: str | None = None
    error_code: TaskErrorCode | None = None


@dataclass(frozen=True)
class DequeueBatchResult:
    """Ready tasks selected for this cycle, plus a starvation guard flag.

    ``withheld_due_to_policy`` distinguishes (a) ``ready`` genuinely empty from
    (b) tasks were ready but every candidate was skipped by caps / streak
    suppression — so the orchestrator should not treat (b) as successive
    idle cycles.
    """

    tasks: list[Task]
    withheld_due_to_policy: bool


class DispatchPolicy:
    """Encapsulates deterministic dispatch behavior for the orchestrator."""

    _BATCHABLE_TASK_TYPES = frozenset({"flag.validate"})
    # Cap flag.validate fan-out per cycle.  Even after upstream filters (shape
    # check at task-creation time, top-N cap inside the solver agent), a
    # creative LLM planner can still propose many validations after a single
    # solver run.  Raised to 5 so a flurry of bracket-span candidates from a
    # single solver run can drain in one cycle.
    _MAX_BATCHABLE_PER_CYCLE = 5

    # Per-prefix cap dict: how many tasks of each ``<prefix>.*`` type can
    # share a cycle.  Default is 2; ``solve`` is pinned to 1 so a single
    # in-flight solver retry chain progresses one attempt per cycle without
    # starving validations / web probes / source review.  Add prefixes here
    # when a class of worker proves "hoggy" in production logs.
    _PER_PREFIX_LIMITS: dict[str, int] = {"solve": 1}
    _DEFAULT_PER_PREFIX_LIMIT = 2

    # Anti-spin: when this many tasks of the same task_type / worker have run
    # consecutively without a single one returning ``solved=True``, stop
    # dispatching more of them this cycle until other work makes progress.
    # Generic for any worker; single-purpose ``flag.validate`` suppression
    # lives in :meth:`_validation_streak_too_long` for backwards readability,
    # but solver / vuln / web workers can also spin and we suppress those
    # uniformly via :meth:`_streak_too_long`.
    _VALIDATION_FAILURE_STREAK_LIMIT = 5
    _SOLVER_FAILURE_STREAK_LIMIT = 4

    # Failure fingerprints surfaced by ``WorkerReport.summary`` that should
    # count toward the solver streak.  These are the dominant fingerprints in
    # ``2013f-cry-stfu`` and ``2013f-web-historypeats`` runs — the LLM keeps
    # producing scripts that exit 0 with empty stdout or exit 0 without any
    # canonical flag candidate.
    _SOLVER_NO_PROGRESS_FINGERPRINTS = (
        "ran without recovering a flag",
        "exit code 1",
        "exit code -1",
    )

    def __init__(self, emit: Callable[[str], None]) -> None:
        self.emit = emit

    def validate_task_for_dispatch(self, task: Task, state: GlobalState) -> DispatchValidation:
        """Check that asset references in *task* point to known state.assets entries."""
        ctx_asset_id = task.input_context.get("asset_id")
        if (
            ctx_asset_id
            and ctx_asset_id not in state.assets
            and not task.task_type.startswith("recon.")
        ):
            return DispatchValidation(
                valid=False,
                reason=f"asset_id {ctx_asset_id!r} not found in state.assets",
                error_code=TaskErrorCode.UNKNOWN_ASSET_ID,
            )
        return DispatchValidation(valid=True)

    def try_repair_task_context(
        self,
        task: Task,
        state: GlobalState,
        candidates: list[WorkerAgent],
    ) -> bool:
        """Fill in missing required-context fields when possible."""
        ctx = task.input_context
        missing: set[str] = set()
        for worker in candidates:
            for key in worker.required_context_keys:
                value = ctx.get(key)
                if value in (None, "", [], {}, ()):
                    missing.add(key)

        if not missing:
            return False

        repaired = False
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files: list[str] = list(challenge_meta.get("files", []) or [])

        if challenge_files:
            kinds = files_by_kind(challenge_files)

            if "files_root" in missing:
                ctx["files_root"] = _DEFAULT_FILES_ROOT
                self.emit(f"[repair] {task.task_id}: filled files_root={_DEFAULT_FILES_ROOT}")
                repaired = True

            if "source_files" in missing:
                inferred = list(kinds.get(FileKind.SOURCE, []))
                ctx["source_files"] = inferred or challenge_files
                self.emit(
                    f"[repair] {task.task_id}: filled source_files "
                    f"({len(ctx['source_files'])} file(s))"
                )
                repaired = True

            if "binary_files" in missing:
                inferred = list(kinds.get(FileKind.BINARY, []))
                if inferred:
                    ctx["binary_files"] = inferred
                    self.emit(
                        f"[repair] {task.task_id}: filled binary_files "
                        f"({len(inferred)} file(s))"
                    )
                    repaired = True

            if "pcap_files" in missing:
                inferred = list(kinds.get(FileKind.PCAP, []))
                if inferred:
                    ctx["pcap_files"] = inferred
                    self.emit(
                        f"[repair] {task.task_id}: filled pcap_files ({len(inferred)} file(s))"
                    )
                    repaired = True

            if "database_files" in missing:
                inferred = list(kinds.get(FileKind.SQLITE, []))
                if inferred:
                    ctx["database_files"] = inferred
                    self.emit(
                        f"[repair] {task.task_id}: filled database_files ({len(inferred)} file(s))"
                    )
                    repaired = True

            if "archive_files" in missing:
                inferred = list(kinds.get(FileKind.ARCHIVE, []))
                if inferred:
                    ctx["archive_files"] = inferred
                    self.emit(
                        f"[repair] {task.task_id}: filled archive_files ({len(inferred)} file(s))"
                    )
                    repaired = True

        if "paths" in missing and task.task_type == "web.path_probe":
            paths = ["/", "/index.php", "/index.html", "/robots.txt", "/flag", "/admin"]
            for finding in state.findings.values():
                meta = finding.metadata or {}
                for key in ("interesting_routes", "interesting_paths"):
                    for path in meta.get(key) or []:
                        path = str(path).strip()
                        if path and path.startswith("/") and ":" not in path and path not in paths:
                            paths.append(path)
            ctx["paths"] = paths[:20]
            self.emit(f"[repair] {task.task_id}: filled paths ({len(ctx['paths'])} path(s))")
            repaired = True

        if "scope" in missing and state.authorized_scope:
            ctx["scope"] = state.authorized_scope[0]
            self.emit(f"[repair] {task.task_id}: filled scope={ctx['scope']}")
            repaired = True

        filled = state.infer_asset_identity(ctx)
        for field_name, field_value in filled.items():
            self.emit(f"[repair] {task.task_id}: filled {field_name}={field_value}")
            repaired = True

        return repaired

    def dequeue_batch(self, state: GlobalState, *, max_batch: int = 6) -> DequeueBatchResult:
        """Dequeue up to *max_batch* independent ready tasks in priority order.

        Each ``<prefix>.*`` task type is capped via :attr:`_PER_PREFIX_LIMITS`
        (defaulting to :attr:`_DEFAULT_PER_PREFIX_LIMIT`) so accumulated
        planner proposals don't starve other work and the cycle budget is
        actually consumed.  ``solve`` is pinned to 1 because solver retry
        chains keep adding new tasks every cycle, and two of them per cycle
        starves validations / web probes (`2013f-cry-stfu` ran cycles 4-20
        with exactly two solver tasks each cycle).

        When the recent execution log shows a long streak of failed tasks of
        the same kind (validates with no progress, solvers with empty stdout,
        etc.), suppress further dispatch of that kind this cycle so the
        planner is forced to diversify.  The suppression event is also
        pushed to ``state.notes`` so the next planner call sees the hint.

        Returns a :class:`DequeueBatchResult` so callers can tell when ready
        tasks exist but were withheld by policy (``withheld_due_to_policy``).
        """
        completed = state.task_chain.completed_task_ids()
        ready = [t for t in state.task_chain.tasks if t.is_ready(completed)]
        ready.sort(key=lambda t: (-t.priority, t.created_at))

        suppress_validates = self._validation_streak_too_long(state)
        suppress_solver = self._solver_streak_too_long(state)
        if suppress_solver:
            state.notes.append(
                "dispatch: solver suppressed this cycle due to a streak of "
                "no-progress runs; propose a non-solver task type next."
            )
        if suppress_validates:
            state.notes.append(
                "dispatch: flag.validate suppressed this cycle due to a streak "
                "of failed validations; propose a different task type."
            )

        batch: list[Task] = []
        prefix_counts: Counter[str] = Counter()
        batchable_count = 0
        for task in ready:
            prefix = task.task_type.split(".")[0]
            if task.task_type in self._BATCHABLE_TASK_TYPES:
                if suppress_validates:
                    continue
                if batchable_count >= self._MAX_BATCHABLE_PER_CYCLE:
                    continue
                batchable_count += 1
            else:
                if suppress_solver and prefix == "solve":
                    continue
                limit = self._PER_PREFIX_LIMITS.get(
                    prefix, self._DEFAULT_PER_PREFIX_LIMIT
                )
                if prefix_counts[prefix] >= limit:
                    continue
                prefix_counts[prefix] += 1
            batch.append(task)
            non_batchable = len(batch) - batchable_count
            if non_batchable >= max_batch:
                break

        withheld = bool(ready) and len(batch) == 0
        return DequeueBatchResult(tasks=batch, withheld_due_to_policy=withheld)

    def _validation_streak_too_long(self, state: GlobalState) -> bool:
        """Return True if the recent execution log is dominated by failed validates."""
        return self._streak_too_long(
            state,
            worker_name="flag-validation-agent",
            limit=self._VALIDATION_FAILURE_STREAK_LIMIT,
            kind="flag.validate",
        )

    def _solver_streak_too_long(self, state: GlobalState) -> bool:
        """Return True if the recent execution log shows the solver-agent spinning.

        We treat a solver run as "no progress" when its summary contains one
        of :attr:`_SOLVER_NO_PROGRESS_FINGERPRINTS`.  Once that streak hits
        the configured limit we drop new ``solve.*`` dispatches for one
        cycle so the planner has to propose a different task type (web
        probe, computation analysis, etc.).
        """
        limit = self._SOLVER_FAILURE_STREAK_LIMIT
        if limit <= 0 or state.solved:
            return False
        streak = 0
        for record in reversed(state.execution_log):
            if record.worker_name != "solver-agent":
                return False
            summary = (record.summary or "").lower()
            if not any(fp in summary for fp in self._SOLVER_NO_PROGRESS_FINGERPRINTS):
                return False
            streak += 1
            if streak >= limit:
                self.emit(
                    f"[dispatch] suppressing solve.* this cycle: "
                    f"{streak} consecutive no-progress solver runs"
                )
                return True
        return False

    def _streak_too_long(
        self,
        state: GlobalState,
        *,
        worker_name: str,
        limit: int,
        kind: str,
    ) -> bool:
        """Generic anti-spin: ``limit`` consecutive failures from *worker_name*.

        Walks the execution log backwards: every failed record from the
        target worker contributes to the streak, the first record from a
        *different* worker resets it (i.e. resets when other progress is
        made).  Once the streak hits ``limit`` we emit a debug note and
        return True so the caller can suppress that work for the cycle.
        """
        if limit <= 0 or state.solved:
            return False
        streak = 0
        for record in reversed(state.execution_log):
            if record.worker_name != worker_name:
                return False
            streak += 1
            if streak >= limit:
                self.emit(
                    f"[dispatch] suppressing {kind} this cycle: "
                    f"{streak} consecutive {worker_name} records without progress"
                )
                return True
        return False
