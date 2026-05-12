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
from typing import Any, Callable

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

    # Anti-spin: when this many validations have run consecutively without
    # progress, skip more validation tasks for the current cycle.  Solver
    # recovery is handled by orchestrator.recovery.RecoveryPolicy; dispatch
    # no longer reads RAG state or suppresses solve.* tasks.
    _VALIDATION_FAILURE_STREAK_LIMIT = 5

    def __init__(
        self,
        emit: Callable[[str], None],
    ) -> None:
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
        """Fill in missing required-context fields when possible.

        Each repair is recorded both via :meth:`emit` (for live logs) and on
        ``task.metadata["_repaired_fields"]`` so workers / downstream
        debugging can tell which fields the orchestrator inferred vs which
        ones the planner supplied.
        """
        ctx = task.input_context
        missing: set[str] = set()
        for worker in candidates:
            for key in worker.required_context_keys:
                value = ctx.get(key)
                if value in (None, "", [], {}, ()):
                    missing.add(key)

        if not missing:
            return False

        repaired_fields: list[dict[str, Any]] = []

        def _record(field: str, summary: str) -> None:
            repaired_fields.append({"field": field, "summary": summary})
            self.emit(f"[repair] {task.task_id}: filled {summary}")

        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files: list[str] = list(challenge_meta.get("files", []) or [])

        if challenge_files:
            kinds = files_by_kind(challenge_files)

            if "files_root" in missing:
                ctx["files_root"] = _DEFAULT_FILES_ROOT
                _record("files_root", f"files_root={_DEFAULT_FILES_ROOT}")

            if "source_files" in missing:
                inferred = list(kinds.get(FileKind.SOURCE, []))
                ctx["source_files"] = inferred or challenge_files
                _record(
                    "source_files",
                    f"source_files ({len(ctx['source_files'])} file(s))",
                )

            if "binary_files" in missing:
                inferred = list(kinds.get(FileKind.BINARY, []))
                if inferred:
                    ctx["binary_files"] = inferred
                    _record(
                        "binary_files",
                        f"binary_files ({len(inferred)} file(s))",
                    )

            if "pcap_files" in missing:
                inferred = list(kinds.get(FileKind.PCAP, []))
                if inferred:
                    ctx["pcap_files"] = inferred
                    _record(
                        "pcap_files",
                        f"pcap_files ({len(inferred)} file(s))",
                    )

            if "database_files" in missing:
                inferred = list(kinds.get(FileKind.SQLITE, []))
                if inferred:
                    ctx["database_files"] = inferred
                    _record(
                        "database_files",
                        f"database_files ({len(inferred)} file(s))",
                    )

            if "archive_files" in missing:
                inferred = list(kinds.get(FileKind.ARCHIVE, []))
                if inferred:
                    ctx["archive_files"] = inferred
                    _record(
                        "archive_files",
                        f"archive_files ({len(inferred)} file(s))",
                    )

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
            _record("paths", f"paths ({len(ctx['paths'])} path(s))")

        if "scope" in missing and state.authorized_scope:
            ctx["scope"] = state.authorized_scope[0]
            _record("scope", f"scope={ctx['scope']}")

        filled = state.infer_asset_identity(ctx)
        for field_name, field_value in filled.items():
            _record(field_name, f"{field_name}={field_value}")

        if repaired_fields:
            # Append so multiple repair passes in one run accumulate rather
            # than overwrite.  Workers that care can read this off
            # ``task.metadata`` without scanning events.log.
            prior = list(task.metadata.get("_repaired_fields") or [])
            task.metadata["_repaired_fields"] = prior + repaired_fields
            return True
        return False

    def dequeue_batch(self, state: GlobalState, *, max_batch: int = 6) -> DequeueBatchResult:
        """Dequeue up to *max_batch* independent ready tasks in priority order.

        Each ``<prefix>.*`` task type is capped via :attr:`_PER_PREFIX_LIMITS`
        (defaulting to :attr:`_DEFAULT_PER_PREFIX_LIMIT`) so accumulated
        planner proposals don't starve other work and the cycle budget is
        actually consumed.  ``solve`` is pinned to 1 because solver retry
        chains keep adding new tasks every cycle, and two of them per cycle
        starves validations / web probes (`2013f-cry-stfu` ran cycles 4-20
        with exactly two solver tasks each cycle).

        When the recent execution log shows a long streak of failed
        validations, suppress further validation dispatch this cycle.  Solver
        streaks are intentionally not handled here; high-confidence RAG
        recovery is an explicit task-generation policy.

        Returns a :class:`DequeueBatchResult` so callers can tell when ready
        tasks exist but were withheld by policy (``withheld_due_to_policy``).
        """
        completed = state.task_chain.completed_task_ids()
        ready = [t for t in state.task_chain.tasks if t.is_ready(completed)]
        ready.sort(key=lambda t: (-t.priority, t.created_at))

        suppress_validates = self._validation_streak_too_long(state)
        if suppress_validates:
            state.orchestration_notes.append(
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

    def _streak_too_long(
        self,
        state: GlobalState,
        *,
        worker_name: str,
        limit: int,
        kind: str,
    ) -> bool:
        """Generic anti-spin: ``limit`` consecutive failures from *worker_name*.

        Records from *other* workers are skipped (not used to reset the
        streak) — that way unrelated probes / source-reviews running on the
        same cycle don't mask the fact that the target worker is stuck.  A
        successful record from *worker_name* DOES reset the streak.
        """
        if limit <= 0 or state.solved:
            return False
        streak = self._count_no_progress_streak(
            state,
            worker_name=worker_name,
            fingerprints=(),
            require_fingerprint=False,
        )
        if streak >= limit:
            self.emit(
                f"[dispatch] suppressing {kind} this cycle: "
                f"{streak} consecutive {worker_name} records without progress"
            )
            return True
        return False

    @staticmethod
    def _count_no_progress_streak(
        state: GlobalState,
        *,
        worker_name: str,
        fingerprints: tuple[str, ...],
        require_fingerprint: bool,
    ) -> int:
        """Walk ``state.execution_log`` backwards, counting failed *worker_name* records.

        Records from *other* workers are SKIPPED (do not reset the streak) so
        unrelated workers running in the same cycle do not mask a stuck
        worker.  A *successful* record from *worker_name* resets the streak.
        When ``require_fingerprint`` is True, the record's
        ``summary`` / ``error`` text must contain at least one of the
        provided ``fingerprints`` for it to count.
        """
        streak = 0
        for record in reversed(state.execution_log):
            if record.worker_name != worker_name:
                continue
            if record.success:
                return 0
            if require_fingerprint:
                blob = " ".join(
                    part for part in (record.summary, record.error) if part
                ).lower()
                if not any(fp in blob for fp in fingerprints):
                    continue
            streak += 1
        return streak
