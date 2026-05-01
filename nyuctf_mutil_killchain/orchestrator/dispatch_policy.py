"""Dispatch policy helpers for orchestrator task execution.

Responsibilities (only these):
- Validate task context (asset_id reference must exist in state.assets)
- Conservative context repair (fill missing required keys from challenge_files / assets)
- Ready-task batch selection (priority order, capped per type prefix per cycle)

No suppression, no capping, no retry decisions.  Those are LLM concerns.
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


class DispatchPolicy:
    """Encapsulates deterministic dispatch behavior for the orchestrator."""

    _BATCHABLE_TASK_TYPES = frozenset({"flag.validate"})
    # Cap flag.validate fan-out per cycle.  Even after upstream filters (shape
    # check at task-creation time, top-N cap inside the solver agent), a
    # creative LLM planner can still propose many validations after a single
    # solver run.  3 is enough to confirm the most-likely candidate without
    # spinning the whole cycle on negative confirmations.
    _MAX_BATCHABLE_PER_CYCLE = 3
    _MAX_PER_PREFIX_PER_CYCLE = 2

    # Anti-spin: when this many flag.validate tasks have run consecutively
    # without a single one returning ``solved=True``, stop dispatching new
    # validations until at least one non-validate task makes progress.
    # Otherwise the planner happily refills the queue with shape-rejected
    # noise it harvested from solver findings.
    _VALIDATION_FAILURE_STREAK_LIMIT = 5

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

    def dequeue_batch(self, state: GlobalState, *, max_batch: int = 6) -> list[Task]:
        """Dequeue up to *max_batch* independent ready tasks in priority order.

        At most :attr:`_MAX_PER_PREFIX_PER_CYCLE` non-batchable tasks share the
        same prefix per cycle (e.g. two ``solve.*`` tasks can run concurrently
        when the queue is solver-heavy), so accumulated planner proposals don't
        starve and the cycle budget is actually consumed.

        When the recent execution log shows a long streak of failed
        ``flag.validate`` tasks (a sign that the planner is filling the queue
        with shape-rejected noise harvested from solver findings), stop
        accepting more validations until non-validate work makes progress.
        """
        completed = state.task_chain.completed_task_ids()
        ready = [t for t in state.task_chain.tasks if t.is_ready(completed)]
        ready.sort(key=lambda t: (-t.priority, t.created_at))

        suppress_validates = self._validation_streak_too_long(state)

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
                if prefix_counts[prefix] >= self._MAX_PER_PREFIX_PER_CYCLE:
                    continue
                prefix_counts[prefix] += 1
            batch.append(task)
            non_batchable = len(batch) - batchable_count
            if non_batchable >= max_batch:
                break

        return batch

    def _validation_streak_too_long(self, state: GlobalState) -> bool:
        """Return True if the recent execution log is dominated by failed validates.

        Walk backwards through the execution log: every failed-validation
        record (``flag-validation-agent`` + the run flag is still unset)
        contributes to the streak; the first non-validation record resets it.
        Once that streak hits the configured limit we suppress further
        ``flag.validate`` dispatch this cycle so a noisy planner can't keep
        refilling the queue with already-rejected candidates.
        """
        limit = self._VALIDATION_FAILURE_STREAK_LIMIT
        if limit <= 0 or state.solved:
            return False
        streak = 0
        for record in reversed(state.execution_log):
            if record.worker_name != "flag-validation-agent":
                return False
            streak += 1
            if streak >= limit:
                self.emit(
                    f"[dispatch] suppressing flag.validate this cycle: "
                    f"{streak} consecutive validations recorded without "
                    f"solver/planner progress"
                )
                return True
        return False
