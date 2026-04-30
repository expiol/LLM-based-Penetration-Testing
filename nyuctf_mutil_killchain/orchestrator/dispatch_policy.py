"""Dispatch policy helpers for orchestrator task execution.

Responsibilities (only these):
- Validate task context (asset_id reference must exist in state.assets)
- Conservative context repair (fill missing required keys from challenge_files / assets)
- Ready-task batch selection (priority order, one task per type prefix per cycle)

No suppression, no capping, no retry decisions.  Those are LLM concerns.
"""

from __future__ import annotations

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
    _MAX_BATCHABLE_PER_CYCLE = 8

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

    def dequeue_batch(self, state: GlobalState, *, max_batch: int = 4) -> list[Task]:
        """Dequeue up to *max_batch* independent ready tasks in priority order."""
        completed = state.task_chain.completed_task_ids()
        ready = [t for t in state.task_chain.tasks if t.is_ready(completed)]
        ready.sort(key=lambda t: (-t.priority, t.created_at))

        batch: list[Task] = []
        seen_type_prefixes: set[str] = set()
        batchable_count = 0
        for task in ready:
            prefix = task.task_type.split(".")[0]
            if task.task_type in self._BATCHABLE_TASK_TYPES:
                if batchable_count >= self._MAX_BATCHABLE_PER_CYCLE:
                    continue
                batchable_count += 1
            else:
                if prefix in seen_type_prefixes:
                    continue
                seen_type_prefixes.add(prefix)
            batch.append(task)
            non_batchable = len(batch) - batchable_count
            if non_batchable >= max_batch:
                break

        return batch
