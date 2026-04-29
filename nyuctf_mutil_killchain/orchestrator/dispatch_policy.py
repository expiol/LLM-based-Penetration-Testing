"""Dispatch policy helpers for orchestrator task execution.

This module isolates pre-dispatch concerns from the orchestrator main loop:
- task context validation
- conservative context repair
- ready-task batch selection policy
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Task, TaskErrorCode, TaskStatus
from nyuctf_mutil_killchain.state.constants import SOURCE_EXTENSIONS as _SOURCE_EXTS

_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"
_PCAP_EXTS = frozenset({".pcap", ".pcapng", ".cap"})
_DB_EXTS = frozenset({".db", ".sqlite", ".sqlite3"})
_ARCHIVE_EXTS = frozenset({".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".xz"})


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

    _MAX_BLOCKED_PER_TASK_TYPE = 3

    def validate_task_for_dispatch(self, task: Task, state: GlobalState) -> DispatchValidation:
        """Validate that context references required for dispatch are consistent."""
        ctx_asset_id = task.input_context.get("asset_id")
        if ctx_asset_id and ctx_asset_id not in state.assets and not task.task_type.startswith("recon."):
            return DispatchValidation(
                valid=False,
                reason=f"asset_id {ctx_asset_id!r} not found in state.assets",
                error_code=TaskErrorCode.UNKNOWN_ASSET_ID,
            )

        # Suppress tasks whose type has been blocked too many times this run.
        blocked_count = sum(
            1 for t in state.task_chain.tasks
            if t.task_type == task.task_type and t.status == TaskStatus.BLOCKED
        )
        if blocked_count >= self._MAX_BLOCKED_PER_TASK_TYPE:
            return DispatchValidation(
                valid=False,
                reason=(
                    f"task type {task.task_type!r} already blocked {blocked_count} time(s); "
                    f"suppressing further attempts"
                ),
                error_code=TaskErrorCode.DISPATCH_REFUSED,
            )

        return DispatchValidation(valid=True)

    def try_repair_task_context(
        self,
        task: Task,
        state: GlobalState,
        candidates: list[WorkerAgent],
    ) -> bool:
        """Attempt conservative context repair for missing required fields."""
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
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])

        if challenge_files:
            if "files_root" in missing:
                ctx["files_root"] = _DEFAULT_FILES_ROOT
                self.emit(f"[repair] {task.task_id}: filled files_root={_DEFAULT_FILES_ROOT}")
                repaired = True

            if "source_files" in missing:
                inferred = [
                    f for f in challenge_files
                    if "." in f and ("." + f.rsplit(".", 1)[-1].lower()) in _SOURCE_EXTS
                ]
                ctx["source_files"] = inferred or challenge_files
                self.emit(f"[repair] {task.task_id}: filled source_files ({len(ctx['source_files'])} file(s))")
                repaired = True

            if "binary_files" in missing:
                ctx["binary_files"] = [
                    f for f in challenge_files
                    if "." not in f
                    or ("." + f.rsplit(".", 1)[-1].lower()) not in _SOURCE_EXTS
                ]
                self.emit(f"[repair] {task.task_id}: filled binary_files ({len(ctx['binary_files'])} file(s))")
                repaired = True

            if "pcap_files" in missing:
                inferred = [
                    f for f in challenge_files
                    if "." in f and ("." + f.rsplit(".", 1)[-1].lower()) in _PCAP_EXTS
                ]
                if inferred:
                    ctx["pcap_files"] = inferred
                    self.emit(f"[repair] {task.task_id}: filled pcap_files ({len(inferred)} file(s))")
                    repaired = True

            if "database_files" in missing:
                inferred = [
                    f for f in challenge_files
                    if "." in f and ("." + f.rsplit(".", 1)[-1].lower()) in _DB_EXTS
                ]
                if inferred:
                    ctx["database_files"] = inferred
                    self.emit(f"[repair] {task.task_id}: filled database_files ({len(inferred)} file(s))")
                    repaired = True

            if "archive_files" in missing:
                inferred = [
                    f for f in challenge_files
                    if "." in f and ("." + f.rsplit(".", 1)[-1].lower()) in _ARCHIVE_EXTS
                ]
                if inferred:
                    ctx["archive_files"] = inferred
                    self.emit(f"[repair] {task.task_id}: filled archive_files ({len(inferred)} file(s))")
                    repaired = True

        if "paths" in missing and task.task_type == "web.path_probe":
            # Start with defaults then add paths discovered in findings
            paths = ["/", "/index.php", "/index.html", "/robots.txt", "/flag", "/admin"]
            for finding in state.findings.values():
                meta = finding.metadata or {}
                for key in ("interesting_routes", "interesting_paths"):
                    for path in (meta.get(key) or []):
                        path = str(path).strip()
                        if path and path.startswith("/") and path not in paths:
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
