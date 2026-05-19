"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations

import traceback
from collections.abc import Callable, Iterable

from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.planning import PlannerAgent
from killchain_docker.orchestrator.policy import RoundOutcomePolicy
from killchain_docker.orchestrator.router import RouterAgent, WorkerDirectory
from killchain_docker.state import (
    RouterDecision,
    RouterRound,
    RunState,
    RunStatus,
    TodoItem,
    TodoStatus,
    WorkerResult,
)
from killchain_docker.state.models import utc_now
from killchain_docker.workers.base import WorkerAgent


class Orchestrator:
    """Run the planner-router-worker loop for one assessment."""

    MAX_CONSECUTIVE_EMPTY_ROUNDS = 4
    FORCED_PIVOT_THRESHOLD = 5  # Rounds without flag progress triggers pivot
    MAX_TRANSIENT_SKIPS = 3  # Transient LLM errors to tolerate before aborting

    def __init__(
        self,
        state: RunState,
        workers: Iterable[WorkerAgent],
        *,
        planner: PlannerAgent | None = None,
        router: RouterAgent | None = None,
        emit: Callable[[str], None] = print,
        checkpoint_callback: Callable[[RunState], None] | None = None,
    ) -> None:
        self.state = state
        if planner is None:
            raise LLMClientError("Orchestrator requires an LLM planner; planner-less execution is disabled.")
        if router is None:
            raise LLMClientError("Orchestrator requires a router; router-less execution is disabled.")
        self.workers = list(workers)
        self.worker_directory = WorkerDirectory.from_workers(self.workers)
        self.planner = planner
        self.router = router
        self.emit = emit
        self.checkpoint_callback = checkpoint_callback
        self._consecutive_empty_rounds = 0
        self._rounds_without_progress = 0
        self._pivot_count = 0
        self._transient_skip_count = 0

    def _checkpoint(self) -> None:
        if self.checkpoint_callback is None:
            return
        try:
            self.checkpoint_callback(self.state)
        except Exception as exc:
            self.emit(f"[checkpoint] failed to persist state: {type(exc).__name__}: {exc}")

    def refresh_plan(self, cycle: int) -> tuple[bool, str]:
        decision = self.planner.plan(self.state)
        created = 0
        for planned_todo in decision.todos:
            todo = planned_todo.to_todo()
            queued = self.state.queue_todo(todo)
            if queued.todo_id == todo.todo_id:
                created += 1
        if decision.notes:
            self.state.orchestration_notes.extend(decision.notes)
            self.state.touch()
        proposed = len(decision.todos)
        deduped = proposed - created
        summary = decision.summary or "(no summary)"
        self.emit(
            f"[cycle {cycle}] plan: proposed={proposed} new={created} "
            f"deduped={deduped} stop_run={decision.stop_run} - {summary[:200]}"
        )
        return decision.stop_run, summary

    def route(self, cycle: int) -> RouterDecision:
        return self.router.route(
            self.state,
            worker_directory=self.worker_directory,
            max_assignments=5,
        )

    def select_worker(self, todo: TodoItem, worker_name: str) -> tuple[WorkerAgent | None, str]:
        return self.worker_directory.select(worker_name, todo, self.state)

    def _run_assignment(self, cycle: int, todo: TodoItem, worker: WorkerAgent) -> WorkerResult:
        todo.mark_running(worker.name)
        self.emit(f"[cycle {cycle}] dispatch {todo.todo_id} -> {worker.name}")
        try:
            return worker.run(todo, self.state)
        except LLMClientError as exc:
            if exc.transient:
                todo.release_after_transient_error(str(exc))
                raise
            raise
        except Exception as exc:
            tb_text = traceback.format_exc(limit=20)
            self.emit(
                f"[cycle {cycle}] UNHANDLED EXCEPTION in {worker.name} "
                f"while executing {todo.todo_id}: {type(exc).__name__}: {exc}"
            )
            return WorkerResult(
                todo_id=todo.todo_id,
                worker_name=worker.name,
                success=False,
                summary=f"{worker.name} raised {type(exc).__name__}: {exc}",
                error=tb_text,
                retryable=False,
            )

    def _skip_transient_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> bool:
        if not exc.transient or self._transient_skip_count >= self.MAX_TRANSIENT_SKIPS:
            return False
        self._transient_skip_count += 1
        self.emit(
            f"[cycle {cycle}] transient LLM error in {source} "
            f"(skip {self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS}), "
            f"continuing next cycle: {exc}"
        )
        self.state.orchestration_notes.append(
            f"cycle {cycle}: transient LLM error skipped in {source} "
            f"({self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS})"
        )
        self.state.touch()
        return True

    def _summarize_round(self, results: list[WorkerResult]):
        return self.router.summarize_round(self.state, results=results)

    def _has_ready_backlog(self) -> bool:
        return bool(self.state.ready_todos(limit=1))

    def _inject_forced_pivot(self, cycle: int) -> None:
        """Inject a forced pivot directive into state metadata.

        Instead of hard-stopping, this bans stalled families and forces the
        planner to try a fundamentally different attack vector.
        """
        self._pivot_count += 1
        self._rounds_without_progress = 0  # Reset counter after pivot

        pivot_directive = RoundOutcomePolicy.forced_pivot_directive(
            self.state,
            pivot_number=self._pivot_count,
            cycle=cycle,
            threshold=self.FORCED_PIVOT_THRESHOLD,
        )
        banned_families = list(pivot_directive.get("banned_families") or [])
        self.state.metadata["forced_pivot"] = pivot_directive
        self.state.orchestration_notes.append(
            f"cycle {cycle}: forced pivot #{self._pivot_count} — "
            f"banned families: {banned_families}"
        )
        self.emit(
            f"[cycle {cycle}] FORCED PIVOT #{self._pivot_count}: "
            f"banning families {banned_families}"
        )
        self.state.touch()

    def _mark_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> None:
        kind = str(getattr(exc, "kind", "unknown"))
        reason = f"llm_error:{source}:{kind}:{type(exc).__name__}: {exc}"
        self.state.stop_reason = "llm_error"
        self.state.status = RunStatus.FAILED
        self.state.metadata["last_llm_error"] = {
            "cycle": cycle,
            "source": source,
            "kind": kind,
            "transient": bool(getattr(exc, "transient", False)),
            "schema_name": getattr(exc, "schema_name", None),
            "model": getattr(exc, "model", None),
            "attempts": getattr(exc, "attempts", None),
            "message": str(exc),
        }
        self.state.orchestration_notes.append(f"cycle {cycle}: {reason}")
        for todo in self.state.todos:
            if todo.status == TodoStatus.RUNNING:
                todo.mark_failed(reason, retryable=False)
            elif todo.status == TodoStatus.PENDING:
                todo.mark_blocked("llm_error")
        self.state.touch()

    def _block_open_todos(self, reason: str) -> None:
        for todo in self.state.todos:
            if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}:
                todo.mark_blocked(reason)
        self.state.orchestration_notes.append(reason)
        self.state.touch()

    def _terminal_unsolved_reason(self) -> str:
        if any(todo.status == TodoStatus.FAILED for todo in self.state.todos):
            return "todo_failed"
        if any(todo.status == TodoStatus.BLOCKED for todo in self.state.todos):
            return "todo_blocked"
        if any(todo.status == TodoStatus.PARTIAL for todo in self.state.todos):
            return "partial_todos_unsolved"
        if self.state.todos:
            return "unsolved_no_work_remaining"
        return "no_todos_created"

    def _finalize_terminal_state(self, *, max_cycles_exhausted: bool) -> None:
        if max_cycles_exhausted and self.state.has_open_todos():
            self.state.stop_reason = "max_cycles_exhausted"
            self._block_open_todos("max_cycles_exhausted")

        if self.state.solved:
            self.state.status = RunStatus.SOLVED
        elif self.state.status == RunStatus.INTERRUPTED:
            self.state.stop_reason = self.state.stop_reason or "interrupted"
        elif self.state.status == RunStatus.STOPPED:
            self.state.stop_reason = self.state.stop_reason or "planner_stop"
        elif self.state.stop_reason == "llm_error":
            self.state.status = RunStatus.FAILED
        elif self.state.stop_reason == "max_cycles_exhausted":
            self.state.status = RunStatus.FAILED
        elif self.state.stop_reason == "router_no_assignments":
            self.state.status = RunStatus.FAILED
        elif self.state.has_open_todos():
            self.state.stop_reason = self.state.stop_reason or "open_todos_remaining"
            self.state.status = RunStatus.FAILED
        elif any(
            todo.status in {TodoStatus.FAILED, TodoStatus.BLOCKED, TodoStatus.PARTIAL}
            for todo in self.state.todos
        ):
            self.state.stop_reason = self.state.stop_reason or self._terminal_unsolved_reason()
            self.state.status = RunStatus.FAILED
        else:
            reason = self.state.stop_reason or self._terminal_unsolved_reason()
            self.state.stop_reason = reason
            self.state.status = (
                RunStatus.COMPLETED
                if reason == "unsolved_no_work_remaining"
                else RunStatus.FAILED
            )
        self.state.touch()

    def run(self, max_cycles: int = 10) -> RunState:
        self.state.status = RunStatus.RUNNING
        max_cycles_exhausted = True
        current_cycle = 0

        try:
            for cycle in range(1, max_cycles + 1):
                current_cycle = cycle
                if self.state.solved:
                    self.emit(f"[cycle {cycle}] validated flag found - halting run")
                    max_cycles_exhausted = False
                    break
                self.state.last_cycle_at = utc_now()

                planner_summary = "planner skipped: ready todo backlog"
                if self._has_ready_backlog():
                    self.emit(f"[cycle {cycle}] planner skipped - ready todo backlog")
                else:
                    try:
                        planner_stop, planner_summary = self.refresh_plan(cycle)
                        if planner_stop and (self.state.solved or not self.state.has_open_todos()):
                            self.emit(f"[cycle {cycle}] planner signalled stop - halting run")
                            self.state.status = RunStatus.STOPPED
                            self.state.stop_reason = "planner_stop"
                            self._checkpoint()
                            max_cycles_exhausted = False
                            break
                    except LLMClientError as exc:
                        if self._skip_transient_llm_error(cycle, "planner", exc):
                            self._checkpoint()
                            continue
                        self.emit(f"[cycle {cycle}] planner LLM error - aborting run")
                        self._mark_llm_error(cycle, "planner", exc)
                        self._checkpoint()
                        max_cycles_exhausted = False
                        raise

                try:
                    decision = self.route(cycle)
                except LLMClientError as exc:
                    if self._skip_transient_llm_error(cycle, "router", exc):
                        self._checkpoint()
                        continue
                    self.emit(f"[cycle {cycle}] router LLM error - aborting run")
                    self._mark_llm_error(cycle, "router", exc)
                    self._checkpoint()
                    max_cycles_exhausted = False
                    raise
                if not decision.assignments:
                    self._consecutive_empty_rounds += 1
                    self.emit(f"[cycle {cycle}] router selected no assignments")
                    self._checkpoint()
                    if self._consecutive_empty_rounds >= self.MAX_CONSECUTIVE_EMPTY_ROUNDS:
                        self.state.stop_reason = "router_no_assignments"
                        self._block_open_todos("router_no_assignments")
                        max_cycles_exhausted = False
                        break
                    continue
                self._consecutive_empty_rounds = 0

                results: list[WorkerResult] = []
                executed_assignments = []
                transient_worker_skip = False
                for assignment in decision.assignments:
                    if self.state.solved:
                        break
                    todo = self.state.get_todo(assignment.todo_id)
                    if todo is None:
                        self.state.orchestration_notes.append(
                            f"cycle {cycle}: assignment referenced unknown todo {assignment.todo_id}"
                        )
                        continue
                    if todo.status != TodoStatus.PENDING:
                        continue
                    worker, reason = self.select_worker(todo, assignment.worker_name)
                    if worker is None:
                        todo.mark_blocked(reason)
                        results.append(
                            WorkerResult(
                                todo_id=todo.todo_id,
                                worker_name=assignment.worker_name,
                                success=False,
                                summary=f"Assignment blocked: {reason}",
                                error=reason,
                                retryable=False,
                            )
                        )
                        self.emit(f"[cycle {cycle}] blocked {todo.todo_id}: {reason}")
                        continue
                    executed_assignments.append(assignment)
                    try:
                        result = self._run_assignment(cycle, todo, worker)
                    except LLMClientError as exc:
                        if self._skip_transient_llm_error(cycle, worker.name, exc):
                            transient_worker_skip = True
                            break
                        self.emit(f"[cycle {cycle}] worker LLM error - aborting run")
                        self._mark_llm_error(cycle, worker.name, exc)
                        self._checkpoint()
                        max_cycles_exhausted = False
                        raise
                    if RoundOutcomePolicy.is_hollow_result(result):
                        result.partial = True
                        result.partial_reason = (
                            result.partial_reason
                            or "worker reported success but produced no meaningful output"
                        )
                        self.emit(f"[cycle {cycle}] hollow result downgraded to PARTIAL: {todo.todo_id}")
                    self.state.apply_worker_result(result)
                    results.append(result)
                    status_tag = "PARTIAL" if result.partial else ("ok" if result.success else "FAILED")
                    self.emit(f"[cycle {cycle}] {status_tag} {todo.todo_id}: {result.summary}")
                    if self.state.solved:
                        self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                        break

                if transient_worker_skip:
                    self._checkpoint()
                    continue

                try:
                    round_summary = self._summarize_round(results)
                except LLMClientError as exc:
                    if self._skip_transient_llm_error(cycle, "round_summarizer", exc):
                        self._checkpoint()
                        continue
                    self.emit(f"[cycle {cycle}] round summarizer LLM error - aborting run")
                    self._mark_llm_error(cycle, "round_summarizer", exc)
                    self._checkpoint()
                    max_cycles_exhausted = False
                    raise
                self.state.record_round(
                    RouterRound(
                        cycle=cycle,
                        planner_summary=planner_summary,
                        assignments=executed_assignments,
                        results=results,
                        summary=round_summary,
                    )
                )
                self.emit(f"[cycle {cycle}] router summary: {round_summary.summary[:240]}")

                # Forced Pivot: track rounds without meaningful progress
                if RoundOutcomePolicy.had_meaningful_progress(results):
                    self._rounds_without_progress = 0
                    self.state.metadata.pop("forced_pivot", None)
                else:
                    self._rounds_without_progress += 1

                if self._rounds_without_progress >= self.FORCED_PIVOT_THRESHOLD:
                    self._inject_forced_pivot(cycle)

                self._checkpoint()
                if self.state.solved:
                    max_cycles_exhausted = False
                    break
        except LLMClientError as exc:
            if self.state.stop_reason != "llm_error":
                self.emit(f"[cycle {current_cycle}] LLM error - aborting run")
                self._mark_llm_error(current_cycle, "runtime", exc)
                self._checkpoint()
            max_cycles_exhausted = False
            raise
        except (KeyboardInterrupt, SystemExit) as exc:
            reason = f"run interrupted by {type(exc).__name__}"
            self.state.interrupt_running_todos(reason)
            self.state.status = RunStatus.INTERRUPTED
            self.state.stop_reason = "interrupted"
            self.state.orchestration_notes.append(reason)
            self.emit(f"[interrupt] {reason}; marked running todos as interrupted")
            self._checkpoint()

        self._finalize_terminal_state(max_cycles_exhausted=max_cycles_exhausted)
        return self.state
