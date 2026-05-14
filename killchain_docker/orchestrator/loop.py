"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations

import traceback
from collections.abc import Callable, Iterable

from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.planning import BootstrapSeeder, TaskPlanner
from killchain_docker.orchestrator.router import RouterAgent
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

    MAX_CONSECUTIVE_PLANNER_ERRORS = 3
    MAX_CONSECUTIVE_EMPTY_ROUNDS = 2

    def __init__(
        self,
        state: RunState,
        workers: Iterable[WorkerAgent],
        *,
        planner: TaskPlanner | None = None,
        router: RouterAgent | None = None,
        emit: Callable[[str], None] = print,
        checkpoint_callback: Callable[[RunState], None] | None = None,
    ) -> None:
        self.state = state
        self.workers = list(workers)
        self.planner = planner or BootstrapSeeder()
        self.router = router
        self.emit = emit
        self.checkpoint_callback = checkpoint_callback
        self._consecutive_planner_errors = 0
        self._consecutive_empty_rounds = 0

    def _checkpoint(self) -> None:
        if self.checkpoint_callback is None:
            return
        try:
            self.checkpoint_callback(self.state)
        except Exception as exc:
            self.emit(f"[checkpoint] failed to persist state: {type(exc).__name__}: {exc}")

    def _worker_catalog(self) -> list[dict[str, object]]:
        return [
            {
                "name": worker.name,
                "routing_summary": worker.routing_summary,
                "required_context_keys": list(worker.required_context_keys),
                "preferred_challenge_categories": list(worker.preferred_challenge_categories),
            }
            for worker in self.workers
        ]

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
        if self.router is None:
            return self._fallback_route()
        try:
            return self.router.route(
                self.state,
                worker_catalog=self._worker_catalog(),
                max_assignments=5,
            )
        except LLMClientError as exc:
            self.state.orchestration_notes.append(
                f"cycle {cycle}: router {type(exc).__name__}: {exc}; fallback route used."
            )
            return self._fallback_route()

    def _fallback_route(self) -> RouterDecision:
        from killchain_docker.state import WorkerAssignment

        ready = self.state.ready_todos(limit=1)
        if not ready:
            return RouterDecision(rationale="No ready todos.")
        todo = ready[0]
        worker_name = self._fallback_worker_name(todo)
        return RouterDecision(
            assignments=[
                WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name=worker_name,
                    rationale="Deterministic fallback route.",
                )
            ],
            rationale="Router unavailable or failed.",
        )

    def _fallback_worker_name(self, todo: TodoItem) -> str:
        goal = todo.goal.lower()
        context = todo.context
        preferred = "artifact-worker"
        if "candidate_flag" in context or "flag" in goal:
            preferred = "flag-worker"
        elif "scope" in context or "recon" in goal:
            preferred = "recon-worker"
        elif "base_url" in context or "path" in goal or "web" in goal or "http" in goal:
            preferred = "web-worker"
        elif "exploit" in goal or "vuln" in goal or "credential" in goal:
            preferred = "exploit-worker"
        if any(worker.name == preferred for worker in self.workers):
            return preferred
        return self.workers[0].name if self.workers else ""

    def select_worker(self, todo: TodoItem, worker_name: str) -> tuple[WorkerAgent | None, str]:
        worker = next((item for item in self.workers if item.name == worker_name), None)
        if worker is None:
            return None, f"router selected unknown worker {worker_name!r}"
        allowed, reason = worker.can_route_task(todo, self.state)
        if not allowed:
            return None, reason or "worker rejected todo"
        return worker, ""

    def _run_assignment(self, cycle: int, todo: TodoItem, worker: WorkerAgent) -> WorkerResult:
        todo.mark_running(worker.name)
        self.emit(f"[cycle {cycle}] dispatch {todo.todo_id} -> {worker.name}")
        try:
            return worker.run(todo, self.state)
        except LLMClientError as exc:
            return WorkerResult(
                todo_id=todo.todo_id,
                worker_name=worker.name,
                success=False,
                summary=f"{worker.name} raised LLMClientError; planner should re-evaluate.",
                error=str(exc),
                retryable=False,
            )
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

    def _summarize_round(self, results: list[WorkerResult]):
        if self.router is not None:
            try:
                return self.router.summarize_round(self.state, results=results)
            except LLMClientError as exc:
                self.state.orchestration_notes.append(
                    f"router summary failed: {type(exc).__name__}: {exc}"
                )
        from killchain_docker.state import RouterRoundSummary

        lines = [f"{result.worker_name}: {result.summary}" for result in results]
        return RouterRoundSummary(
            summary="; ".join(lines) if lines else "No worker results.",
            direct_results=lines,
            key_findings=[result.summary for result in results if result.success][:8],
            used_llm=False,
        )

    def run(self, max_cycles: int = 10) -> RunState:
        self.state.status = RunStatus.RUNNING

        for cycle in range(1, max_cycles + 1):
            if self.state.solved:
                self.emit(f"[cycle {cycle}] validated flag found - halting run")
                break
            self.state.last_cycle_at = utc_now()

            planner_summary = ""
            try:
                planner_stop, planner_summary = self.refresh_plan(cycle)
                self._consecutive_planner_errors = 0
                if planner_stop and (self.state.solved or not self.state.has_open_todos()):
                    self.emit(f"[cycle {cycle}] planner signalled stop - halting run")
                    self.state.status = RunStatus.STOPPED
                    self._checkpoint()
                    break
            except LLMClientError as exc:
                self._consecutive_planner_errors += 1
                self.state.orchestration_notes.append(
                    f"cycle {cycle}: planner {type(exc).__name__} "
                    f"(consecutive={self._consecutive_planner_errors}): {exc}"
                )
                if self._consecutive_planner_errors >= self.MAX_CONSECUTIVE_PLANNER_ERRORS:
                    self.emit(f"[cycle {cycle}] planner error limit reached - stopping")
                    self.state.status = RunStatus.STOPPED
                    self._checkpoint()
                    break

            decision = self.route(cycle)
            if not decision.assignments:
                self._consecutive_empty_rounds += 1
                self.emit(f"[cycle {cycle}] router selected no assignments")
                self._checkpoint()
                if self._consecutive_empty_rounds >= self.MAX_CONSECUTIVE_EMPTY_ROUNDS:
                    break
                continue
            self._consecutive_empty_rounds = 0

            results: list[WorkerResult] = []
            executed_assignments = []
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
                    self.emit(f"[cycle {cycle}] blocked {todo.todo_id}: {reason}")
                    continue
                executed_assignments.append(assignment)
                result = self._run_assignment(cycle, todo, worker)
                self.state.apply_worker_result(result)
                results.append(result)
                status_tag = "ok" if result.success else "FAILED"
                self.emit(f"[cycle {cycle}] {status_tag} {todo.todo_id}: {result.summary}")
                if self.state.solved:
                    self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                    break

            round_summary = self._summarize_round(results)
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
            self._checkpoint()
            if self.state.solved:
                break

        if self.state.solved:
            self.state.status = RunStatus.SOLVED
        elif self.state.status == RunStatus.STOPPED:
            pass
        elif self.state.has_open_todos():
            self.state.status = RunStatus.STOPPED
        elif any(todo.status == TodoStatus.FAILED for todo in self.state.todos):
            self.state.status = RunStatus.FAILED
        else:
            self.state.status = RunStatus.COMPLETED
        return self.state
