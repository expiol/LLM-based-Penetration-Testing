"""Orchestrator loop — observe/plan/dispatch/fold cycle with production error handling."""

from __future__ import annotations

import traceback
from collections.abc import Callable, Iterable

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClientError
from nyuctf_mutil_killchain.orchestrator.dispatch_policy import DispatchPolicy
from nyuctf_mutil_killchain.orchestrator.planning import BootstrapSeeder, TaskPlanner
from nyuctf_mutil_killchain.orchestrator.router import (
    WorkerRouteDecision,
    WorkerRouter,
)
from nyuctf_mutil_killchain.state import GlobalState, RunStatus, Task, TaskErrorCode, TaskStatus, WorkerReport
from nyuctf_mutil_killchain.state.models import utc_now


class Orchestrator:
    """Observe state, pick the next task, route it to a worker, and fold results back in.

    Each cycle:
      1. Re-plan — planner proposes new tasks based on current state.
      2. Dequeue — pick the highest-priority ready task.
      3. Dispatch — route to the appropriate worker agent.
      4. Fold — apply the WorkerReport back to GlobalState.

    If a worker raises an unhandled exception the task is marked FAILED (with full
    traceback stored as the error) and the run continues so remaining tasks are not lost.
    """

    def __init__(
        self,
        state: GlobalState,
        workers: Iterable[WorkerAgent],
        *,
        planner: TaskPlanner | None = None,
        router: WorkerRouter | None = None,
        emit: Callable[[str], None] = print,
        checkpoint_callback: Callable[[GlobalState], None] | None = None,
    ) -> None:
        self.state = state
        self.workers = list(workers)
        self.planner = planner or BootstrapSeeder()
        self.router = router
        self.emit = emit
        self.dispatch_policy = DispatchPolicy(emit=self.emit)
        self.checkpoint_callback = checkpoint_callback

    def _checkpoint(self) -> None:
        if self.checkpoint_callback is None:
            return
        try:
            self.checkpoint_callback(self.state)
        except Exception as exc:
            self.emit(f"[checkpoint] failed to persist state: {type(exc).__name__}: {exc}")

    # -- delegate shims for legacy tests ---------------------------------
    # Older callers exercised these methods directly on the Orchestrator.
    # The implementations have moved to :class:`DispatchPolicy`; the shims
    # below preserve the historical interface.

    def _validate_task_for_dispatch(self, task: Task):
        """Validate task context; returns ``(valid, reason, error_code)``."""

        validation = self.dispatch_policy.validate_task_for_dispatch(task, self.state)
        return validation.valid, validation.reason, validation.error_code

    def _try_repair_task_context(self, task: Task, candidates: Iterable[WorkerAgent]) -> bool:
        """Best-effort fill of missing identity / artifact context."""

        return self.dispatch_policy.try_repair_task_context(task, self.state, list(candidates))

    def select_worker(
        self, task: Task,
    ) -> tuple[WorkerAgent | None, WorkerRouteDecision | None, str]:
        """Select a worker for *task*.

        Returns ``(worker, decision, reject_reason)``.  *reject_reason* is a
        human-readable string explaining why no worker was selected (empty
        string on success).
        """
        candidates = [worker for worker in self.workers if worker.supports(task)]
        if not candidates:
            return None, None, f"no worker registered for task type {task.task_type!r}"

        routable = [w for w in candidates if w.can_route_task(task, self.state)[0]]
        if not routable:
            if self.dispatch_policy.try_repair_task_context(task, self.state, candidates):
                routable = [w for w in candidates if w.can_route_task(task, self.state)[0]]
            if not routable:
                reasons = [
                    f"{w.name}: {w.can_route_task(task, self.state)[1]}"
                    for w in candidates
                ]
                return None, None, "; ".join(reasons)

        if len(routable) == 1:
            only = routable[0]
            decision = WorkerRouteDecision(
                worker_name=only.name,
                rationale=f"Single compatible worker available: {only.name}.",
                confidence=1.0,
            )
            return only, decision, ""
        if self.router is None:
            raise LLMClientError(
                f"Multiple workers can handle {task.task_type!r}; an LLM worker router is required."
            )

        decision = self.router.route(task=task, state=self.state, candidates=routable)
        worker = next((c for c in routable if c.name == decision.worker_name), None)
        return worker, decision, ""

    def refresh_plan(self, cycle: int) -> bool:
        decision = self.planner.plan(self.state)
        created = 0
        for planned_task in decision.tasks:
            candidate = planned_task.to_task()
            queued = self.state.queue_task(candidate)
            if queued.task_id == candidate.task_id:
                created += 1

        if decision.notes:
            self.state.notes.extend(decision.notes)
            self.state.touch()

        if created or decision.notes:
            self.emit(f"[cycle {cycle}] plan: {decision.summary}")

        return decision.stop_run

    def run(self, max_cycles: int = 10) -> GlobalState:
        self.state.status = RunStatus.RUNNING

        for cycle in range(1, max_cycles + 1):
            if self.state.solved:
                self.emit(f"[cycle {cycle}] validated flag found — halting run")
                break
            self.state.last_cycle_at = utc_now()
            try:
                if self.refresh_plan(cycle):
                    self.emit(f"[cycle {cycle}] planner signalled stop — halting run")
                    self.state.status = RunStatus.STOPPED
                    self._checkpoint()
                    break
            except LLMClientError as exc:
                self.emit(f"[cycle {cycle}] LLM planner error, stopping run: {exc}")
                self.state.notes.append(
                    f"cycle {cycle}: planner {type(exc).__name__}: {exc}"
                )
                self.state.status = RunStatus.STOPPED
                self._checkpoint()
                break

            batch = self.dispatch_policy.dequeue_batch(self.state)
            if not batch:
                self.emit(f"[cycle {cycle}] task queue exhausted — no ready tasks remain")
                self._checkpoint()
                break

            dispatched = 0
            llm_error_stop = False
            for task in batch:
                if self.state.solved:
                    break

                # Pre-dispatch validation
                validation = self.dispatch_policy.validate_task_for_dispatch(task, self.state)
                if not validation.valid:
                    task.mark_blocked(
                        validation.reason or "dispatch refused",
                        error_code=validation.error_code,
                    )
                    self.emit(
                        f"[cycle {cycle}] dispatch_refused {task.task_id}: "
                        f"{validation.reason} (error_code={validation.error_code})"
                    )
                    continue

                try:
                    worker, route_decision, reject_reason = self.select_worker(task)
                except LLMClientError as exc:
                    task.mark_failed(str(exc), requeue=False)
                    self.emit(
                        f"[cycle {cycle}] LLM router error, stopping run: {exc}"
                    )
                    self.state.notes.append(
                        f"cycle {cycle}: router {type(exc).__name__}: {exc}"
                    )
                    self.state.status = RunStatus.STOPPED
                    llm_error_stop = True
                    break
                if worker is None:
                    task.mark_blocked(reject_reason, error_code=TaskErrorCode.DISPATCH_REFUSED)
                    self.emit(
                        f"[cycle {cycle}] blocked {task.task_id}: {reject_reason}"
                    )
                    continue

                if route_decision is not None:
                    task.metadata["route_decision"] = route_decision.model_dump(mode="json")
                    self.emit(
                        f"[cycle {cycle}] route {task.task_id}: "
                        f"{route_decision.worker_name} ({route_decision.rationale})"
                    )
                task.mark_running(worker.name)
                self.emit(f"[cycle {cycle}] dispatch {task.task_id} -> {worker.name}")

                try:
                    report = worker.run(task, self.state)
                except LLMClientError as exc:
                    task.mark_failed(str(exc), requeue=False)
                    tag = "TRANSIENT LLM ERROR" if exc.transient else "LLM ERROR"
                    self.emit(
                        f"[cycle {cycle}] {tag} in {worker.name} "
                        f"while executing {task.task_id}, stopping run: {exc}"
                    )
                    self.state.notes.append(
                        f"cycle {cycle}: worker {worker.name} {type(exc).__name__}: {exc}"
                    )
                    self.state.status = RunStatus.STOPPED
                    llm_error_stop = True
                    break
                except Exception as exc:
                    tb_text = traceback.format_exc(limit=20)
                    self.emit(
                        f"[cycle {cycle}] UNHANDLED EXCEPTION in {worker.name} "
                        f"while executing {task.task_id}: {type(exc).__name__}: {exc}"
                    )
                    report = WorkerReport(
                        task_id=task.task_id,
                        worker_name=worker.name,
                        success=False,
                        summary=f"Worker {worker.name} raised {type(exc).__name__}: {exc}",
                        error=tb_text,
                    )

                self.state.apply_worker_report(report)
                dispatched += 1

                status_tag = "ok" if report.success else "FAILED"
                self.emit(
                    f"[cycle {cycle}] {status_tag} {task.task_id}: {report.summary}"
                )
                if self.state.solved:
                    self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                    break

            if dispatched > 1:
                self.emit(f"[cycle {cycle}] batch: dispatched {dispatched} task(s)")

            self._checkpoint()

            if llm_error_stop:
                break

            if self.state.solved:
                break
        else:
            remaining_open_tasks = [
                task for task in self.state.task_chain.tasks
                if task.status in {TaskStatus.PENDING, TaskStatus.RUNNING}
            ]
            if remaining_open_tasks:
                message = (
                    f"Max cycle budget ({max_cycles}) exhausted with "
                    f"{len(remaining_open_tasks)} open task(s) remaining."
                )
                self.emit(
                    f"[cycle {max_cycles}] max cycles exhausted — "
                    f"{len(remaining_open_tasks)} task(s) still open"
                )
                self.state.notes.append(message)
                self.state.touch()

        # Determine final run status from task outcomes
        tasks = self.state.task_chain.tasks
        has_open_tasks = any(
            task.status in {TaskStatus.PENDING, TaskStatus.RUNNING}
            for task in tasks
        )
        if self.state.solved:
            self.state.status = RunStatus.SOLVED
        elif self.state.status == RunStatus.STOPPED:
            # Loop deliberately set STOPPED (planner stop_run, LLM error,
            # or queue exhausted); preserve that decision over downstream
            # task-status heuristics so the caller can tell graceful halts
            # apart from natural completion.
            pass
        elif has_open_tasks:
            self.state.status = RunStatus.STOPPED
        elif any(t.status == TaskStatus.BLOCKED for t in tasks):
            self.state.status = RunStatus.STOPPED
        elif any(t.status == TaskStatus.FAILED for t in tasks):
            self.state.status = RunStatus.FAILED
        else:
            self.state.status = RunStatus.COMPLETED

        return self.state
