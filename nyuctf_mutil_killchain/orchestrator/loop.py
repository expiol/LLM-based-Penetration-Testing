"""Orchestrator loop — observe/plan/dispatch/fold cycle with production error handling."""

from __future__ import annotations

import traceback
from collections.abc import Callable, Iterable

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.orchestrator.planner import HeuristicPlanner, TaskPlanner
from nyuctf_mutil_killchain.orchestrator.router import (
    HeuristicWorkerRouter,
    WorkerRouteDecision,
    WorkerRouter,
)
from nyuctf_mutil_killchain.state import GlobalState, RunStatus, Task, TaskStatus, WorkerReport
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
    ) -> None:
        self.state = state
        self.workers = list(workers)
        self.planner = planner or HeuristicPlanner()
        self.router = router or HeuristicWorkerRouter()
        self.emit = emit

    def select_worker(self, task: Task) -> tuple[WorkerAgent | None, WorkerRouteDecision | None]:
        candidates = [worker for worker in self.workers if worker.supports(task)]
        if not candidates:
            return None, None
        routable = [w for w in candidates if w.can_route_task(task, self.state)[0]]
        if not routable:
            return None, None
        decision = self.router.route(task=task, state=self.state, candidates=routable)
        worker = next((c for c in routable if c.name == decision.worker_name), None)
        return worker, decision

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

    _BATCHABLE_TASK_TYPES = frozenset({"flag.validate"})
    _MAX_BATCHABLE_PER_CYCLE = 8

    def _dequeue_batch(self, *, max_batch: int = 4) -> list[Task]:
        """Dequeue up to *max_batch* independent ready tasks in priority order.

        Tasks are independent when they don't share a worker (different
        task_type prefixes) so they won't contend for the same execution
        context.  Lightweight batchable tasks (e.g. flag validation) bypass
        the prefix dedup so multiple can retire in a single cycle.
        """
        completed = self.state.task_chain.completed_task_ids()
        ready = [t for t in self.state.task_chain.tasks if t.is_ready(completed)]
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

    def run(self, max_cycles: int = 10) -> GlobalState:
        self.state.status = RunStatus.RUNNING

        for cycle in range(1, max_cycles + 1):
            if self.state.solved:
                self.emit(f"[cycle {cycle}] validated flag found — halting run")
                break
            self.state.last_cycle_at = utc_now()
            if self.refresh_plan(cycle):
                self.emit(f"[cycle {cycle}] planner signalled stop — halting run")
                self.state.status = RunStatus.STOPPED
                break

            batch = self._dequeue_batch()
            if not batch:
                self.emit(f"[cycle {cycle}] task queue exhausted — no ready tasks remain")
                break

            dispatched = 0
            for task in batch:
                if self.state.solved:
                    break

                worker, route_decision = self.select_worker(task)
                if worker is None:
                    task.mark_blocked(f"No worker registered for task type {task.task_type!r}.")
                    self.emit(
                        f"[cycle {cycle}] blocked {task.task_id}: "
                        f"no worker handles {task.task_type!r}"
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
        elif any(t.status == TaskStatus.FAILED for t in tasks):
            self.state.status = RunStatus.FAILED
        elif any(t.status == TaskStatus.BLOCKED for t in tasks):
            self.state.status = RunStatus.STOPPED
        elif has_open_tasks:
            self.state.status = RunStatus.STOPPED
        else:
            self.state.status = RunStatus.COMPLETED

        return self.state
