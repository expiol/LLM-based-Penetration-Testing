"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations

import traceback
from collections.abc import Callable, Iterable

from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.planning import PlannerAgent
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

    def _worker_catalog(self) -> list[dict[str, object]]:
        return [
            {
                "name": worker.name,
                "supported_todo_kinds": list(worker.supported_todo_kinds),
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
        return self.router.route(
            self.state,
            worker_catalog=self._worker_catalog(),
            max_assignments=5,
        )

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
            if exc.transient:
                self.emit(
                    f"[cycle {cycle}] transient LLM error in {worker.name} "
                    f"for {todo.todo_id}, returning retryable failure"
                )
                return WorkerResult(
                    todo_id=todo.todo_id,
                    worker_name=worker.name,
                    success=False,
                    summary=f"transient LLM error: {exc}",
                    error=str(exc),
                    retryable=True,
                )
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

    @staticmethod
    def _is_hollow_result(result: WorkerResult) -> bool:
        """Detect results that report success but produce no meaningful output.

        A hollow result typically means the worker ran a trivial command
        (e.g. a bare ``curl GET``) instead of executing the planned task.
        Downgrading these to partial prevents them from masking stagnation.
        """
        if not result.success or result.partial or result.solved:
            return False
        delta = result.state_delta
        if delta and (
            delta.flag_candidates
            or delta.artifacts
            or delta.endpoints
            or delta.routes
            or delta.hypotheses
            or delta.vulnerabilities
            or delta.exploit_attempts
            or delta.sessions
        ):
            return False
        ctx = result.output_context or {}
        if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
            return False
        if result.result_quality:
            return False
        if result.finding_updates or result.credential_updates:
            return False
        return True

    @staticmethod
    def _round_had_meaningful_progress(results: list[WorkerResult]) -> bool:
        """Check whether any result in the round produced new state signals.

        Broadens the original flag-only check to include findings,
        credentials, vulnerabilities, sessions, and near-miss candidates
        so that productive non-flag work does not trigger a premature pivot.
        """
        for r in results:
            if not r.success:
                continue
            delta = r.state_delta
            if delta and (
                delta.flag_candidates
                or delta.vulnerabilities
                or delta.sessions
                or delta.exploit_attempts
            ):
                return True
            if r.finding_updates or r.credential_updates:
                return True
            ctx = r.output_context or {}
            if ctx.get("near_miss_candidates"):
                return True
        return False

    def _summarize_round(self, results: list[WorkerResult]):
        return self.router.summarize_round(self.state, results=results)

    def _inject_forced_pivot(self, cycle: int) -> None:
        """Inject a forced pivot directive into state metadata.

        Instead of hard-stopping, this bans stalled families and forces the
        planner to try a fundamentally different attack vector.
        """
        from killchain_docker.orchestrator.policy import ProgressPolicy

        self._pivot_count += 1
        self._rounds_without_progress = 0  # Reset counter after pivot

        # Identify families to ban
        snapshot = ProgressPolicy.stagnation_snapshot(self.state)
        failed_counts = snapshot.get("failed_or_partial_family_counts", {})
        banned_families = sorted(
            family for family, count in failed_counts.items()
            if count >= ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD
        )

        # Also ban the most-attempted family even if below threshold
        family_counts = snapshot.get("family_counts", {})
        if family_counts:
            top_family = max(family_counts, key=lambda f: family_counts[f])
            if top_family not in banned_families and family_counts[top_family] >= 3:
                banned_families.append(top_family)

        pivot_directive = {
            "pivot_number": self._pivot_count,
            "triggered_at_cycle": cycle,
            "banned_families": banned_families,
            "instruction": (
                f"FORCED PIVOT #{self._pivot_count}: The run has spent "
                f"{self.FORCED_PIVOT_THRESHOLD} consecutive rounds without producing "
                f"a valid flag candidate. The following approach families are NOW BANNED "
                f"and must NOT be re-attempted: {banned_families}. "
                "You MUST propose a fundamentally different attack vector: "
                "different algorithm, different tool, different attack surface, "
                "or different interpretation of the challenge. "
                "If no alternative exists, set stop_run=true."
            ),
        }
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
        reason = f"llm_error:{source}:{type(exc).__name__}: {exc}"
        self.state.stop_reason = "llm_error"
        self.state.status = RunStatus.FAILED
        self.state.orchestration_notes.append(f"cycle {cycle}: {reason}")
        for todo in self.state.todos:
            if todo.status == TodoStatus.RUNNING:
                todo.mark_failed(reason, retryable=False)
            elif todo.status == TodoStatus.PENDING:
                todo.mark_blocked("llm_error")
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

                planner_summary = ""
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
                    if exc.transient and self._transient_skip_count < self.MAX_TRANSIENT_SKIPS:
                        self._transient_skip_count += 1
                        self.emit(
                            f"[cycle {cycle}] transient LLM error in planner "
                            f"(skip {self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS}), "
                            f"continuing: {exc}"
                        )
                        self.state.orchestration_notes.append(
                            f"cycle {cycle}: transient LLM error skipped "
                            f"({self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS})"
                        )
                        self._checkpoint()
                        continue
                    self.emit(f"[cycle {cycle}] planner LLM error - aborting run")
                    self._mark_llm_error(cycle, "planner", exc)
                    self._checkpoint()
                    max_cycles_exhausted = False
                    raise

                decision = self.route(cycle)
                if not decision.assignments:
                    self._consecutive_empty_rounds += 1
                    self.emit(f"[cycle {cycle}] router selected no assignments")
                    self._checkpoint()
                    if self._consecutive_empty_rounds >= self.MAX_CONSECUTIVE_EMPTY_ROUNDS:
                        max_cycles_exhausted = False
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
                    result = self._run_assignment(cycle, todo, worker)
                    if self._is_hollow_result(result):
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

                # Forced Pivot: track rounds without meaningful progress
                if self._round_had_meaningful_progress(results):
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
            if exc.transient and self._transient_skip_count < self.MAX_TRANSIENT_SKIPS:
                # Transient error escaped from router/summarizer — absorb it.
                self._transient_skip_count += 1
                self.emit(
                    f"[cycle {current_cycle}] transient LLM error escaped "
                    f"(skip {self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS}): {exc}"
                )
                self.state.orchestration_notes.append(
                    f"cycle {current_cycle}: transient LLM error absorbed "
                    f"({self._transient_skip_count}/{self.MAX_TRANSIENT_SKIPS})"
                )
                self._checkpoint()
                max_cycles_exhausted = True  # Allow normal termination logic
            else:
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
            self.state.orchestration_notes.append(reason)
            self.emit(f"[interrupt] {reason}; marked running todos as interrupted")
            self._checkpoint()

        if max_cycles_exhausted and self.state.has_open_todos():
            self.state.stop_reason = "max_cycles_exhausted"
            for todo in self.state.todos:
                if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}:
                    todo.mark_blocked("max_cycles_exhausted")
            self.state.orchestration_notes.append("max_cycles_exhausted")
            self.state.touch()

        if self.state.solved:
            self.state.status = RunStatus.SOLVED
        elif self.state.status == RunStatus.INTERRUPTED:
            pass
        elif self.state.status == RunStatus.STOPPED:
            pass
        elif self.state.stop_reason == "max_cycles_exhausted":
            self.state.status = RunStatus.FAILED
        elif self.state.has_open_todos():
            self.state.stop_reason = self.state.stop_reason or "open_todos_remaining"
            self.state.status = RunStatus.FAILED
        elif any(todo.status in {TodoStatus.FAILED, TodoStatus.BLOCKED} for todo in self.state.todos):
            self.state.status = RunStatus.FAILED
        else:
            self.state.status = RunStatus.COMPLETED
        return self.state
