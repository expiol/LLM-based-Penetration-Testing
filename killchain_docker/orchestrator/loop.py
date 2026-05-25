"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from inspect import Parameter, signature
from queue import Empty, PriorityQueue
import re
from threading import Event, Lock, Thread
import traceback

from killchain_docker.logging_utils import get_logger
from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.planning import PlannerAgent, PlannedTodo, PlannerDecision
from killchain_docker.orchestrator.policy import RoundOutcomePolicy
from killchain_docker.orchestrator.router import RouterAgent, WorkerDirectory
from killchain_docker.state import (
    DispatchIntent,
    RouterDecision,
    RouterRound,
    RouterRoundSummary,
    FlagCandidate,
    RunState,
    RunStatus,
    StateDelta,
    TodoPhase,
    TodoItem,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
)
from killchain_docker.state.models import utc_now
from killchain_docker.workers.base import WorkerAgent


LOGGER = get_logger(__name__)


def _supports_structured_emit(callback: Callable[..., object]) -> bool:
    try:
        parameters = signature(callback).parameters.values()
    except (TypeError, ValueError):
        return False
    names = {parameter.name for parameter in parameters}
    has_context = any(parameter.kind == Parameter.VAR_KEYWORD for parameter in parameters)
    return "event_type" in names and has_context


class _BackgroundFlagSolved(Exception):
    """Raised at safe checkpoints after a background validator solves the run."""


class _BackgroundFlagValidator:
    def __init__(
        self,
        *,
        expected_flag: str,
        match_candidate: Callable[[str, str], bool],
        emit: Callable[[str], None],
    ) -> None:
        self.expected_flag = expected_flag
        self._match_candidate = match_candidate
        self._emit = emit
        self._queue: PriorityQueue[tuple[float, int, str]] = PriorityQueue()
        self._stop = Event()
        self._solved = Event()
        self._seen: set[str] = set()
        self._counter = 0
        self._lock = Lock()
        self._thread: Thread | None = None
        self._validated_candidate: str | None = None
        self._rejections: list[str] = []

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = Thread(
            target=self._run,
            name="background-flag-validator",
            daemon=True,
        )
        self._thread.start()

    def enqueue(self, candidate: FlagCandidate) -> bool:
        value = str(candidate.value or "").strip()
        if not value or self._stop.is_set() or self._solved.is_set():
            return False
        with self._lock:
            if value in self._seen:
                return False
            self._seen.add(value)
            self._counter += 1
            order = self._counter
        self._queue.put((-float(candidate.confidence), order, value))
        return True

    def collect_solution(self, *, wait_s: float = 0.0) -> tuple[str, str] | None:
        if wait_s > 0:
            self._solved.wait(wait_s)
        if not self._solved.is_set() or self._validated_candidate is None:
            return None
        return self._validated_candidate, self.expected_flag

    def drain_rejections(self) -> list[str]:
        with self._lock:
            values = list(self._rejections)
            self._rejections.clear()
        return values

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        while not self._stop.is_set() and not self._solved.is_set():
            try:
                _, _, candidate = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                if self._match_candidate(candidate, self.expected_flag):
                    self._validated_candidate = candidate
                    self._solved.set()
                    self._emit("[flag-validator] validated candidate in background")
                else:
                    with self._lock:
                        self._rejections.append(candidate)
            finally:
                self._queue.task_done()


def _default_flag_matches(candidate: str, expected: str) -> bool:
    candidate_text = candidate.strip()
    expected_text = expected.strip()
    if candidate_text == expected_text:
        return True
    candidate_inner = _unwrap_flag(candidate_text)
    expected_inner = _unwrap_flag(expected_text)
    if candidate_inner == expected_inner:
        return True
    if match := re.match(r"([A-Za-z0-9_]+)\{", expected_text):
        if f"{match.group(1)}{{{candidate_text}}}" == expected_text:
            return True
    return candidate_inner.lower() == expected_inner.lower()


def _unwrap_flag(value: str) -> str:
    match = re.match(r"[A-Za-z0-9_]+\{(.+)\}\s*$", value, re.DOTALL)
    return match.group(1) if match else value


class Orchestrator:
    """Run the planner-router-worker loop for one assessment."""

    MAX_CONSECUTIVE_EMPTY_ROUNDS = 4
    FORCED_PIVOT_THRESHOLD = 5  # Rounds without flag progress triggers pivot
    MAX_TRANSIENT_SKIPS = 3  # Transient LLM errors to tolerate before aborting
    LLM_ERROR_MESSAGE_LIMIT = 1200
    MAX_FINAL_DETERMINISTIC_CLOSURE_PASSES = 2
    MAX_FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS = 8
    FINAL_DETERMINISTIC_CAPABILITIES = frozenset({
        "artifact.triage",
        "disk.extract",
        "media.scan",
        "office.inspect",
        "png.inspect",
    })

    def __init__(
        self,
        state: RunState,
        workers: Iterable[WorkerAgent],
        *,
        planner: PlannerAgent | None = None,
        router: RouterAgent | None = None,
        emit: Callable[[str], None] = LOGGER.info,
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
        self._structured_emit = _supports_structured_emit(emit)
        self.checkpoint_callback = checkpoint_callback
        self._consecutive_empty_rounds = 0
        self._rounds_without_progress = 0
        self._pivot_count = 0
        self._transient_skip_count = 0
        self._background_flag_validator = self._build_background_flag_validator()

    def _build_background_flag_validator(self) -> _BackgroundFlagValidator | None:
        for worker in self.workers:
            if getattr(worker, "name", "") != "flag-worker":
                continue
            expected_flag = str(getattr(worker, "expected_flag", "") or "").strip()
            if not expected_flag:
                continue
            matcher = getattr(worker, "_flag_matches", None)
            if callable(matcher):
                def match_candidate(candidate: str, expected: str) -> bool:
                    return bool(matcher(candidate, expected))
            else:
                match_candidate = _default_flag_matches
            return _BackgroundFlagValidator(
                expected_flag=expected_flag,
                match_candidate=match_candidate,
                emit=self.emit,
            )
        return None

    def _start_background_flag_validator(self) -> None:
        if self._background_flag_validator is not None:
            self._background_flag_validator.start()
            self._sync_background_flag_validator(0)

    def _stop_background_flag_validator(self) -> None:
        if self._background_flag_validator is not None:
            self._background_flag_validator.stop()

    def _enqueue_background_flag_candidates(
        self,
        candidates: Iterable[FlagCandidate],
    ) -> int:
        validator = self._background_flag_validator
        if validator is None:
            return 0
        queued = 0
        for candidate in candidates:
            if validator.enqueue(candidate):
                queued += 1
        return queued

    def _sync_background_flag_validator(self, cycle: int, *, wait_s: float = 0.0) -> bool:
        validator = self._background_flag_validator
        if validator is None:
            return False
        self._enqueue_background_flag_candidates(self.state.active_flag_candidates())
        for rejected in validator.drain_rejections():
            self._reject_background_flag_candidate(rejected)
        solution = validator.collect_solution(wait_s=wait_s)
        for rejected in validator.drain_rejections():
            self._reject_background_flag_candidate(rejected)
        if solution is None:
            return False
        candidate, expected_flag = solution
        if self.state.solved:
            return True
        self.state.apply_state_delta(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value=candidate,
                        source="background-flag-validation",
                        confidence=1.0,
                        validated=True,
                    )
                ]
            )
        )
        self.state.solved = True
        self.state.status = RunStatus.SOLVED
        self.state.validated_flag = expected_flag
        self.state.stop_reason = "background_flag_validated"
        self.state.orchestration_notes.append(
            f"cycle {cycle}: background flag validator accepted a candidate"
        )
        self.state.interrupt_running_todos("background_flag_validated")
        self.state.touch()
        self._checkpoint()
        return True

    def _reject_background_flag_candidate(self, value: str) -> None:
        self.state.apply_state_delta(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value=value,
                        source="background-flag-validation",
                        confidence=0.1,
                        validated=False,
                        rejected_reason="candidate mismatch",
                    )
                ]
            )
        )

    def _checkpoint(self) -> None:
        if self.checkpoint_callback is None:
            return
        try:
            self.checkpoint_callback(self.state)
        except Exception as exc:
            LOGGER.exception(
                "checkpoint callback failed",
                extra={"run_id": self.state.run_id},
            )
            self.emit(f"[checkpoint] failed to persist state: {type(exc).__name__}: {exc}")

    def _emit_event(
        self,
        message: str,
        *,
        event_type: str | None = None,
        **context: object,
    ) -> None:
        if self._structured_emit:
            self.emit(message, event_type=event_type, **context)
            return
        self.emit(message)

    def _checkpoint_activity(self, message: str, **context: object) -> None:
        self._emit_event(message, **context)
        self.state.touch()
        self._checkpoint()

    def _todo_context(
        self,
        cycle: int,
        todo: TodoItem,
        *,
        worker: str | None = None,
    ) -> dict[str, object]:
        return {
            "cycle": cycle,
            "todo_id": todo.todo_id,
            "todo_status": str(todo.status),
            "todo_phase": str(todo.phase),
            "worker": worker or todo.assigned_worker,
        }

    def _queue_planner_decision(
        self,
        decision: PlannerDecision,
    ) -> tuple[int, int, list[str]]:
        created = 0
        created_ids: list[str] = []
        for planned_todo in decision.todos:
            todo = planned_todo.to_todo()
            queued = self.state.queue_todo(todo)
            if queued.todo_id == todo.todo_id:
                created += 1
                created_ids.append(queued.todo_id)
        if decision.notes:
            self.state.orchestration_notes.extend(decision.notes)
            self.state.touch()
        return len(decision.todos), created, created_ids

    def refresh_plan(self, cycle: int) -> tuple[bool, str]:
        decision = self.planner.plan(self.state)
        proposed, created, _created_ids = self._queue_planner_decision(decision)
        proposed = len(decision.todos)
        deduped = proposed - created
        summary = decision.summary or "(no summary)"
        self.emit(
            f"[cycle {cycle}] plan: proposed={proposed} new={created} "
            f"deduped={deduped} stop_run={decision.stop_run} - {summary[:200]}"
        )
        return decision.stop_run, summary

    def refresh_deterministic_seeds(self, cycle: int) -> str:
        pipeline = getattr(self.planner, "pipeline", None)
        merge = getattr(pipeline, "merge", None)
        if not callable(merge):
            return "planner skipped: ready todo backlog"
        decision = merge(
            self.state,
            llm_decision=PlannerDecision(
                summary="Deterministic seed refresh while ready backlog exists.",
                todos=[],
                notes=["Skipped LLM planning because ready todo backlog exists."],
            ),
        )
        proposed, created, _created_ids = self._queue_planner_decision(decision)
        deduped = proposed - created
        if proposed or created:
            self.emit(
                f"[cycle {cycle}] deterministic seed refresh: proposed={proposed} "
                f"new={created} deduped={deduped}"
            )
        return decision.summary or "deterministic seed refresh while ready backlog exists"

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
        self._checkpoint_activity(
            f"[cycle {cycle}] dispatch {todo.todo_id} -> {worker.name}",
            event_type="dispatch",
            **self._todo_context(cycle, todo, worker=worker.name),
        )
        previous_callback = worker.progress_callback
        previous_candidate_callback = worker.flag_candidate_callback
        worker.progress_callback = lambda state, task, message: self._worker_progress(
            cycle, state, task, message
        )
        worker.flag_candidate_callback = lambda state, task, candidates: self._worker_flag_candidates(
            cycle, state, task, candidates
        )
        try:
            return worker.run(todo, self.state)
        except LLMClientError as exc:
            if exc.transient:
                todo.release_after_transient_error(str(exc))
                raise
            raise
        except _BackgroundFlagSolved:
            raise
        except Exception as exc:
            tb_text = traceback.format_exc(limit=20)
            LOGGER.exception(
                "worker execution failed",
                extra={
                    "run_id": self.state.run_id,
                    "cycle": cycle,
                    "todo_id": todo.todo_id,
                    "worker": worker.name,
                },
            )
            self._emit_event(
                f"[cycle {cycle}] UNHANDLED EXCEPTION in {worker.name} "
                f"while executing {todo.todo_id}: {type(exc).__name__}: {exc}",
                event_type="worker_error",
                **self._todo_context(cycle, todo, worker=worker.name),
            )
            return WorkerResult(
                todo_id=todo.todo_id,
                worker_name=worker.name,
                success=False,
                summary=f"{worker.name} raised {type(exc).__name__}: {exc}",
                error=tb_text,
                retryable=False,
            )
        finally:
            worker.progress_callback = previous_callback
            worker.flag_candidate_callback = previous_candidate_callback

    def _worker_progress(self, cycle: int, state: RunState, todo: TodoItem, message: str) -> None:
        self._emit_event(
            f"[cycle {cycle}] {todo.todo_id}: {message}",
            event_type="worker_progress",
            **self._todo_context(cycle, todo),
        )
        state.touch()
        self._checkpoint()
        if self._sync_background_flag_validator(cycle):
            raise _BackgroundFlagSolved()

    def _worker_flag_candidates(
        self,
        cycle: int,
        state: RunState,
        todo: TodoItem,
        candidates: Iterable[FlagCandidate],
    ) -> None:
        candidate_list = list(candidates)
        if not candidate_list:
            return
        queued = self._enqueue_background_flag_candidates(candidate_list)
        if queued:
            self._emit_event(
                f"[cycle {cycle}] queued {queued} flag candidate(s) for background validation",
                event_type="flag_candidate_queued",
                **self._todo_context(cycle, todo),
            )
        state.touch()
        self._checkpoint()
        if self._sync_background_flag_validator(cycle, wait_s=0.05):
            raise _BackgroundFlagSolved()

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

    def _halt_after_transient_llm_error(
        self,
        cycle: int,
        source: str,
        exc: LLMClientError,
        *,
        todo: TodoItem | None = None,
    ) -> None:
        reason = self._remember_llm_error(cycle, source, exc)
        self.state.status = RunStatus.FAILED
        self.state.stop_reason = "llm_transient_error"
        if todo is not None:
            if todo.status == TodoStatus.RUNNING:
                todo.release_after_transient_error(reason)
            if todo.status == TodoStatus.PENDING:
                todo.mark_interrupted(reason)
        else:
            for pending in self.state.todos:
                if pending.status == TodoStatus.RUNNING:
                    pending.mark_interrupted(reason)
        self._emit_event(
            f"[cycle {cycle}] transient LLM error budget exhausted in {source}; "
            "ending run as llm_transient_error without marking task logic failed",
            event_type="llm_transient_error",
        )
        self.state.touch()

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

    def _final_deterministic_evidence_pass(self, cycle: int) -> bool:
        if self.state.solved or self.state.has_open_todos():
            return False
        if not self._has_generated_artifact_for_final_closure():
            return False
        pipeline = getattr(self.planner, "pipeline", None)
        merge = getattr(pipeline, "merge", None)
        if not callable(merge):
            return False

        ran_any = False
        remaining_budget = self.MAX_FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS
        for pass_index in range(1, self.MAX_FINAL_DETERMINISTIC_CLOSURE_PASSES + 1):
            if self.state.solved or self.state.has_open_todos() or remaining_budget <= 0:
                break
            decision = merge(
                self.state,
                llm_decision=PlannerDecision(
                    summary="Final deterministic evidence closure pass.",
                    todos=[],
                    notes=[
                        "Skipped LLM planning for final deterministic evidence closure.",
                    ],
                ),
            )
            filtered = [
                todo for todo in decision.todos
                if self._is_final_deterministic_closure_todo(todo)
            ]
            if not filtered:
                break
            decision = PlannerDecision(
                summary="Final deterministic evidence closure pass.",
                todos=filtered[:remaining_budget],
                notes=decision.notes,
            )
            proposed, created, created_ids = self._queue_planner_decision(decision)
            if not created_ids:
                break
            self.emit(
                f"[cycle {cycle}] final deterministic evidence closure pass "
                f"{pass_index}: proposed={proposed} new={created}"
            )

            results: list[WorkerResult] = []
            assignments: list[WorkerAssignment] = []
            for todo_id in created_ids:
                if remaining_budget <= 0 or self.state.solved:
                    break
                todo = self.state.get_todo(todo_id)
                if todo is None or todo.status != TodoStatus.PENDING:
                    continue
                worker, worker_name, reason = self._select_deterministic_worker(todo)
                if worker is None:
                    todo.mark_blocked(reason)
                    result = WorkerResult(
                        todo_id=todo.todo_id,
                        worker_name=worker_name or "deterministic-worker",
                        success=False,
                        summary=f"Assignment blocked: {reason}",
                        error=reason,
                        retryable=False,
                    )
                else:
                    assignments.append(
                        WorkerAssignment(
                            todo_id=todo.todo_id,
                            worker_name=worker.name,
                            rationale="final deterministic evidence closure",
                        )
                    )
                    result = self._run_assignment(cycle, todo, worker)
                self.state.apply_worker_result(result)
                results.append(result)
                remaining_budget -= 1
                status_tag = "PARTIAL" if result.partial else ("ok" if result.success else "FAILED")
                self._emit_event(
                    f"[cycle {cycle}] final closure {status_tag} {todo.todo_id}: {result.summary}",
                    event_type="worker_result",
                    **self._todo_context(cycle, todo, worker=result.worker_name),
                    result_success=result.success,
                    result_partial=result.partial,
                )
                self._checkpoint()
                if self._sync_background_flag_validator(cycle, wait_s=0.2):
                    self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                    break

            if results:
                ran_any = True
                self.state.record_round(
                    RouterRound(
                        cycle=cycle,
                        planner_summary="final deterministic evidence closure pass",
                        assignments=assignments,
                        results=results,
                        summary=RouterRoundSummary(
                            summary="; ".join(result.summary for result in results),
                            direct_results=[result.summary for result in results],
                        ),
                    )
                )
                self.state.touch()
                self._checkpoint()
            cycle += 1
        return ran_any

    def _has_generated_artifact_for_final_closure(self) -> bool:
        for artifact in self.state.artifacts.values():
            path = str(getattr(artifact, "path", "") or "")
            if "/.autopentest_artifacts/" not in path:
                continue
            source = str(getattr(artifact, "source", "") or "").strip().lower()
            if source in {"artifact_triage", "file", "strings", "exiftool"}:
                continue
            return True
        return False

    def _is_final_deterministic_closure_todo(self, todo: PlannedTodo) -> bool:
        context = todo.context or {}
        if str(context.get("family") or "") != "artifact-followup":
            return False
        intent = DispatchIntent.from_context(context)
        capability = str(
            intent.required_capability
            or context.get("capability_hint")
            or ""
        ).strip()
        if capability not in self.FINAL_DETERMINISTIC_CAPABILITIES:
            return False
        paths = self._todo_paths(context)
        if not paths:
            return False
        return all("/.autopentest_artifacts/" in path for path in paths)

    @staticmethod
    def _todo_paths(context: dict[str, object]) -> list[str]:
        paths: list[str] = []
        for key in ("path", "artifact_path", "file_path"):
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                paths.append(value.strip())
        raw_paths = context.get("paths")
        if isinstance(raw_paths, list):
            paths.extend(str(item).strip() for item in raw_paths if str(item).strip())
        seen: set[str] = set()
        unique: list[str] = []
        for path in paths:
            if path not in seen:
                unique.append(path)
                seen.add(path)
        return unique

    def _select_deterministic_worker(
        self,
        todo: TodoItem,
    ) -> tuple[WorkerAgent | None, str, str]:
        intent = DispatchIntent.from_context(todo.context)
        capability = str(
            intent.required_capability
            or todo.context.get("capability_hint")
            or ""
        ).strip()
        candidates = self.worker_directory.workers_for_capability(capability)
        if "artifact-worker" in candidates:
            candidates = ["artifact-worker", *[name for name in candidates if name != "artifact-worker"]]
        last_reason = ""
        for worker_name in candidates:
            worker, reason = self.select_worker(todo, worker_name)
            if worker is not None:
                return worker, worker_name, ""
            last_reason = reason
        if candidates and last_reason:
            return None, candidates[0], last_reason
        return None, candidates[0] if candidates else "", (
            f"no worker supports required capability {capability!r}"
        )


    def _compact_llm_error(self, exc: LLMClientError) -> str:
        message = str(exc).strip() or type(exc).__name__
        if len(message) <= self.LLM_ERROR_MESSAGE_LIMIT:
            return message
        return f"{message[: self.LLM_ERROR_MESSAGE_LIMIT].rstrip()}... [truncated]"

    def _remember_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> str:
        kind = str(getattr(exc, "kind", "unknown"))
        message = self._compact_llm_error(exc)
        reason = f"llm_error:{source}:{kind}:{type(exc).__name__}: {message}"
        self.state.metadata["last_llm_error"] = {
            "cycle": cycle,
            "source": source,
            "kind": kind,
            "transient": bool(getattr(exc, "transient", False)),
            "schema_name": getattr(exc, "schema_name", None),
            "model": getattr(exc, "model", None),
            "attempts": getattr(exc, "attempts", None),
            "message": message,
        }
        self.state.orchestration_notes.append(f"cycle {cycle}: {reason}")
        return reason

    def _mark_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> None:
        reason = self._remember_llm_error(cycle, source, exc)
        self.state.stop_reason = "llm_error"
        self.state.status = RunStatus.FAILED
        for todo in self.state.todos:
            if todo.status == TodoStatus.RUNNING:
                todo.mark_failed(reason, retryable=False)
            elif todo.status == TodoStatus.PENDING:
                todo.mark_blocked("llm_error")
        self.state.touch()

    def _worker_llm_error_result(
        self,
        cycle: int,
        todo: TodoItem,
        worker: WorkerAgent,
        exc: LLMClientError,
    ) -> WorkerResult:
        reason = self._remember_llm_error(cycle, worker.name, exc)
        return WorkerResult(
            todo_id=todo.todo_id,
            worker_name=worker.name,
            success=False,
            summary=f"{worker.name} LLM error while selecting or running a tool",
            error=reason,
            retryable=False,
            result_quality="llm_error",
        )

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

    def _final_flag_validation_pass(self, cycle: int) -> bool:
        if self.state.solved or self.state.has_open_todos():
            return False
        queued: list[TodoItem] = []
        for candidate in self.state.active_flag_candidates():
            dedupe_key = f"final:flag-validation:{candidate.value}"
            if any(todo.dedupe_key == dedupe_key for todo in self.state.todos):
                continue
            queued.append(
                self.state.queue_todo(
                    TodoItem(
                        goal="Validate recovered flag candidate.",
                        phase=TodoPhase.FLAG_VALIDATION,
                        priority=100,
                        context={
                            "candidate_flag": candidate.value,
                            "flag_candidate_id": candidate.candidate_id,
                            "family": "flag-validation",
                        },
                        success_criteria=["Confirm whether the candidate is the challenge flag."],
                        constraints=["Validate only grounded candidates already present in state."],
                        dedupe_key=dedupe_key,
                    )
                )
            )
        if not queued:
            return False

        self.emit(f"[cycle {cycle}] final flag validation pass for {len(queued)} candidate(s)")
        results: list[WorkerResult] = []
        assignments: list[WorkerAssignment] = []
        for todo in queued:
            if self.state.solved:
                break
            worker, reason = self.select_worker(todo, "flag-worker")
            if worker is None:
                todo.mark_blocked(reason)
                result = WorkerResult(
                    todo_id=todo.todo_id,
                    worker_name="flag-worker",
                    success=False,
                    summary=f"Assignment blocked: {reason}",
                    error=reason,
                    retryable=False,
                )
            else:
                assignments.append(
                    WorkerAssignment(
                        todo_id=todo.todo_id,
                        worker_name="flag-worker",
                        rationale="final validation pass",
                    )
                )
                result = self._run_assignment(cycle, todo, worker)
            self.state.apply_worker_result(result)
            results.append(result)
            status_tag = "ok" if result.success else "FAILED"
            self.emit(f"[cycle {cycle}] final validation {status_tag} {todo.todo_id}: {result.summary}")
            self._checkpoint()
            if self.state.solved:
                self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                break

        self.state.record_round(
            RouterRound(
                cycle=cycle,
                planner_summary="final flag validation pass",
                assignments=assignments,
                results=results,
                summary=RouterRoundSummary(
                    summary="; ".join(result.summary for result in results),
                    direct_results=[result.summary for result in results],
                ),
            )
        )
        self.state.touch()
        self._checkpoint()
        return True

    def run(self, max_cycles: int = 10) -> RunState:
        self.state.status = RunStatus.RUNNING
        max_cycles_exhausted = True
        current_cycle = 0
        self._start_background_flag_validator()

        try:
            for cycle in range(1, max_cycles + 1):
                current_cycle = cycle
                if self._sync_background_flag_validator(cycle):
                    self.emit(f"[cycle {cycle}] background flag validation solved - halting run")
                    max_cycles_exhausted = False
                    break
                if self.state.solved:
                    self.emit(f"[cycle {cycle}] validated flag found - halting run")
                    max_cycles_exhausted = False
                    break
                self.state.last_cycle_at = utc_now()

                planner_summary = "planner skipped: ready todo backlog"
                if self._has_ready_backlog():
                    self.emit(f"[cycle {cycle}] planner skipped - ready todo backlog")
                    planner_summary = self.refresh_deterministic_seeds(cycle)
                else:
                    try:
                        self._checkpoint_activity(f"[cycle {cycle}] planning next todos")
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
                        if exc.transient:
                            self._halt_after_transient_llm_error(cycle, "planner", exc)
                            self._checkpoint()
                            max_cycles_exhausted = False
                            break
                        self.emit(f"[cycle {cycle}] planner LLM error - aborting run")
                        self._mark_llm_error(cycle, "planner", exc)
                        self._checkpoint()
                        max_cycles_exhausted = False
                        raise

                try:
                    self._checkpoint_activity(f"[cycle {cycle}] routing ready todos")
                    decision = self.route(cycle)
                except LLMClientError as exc:
                    if self._skip_transient_llm_error(cycle, "router", exc):
                        self._checkpoint()
                        continue
                    if exc.transient:
                        self._halt_after_transient_llm_error(cycle, "router", exc)
                        self._checkpoint()
                        max_cycles_exhausted = False
                        break
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
                        self._emit_event(
                            f"[cycle {cycle}] blocked {todo.todo_id}: {reason}",
                            event_type="worker_blocked",
                            **self._todo_context(
                                cycle,
                                todo,
                                worker=assignment.worker_name,
                            ),
                        )
                        continue
                    executed_assignments.append(assignment)
                    try:
                        result = self._run_assignment(cycle, todo, worker)
                    except LLMClientError as exc:
                        if self._skip_transient_llm_error(cycle, worker.name, exc):
                            transient_worker_skip = True
                            break
                        if exc.transient:
                            self._halt_after_transient_llm_error(
                                cycle,
                                worker.name,
                                exc,
                                todo=todo,
                            )
                            max_cycles_exhausted = False
                            self._checkpoint()
                            break
                        self._emit_event(
                            f"[cycle {cycle}] worker LLM error in {worker.name} - "
                            f"marking {todo.todo_id} failed and continuing",
                            event_type="worker_llm_error",
                            **self._todo_context(cycle, todo, worker=worker.name),
                        )
                        result = self._worker_llm_error_result(cycle, todo, worker, exc)
                    if RoundOutcomePolicy.is_hollow_result(result):
                        result.partial = True
                        result.partial_reason = (
                            result.partial_reason
                            or "worker reported success but produced no meaningful output"
                        )
                        self._emit_event(
                            f"[cycle {cycle}] hollow result downgraded to PARTIAL: {todo.todo_id}",
                            event_type="worker_result_partial",
                            **self._todo_context(cycle, todo, worker=result.worker_name),
                        )
                    self.state.apply_worker_result(result)
                    results.append(result)
                    status_tag = "PARTIAL" if result.partial else ("ok" if result.success else "FAILED")
                    self._emit_event(
                        f"[cycle {cycle}] {status_tag} {todo.todo_id}: {result.summary}",
                        event_type="worker_result",
                        **self._todo_context(cycle, todo, worker=result.worker_name),
                        result_success=result.success,
                        result_partial=result.partial,
                    )
                    self._checkpoint()
                    if self._sync_background_flag_validator(cycle, wait_s=0.2):
                        self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                        max_cycles_exhausted = False
                        break
                    if self.state.solved:
                        self.emit(f"[cycle {cycle}] solved: {self.state.validated_flag}")
                        break

                if self.state.stop_reason == "llm_transient_error":
                    max_cycles_exhausted = False
                    break

                if transient_worker_skip:
                    self._checkpoint()
                    continue

                if self.state.solved:
                    max_cycles_exhausted = False
                    break

                try:
                    self._checkpoint_activity(f"[cycle {cycle}] summarizing worker results")
                    round_summary = self._summarize_round(results)
                except LLMClientError as exc:
                    if self._skip_transient_llm_error(cycle, "round_summarizer", exc):
                        self._checkpoint()
                        continue
                    if exc.transient:
                        self._halt_after_transient_llm_error(cycle, "round_summarizer", exc)
                        self._checkpoint()
                        max_cycles_exhausted = False
                        break
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
        except _BackgroundFlagSolved:
            self.emit(f"[cycle {current_cycle}] background flag validation solved - halting run")
            max_cycles_exhausted = False
        except (KeyboardInterrupt, SystemExit) as exc:
            reason = f"run interrupted by {type(exc).__name__}"
            self.state.interrupt_running_todos(reason)
            self.state.status = RunStatus.INTERRUPTED
            self.state.stop_reason = "interrupted"
            self.state.orchestration_notes.append(reason)
            self.emit(f"[interrupt] {reason}; marked running todos as interrupted")
            self._checkpoint()
        finally:
            self._stop_background_flag_validator()

        if max_cycles_exhausted:
            if self._sync_background_flag_validator(current_cycle + 1, wait_s=0.2):
                max_cycles_exhausted = False
        if max_cycles_exhausted:
            ran_final_closure = self._final_deterministic_evidence_pass(current_cycle + 1)
            if ran_final_closure and self.state.solved:
                max_cycles_exhausted = False
        if max_cycles_exhausted:
            if self._sync_background_flag_validator(current_cycle + 1, wait_s=0.2):
                max_cycles_exhausted = False
        if max_cycles_exhausted:
            ran_final_validation = self._final_flag_validation_pass(current_cycle + 1)
            if ran_final_validation and self.state.solved:
                max_cycles_exhausted = False

        self._finalize_terminal_state(max_cycles_exhausted=max_cycles_exhausted)
        return self.state
