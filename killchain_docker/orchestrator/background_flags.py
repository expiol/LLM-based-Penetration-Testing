"""Asynchronous flag candidate validation runtime."""

from __future__ import annotations
from collections.abc import Callable, Iterable
from queue import Empty, PriorityQueue
from threading import Event, Lock, Thread
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.domain import FlagCandidate, StateDelta
from killchain_docker.state.run_state import RunState
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.state_delta import StateDeltaApplier
from killchain_docker.workers.runtime.agent import WorkerAgent
from killchain_docker.workers.results.flag_validation import flag_matches


class BackgroundFlagSolved(Exception):
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
            target=self._run, name="background-flag-validator", daemon=True
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
        return (self._validated_candidate, self.expected_flag)

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
        while not self._stop.is_set() and (not self._solved.is_set()):
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


class BackgroundFlagValidationController:
    """Runtime plane for asynchronous flag candidate validation."""

    def __init__(
        self,
        *,
        state: RunState,
        workers: Iterable[WorkerAgent],
        emit: Callable[[str], None],
        checkpoint: Callable[[], None],
    ) -> None:
        self.state = state
        self._checkpoint = checkpoint
        self._validator = self._build_validator(workers, emit)
        self.outcome = RunOutcomeStore(state)

    def start(self) -> None:
        if self._validator is not None:
            self._validator.start()
            self.sync(0)

    def stop(self) -> None:
        if self._validator is not None:
            self._validator.stop()

    def enqueue_candidates(self, candidates: Iterable[FlagCandidate]) -> int:
        if self._validator is None:
            return 0
        queued = 0
        for candidate in candidates:
            if self._validator.enqueue(candidate):
                queued += 1
        return queued

    def sync(self, cycle: int, *, wait_s: float = 0.0) -> bool:
        validator = self._validator
        if validator is None:
            return False
        self.enqueue_candidates(CandidatePolicy.validation_ready_candidates(self.state))
        for rejected in validator.drain_rejections():
            self._reject_candidate(rejected)
        solution = validator.collect_solution(wait_s=wait_s)
        for rejected in validator.drain_rejections():
            self._reject_candidate(rejected)
        if solution is None:
            return False
        candidate, expected_flag = solution
        if self.outcome.is_solved:
            return True
        StateDeltaApplier(self.state).apply(
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
        self.outcome.solved(
            validated_flag=expected_flag,
            reason="background_flag_validated",
            touch=False,
        )
        RunJournal(self.state).orchestration_note(
            f"cycle {cycle}: background flag validator accepted a candidate"
        )
        TodoQueue(self.state).interrupt_running("background_flag_validated")
        RunStateMaintenance(self.state).touch()
        self._checkpoint()
        return True

    @staticmethod
    def _build_validator(
        workers: Iterable[WorkerAgent], emit: Callable[[str], None]
    ) -> _BackgroundFlagValidator | None:
        for worker in workers:
            if getattr(worker, "name", "") != "flag-worker":
                continue
            expected_flag = str(getattr(worker, "expected_flag", "") or "").strip()
            if not expected_flag:
                continue
            return _BackgroundFlagValidator(
                expected_flag=expected_flag, match_candidate=flag_matches, emit=emit
            )
        return None

    def _reject_candidate(self, value: str) -> None:
        StateDeltaApplier(self.state).apply(
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
