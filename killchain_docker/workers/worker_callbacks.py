"""Worker progress and flag-candidate callback plumbing."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from killchain_docker.state.domain import FlagCandidate
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem

ProgressCallback = Callable[[RunState, TodoItem, str], None]
FlagCandidateCallback = Callable[[RunState, TodoItem, Iterable[FlagCandidate]], None]


class WorkerCallbackMixin:
    progress_callback: ProgressCallback | None
    flag_candidate_callback: FlagCandidateCallback | None

    def init_worker_callbacks(self) -> None:
        self.progress_callback = None
        self.flag_candidate_callback = None

    def report_progress(self, state: RunState, task: TodoItem, message: str) -> None:
        if self.progress_callback is None:
            return
        self.progress_callback(state, task, message)

    def report_flag_candidates(
        self, state: RunState, task: TodoItem, candidates: Iterable[FlagCandidate]
    ) -> None:
        if self.flag_candidate_callback is None:
            return
        self.flag_candidate_callback(state, task, list(candidates))
