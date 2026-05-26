"""Execution result value objects."""

from __future__ import annotations
from dataclasses import dataclass
from killchain_docker.state.todos import WorkerAssignment, WorkerResult


@dataclass(frozen=True)
class RoutedAssignmentBatchResult:
    """Outcome of executing one RouterDecision assignment batch."""

    results: list[WorkerResult]
    executed_assignments: list[WorkerAssignment]
    transient_skip: bool = False
    terminal_error: bool = False
    solved: bool = False


@dataclass(frozen=True)
class RoutedRoundCompletionResult:
    """Control-flow result after routed assignment post-processing."""

    retry_cycle: bool = False
    halt_run: bool = False


@dataclass(frozen=True)
class RunCycleGateResult:
    """Control-flow result for one orchestration cycle gate."""

    halt_run: bool = False
