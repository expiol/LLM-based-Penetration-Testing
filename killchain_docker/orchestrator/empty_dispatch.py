"""Recovery behavior when routing produces no executable assignments."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch_rounds import DispatchRoundController
from killchain_docker.orchestrator.dispatch_types import (
    DependencyBlock,
    EmptyDispatchResult,
    ExecutionEventsView,
)
from killchain_docker.state.outcome import RunOutcomeStore


class EmptyDispatchController:
    """Owns dispatch-side recovery when the router selects no assignments."""

    def __init__(
        self, *, rounds: DispatchRoundController, events: ExecutionEventsView
    ) -> None:
        self.rounds = rounds
        self.events = events
        self.outcome = RunOutcomeStore(rounds.reader.state)

    def handle_no_assignments(self, *, cycle: int) -> EmptyDispatchResult:
        result = self.rounds.handle_empty_decision()
        self._emit_dependency_blocks(cycle, result.dependency_blocks)
        if result.dependency_blocks:
            self.events.checkpoint()
            return result
        self.events.emit(f"[cycle {cycle}] router selected no assignments")
        self.events.checkpoint()
        if result.reason == "router_no_assignments":
            self.outcome.failed("router_no_assignments", touch=False)
            self.rounds.commands.block_open("router_no_assignments")
        return result

    def _emit_dependency_blocks(
        self, cycle: int, blocks: list[DependencyBlock]
    ) -> None:
        for block in blocks:
            self.events.emit(
                f"[cycle {cycle}] dependency blocked {block.todo.todo_id}: {block.reason}",
                event_type="todo_dependency_blocked",
                **self.events.todo_context(cycle, block.todo),
            )
