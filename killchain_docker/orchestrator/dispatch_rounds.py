"""Empty router-decision accounting and dependency reconciliation."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch_types import (
    EmptyDispatchAction,
    EmptyDispatchResult,
)
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.orchestrator.todo_status_commands import TodoStatusCommands


class DispatchRoundController:
    """Owns no-assignment queue reconciliation and empty-round limits."""

    def __init__(
        self,
        *,
        reader: TodoQueueReader,
        commands: TodoStatusCommands,
        max_consecutive_empty_rounds: int,
    ) -> None:
        self.reader = reader
        self.commands = commands
        self.max_consecutive_empty_rounds = max(1, max_consecutive_empty_rounds)
        self.consecutive_empty_rounds = 0

    def reset_empty_rounds(self) -> None:
        self.consecutive_empty_rounds = 0

    def handle_empty_decision(self) -> EmptyDispatchResult:
        dependency_blocks = self.commands.block_unsatisfiable_dependencies()
        if dependency_blocks:
            self.consecutive_empty_rounds = 0
            action = (
                EmptyDispatchAction.CONTINUE
                if self.reader.has_open()
                else EmptyDispatchAction.HALT
            )
            return EmptyDispatchResult(
                action=action,
                dependency_blocks=dependency_blocks,
                consecutive_empty_rounds=self.consecutive_empty_rounds,
                checkpoint=True,
                reason="dependency_blocked",
            )
        self.consecutive_empty_rounds += 1
        if self.consecutive_empty_rounds >= self.max_consecutive_empty_rounds:
            return EmptyDispatchResult(
                action=EmptyDispatchAction.HALT,
                consecutive_empty_rounds=self.consecutive_empty_rounds,
                checkpoint=True,
                reason="router_no_assignments",
            )
        return EmptyDispatchResult(
            action=EmptyDispatchAction.CONTINUE,
            consecutive_empty_rounds=self.consecutive_empty_rounds,
            checkpoint=True,
            reason="router_empty",
        )
