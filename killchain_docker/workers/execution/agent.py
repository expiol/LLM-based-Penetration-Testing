"""Protocol for worker tool-loop execution."""

from __future__ import annotations

from typing import Any, Protocol

from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle


class LoopExecutionAgent(Protocol):
    name: str
    allowed_capabilities: tuple[ToolCapability, ...]

    def report_progress(
        self, state: RunState, task: TodoItem, message: str
    ) -> None: ...

    def report_flag_candidates(
        self, state: RunState, task: TodoItem, candidates
    ) -> None: ...

    def run_capability(
        self,
        *,
        task: TodoItem,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle: ...

    def choose_tool_use(self, **kwargs): ...

    def choose_fixed_tool_use(self, **kwargs): ...
