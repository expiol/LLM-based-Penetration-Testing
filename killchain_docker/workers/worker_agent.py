"""Abstract persona worker used by orchestrator runtime."""

from __future__ import annotations

from abc import ABC, abstractmethod

from killchain_docker.llm.gateway import LLMClient
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolGateway
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.workers.worker_callbacks import WorkerCallbackMixin
from killchain_docker.workers.worker_routing import WorkerRoutingMixin
from killchain_docker.workers.worker_tool_choice import WorkerToolChoiceMixin
from killchain_docker.workers.worker_tool_io import WorkerToolIOMixin


class WorkerAgent(
    WorkerCallbackMixin,
    WorkerRoutingMixin,
    WorkerToolChoiceMixin,
    WorkerToolIOMixin,
    ABC,
):
    """Abstract persona worker that can handle high-level todos."""

    name: str
    supported_todo_kinds: tuple[str, ...]
    routing_summary: str = ""
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()
    supported_dispatch_profiles: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
        tool_gateway: ToolGateway | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.execution_plane = execution_plane
        self.tool_gateway = tool_gateway or (
            ToolGateway(execution_plane) if execution_plane is not None else None
        )
        self.init_worker_callbacks()

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Execute a todo against the current shared state."""


__all__ = ["WorkerAgent"]
