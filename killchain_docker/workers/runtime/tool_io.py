"""Worker access to lower-level tool execution."""

from __future__ import annotations

from typing import Any

from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability, ToolGateway
from killchain_docker.tools.core import ToolExecutionBundle, ToolExecutionError


class WorkerToolIOMixin:
    tool_gateway: ToolGateway | None

    def run_capability(
        self,
        *,
        task: TodoItem,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle:
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway but none is configured."
            )
        return self.tool_gateway.run(
            task_id=getattr(task, "todo_id", getattr(task, "task_id", "")),
            capability=capability,
            metadata=metadata,
            timeout_s=timeout_s,
        )
