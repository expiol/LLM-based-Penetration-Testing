"""Worker result builders for tool-loop failures."""

from __future__ import annotations

from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.task_intent import is_execution_closure_task


def metadata_failure_result(
    task: TodoItem,
    worker_name: str,
    capability: ToolCapability | None,
    error_text: str,
    failure_kind: str,
) -> WorkerResult:
    cap_str = (
        capability.value
        if capability and hasattr(capability, "value")
        else str(capability or "unknown")
    )
    partial = is_execution_closure_task(task)
    output_context = {
        "capability": cap_str,
        "failure_kind": failure_kind,
        "failure_detail": error_text,
        "executed": False,
    }
    if partial:
        output_context["agent_handoff"] = {
            "reason": "tool_metadata_validation_failed",
            "target": "planner",
        }
    return WorkerResult(
        todo_id=task.todo_id,
        worker_name=worker_name,
        success=False,
        summary=f"{worker_name} failed to execute its selected tool: {error_text}",
        error=error_text,
        retryable=False,
        partial=partial,
        partial_reason=error_text if partial else None,
        result_quality=failure_kind,
        output_context=output_context,
    )
