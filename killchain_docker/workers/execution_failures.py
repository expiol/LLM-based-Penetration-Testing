"""Worker result builders for tool-loop failures."""

from __future__ import annotations

from typing import Any

from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import _truncate
from killchain_docker.workers.task_intent import is_execution_closure_task

_METADATA_VALUE_PREVIEW_LIMIT = 4000


def metadata_failure_result(
    task: TodoItem,
    worker_name: str,
    capability: ToolCapability | None,
    error_text: str,
    failure_kind: str,
    selected_metadata: dict[str, object] | None = None,
    validation_attempts: list[dict[str, object]] | None = None,
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
    if selected_metadata:
        output_context["selected_metadata"] = metadata_preview(selected_metadata)
    if validation_attempts:
        output_context["validation_attempts"] = validation_attempts[-3:]
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


def metadata_preview(metadata: dict[str, object] | None) -> dict[str, object]:
    if not metadata:
        return {}
    return {
        str(key): preview_metadata_value(value) for key, value in metadata.items()
    }


def preview_metadata_value(value: Any) -> object:
    if isinstance(value, str):
        return _truncate(value, _METADATA_VALUE_PREVIEW_LIMIT)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [preview_metadata_value(item) for item in value[:40]]
    if isinstance(value, tuple):
        return [preview_metadata_value(item) for item in value[:40]]
    if isinstance(value, dict):
        return {
            str(key): preview_metadata_value(item)
            for key, item in list(value.items())[:40]
        }
    return _truncate(str(value), _METADATA_VALUE_PREVIEW_LIMIT)
