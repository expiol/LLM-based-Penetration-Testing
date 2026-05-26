"""Worker result builders for tool-loop failures."""

from __future__ import annotations

from typing import Any

from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import _truncate

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
    """Build a recoverable PARTIAL result after metadata-validation gives up.

    Metadata-validation errors are worker-output bugs (the LLM emitted a tool
    selection without a required metadata field), not task-logic dead ends.
    The same goal can succeed once a later planner cycle re-frames the todo
    or a different worker is routed.  Always emit a PARTIAL result so the
    run can keep working on other todos rather than terminating with
    ``todo_failed`` on a single transient worker miss.
    """

    cap_str = (
        capability.value
        if capability and hasattr(capability, "value")
        else str(capability or "unknown")
    )
    output_context = {
        "capability": cap_str,
        "failure_kind": failure_kind,
        "failure_detail": error_text,
        "executed": False,
        "agent_handoff": {
            "reason": "tool_metadata_validation_failed",
            "target": "planner",
        },
    }
    if selected_metadata:
        output_context["selected_metadata"] = metadata_preview(selected_metadata)
    if validation_attempts:
        output_context["validation_attempts"] = validation_attempts[-3:]
    return WorkerResult(
        todo_id=task.todo_id,
        worker_name=worker_name,
        success=False,
        summary=f"{worker_name} failed to execute its selected tool: {error_text}",
        error=error_text,
        retryable=False,
        partial=True,
        partial_reason=error_text,
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
