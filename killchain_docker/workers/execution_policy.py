"""Worker execution result and repair-loop policies."""

from __future__ import annotations
from typing import Any
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolOutputStatus

INFRASTRUCTURE_FAILURE_KINDS = frozenset({"infrastructure_error"})
SCRIPT_REPAIRABLE_FAILURE_KINDS = frozenset(
    {
        "binary_structure_error",
        "bytes_text_mismatch",
        "host_resolution_error",
        "parse_error",
        "path_resolution_error",
        "path_type_mismatch",
        "scope_violation_blocked",
        "syntax_error",
        "timeout",
        "type_error",
        "unbounded_loop_guard",
        "undefined_name",
    }
)


def tool_success(
    capability: ToolCapability, bundle: Any, output_context: dict[str, object]
) -> bool:
    if bundle.tool_output.status != ToolOutputStatus.SUCCESS:
        return False
    if capability != ToolCapability.SCRIPT_EXEC:
        return True
    if bundle.result.exit_code not in (None, 0):
        return False
    returncode = output_context.get("returncode")
    if returncode not in (None, ""):
        try:
            return int(returncode) == 0
        except (TypeError, ValueError):
            return False
    return True


def should_continue_after_step(
    task: TodoItem, prior_steps: list[dict[str, object]], *, max_inner_steps: int
) -> bool:
    """Allow one bounded script repair after a mechanical script failure."""
    del task
    executed_steps = [step for step in prior_steps if step.get("executed") is not False]
    if len(executed_steps) >= min(2, max_inner_steps):
        return False
    last = prior_steps[-1] if prior_steps else {}
    if last.get("flag_candidates"):
        return False
    if last.get("capability") != ToolCapability.SCRIPT_EXEC.value:
        return False
    failure_kind = str(last.get("failure_kind") or "").strip()
    if failure_kind in INFRASTRUCTURE_FAILURE_KINDS:
        return False
    if failure_kind not in SCRIPT_REPAIRABLE_FAILURE_KINDS:
        return False
    return returncode_failed(last.get("returncode"))


def returncode_failed(value: object) -> bool:
    if value in (None, "", 0):
        return False
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return True
