"""Stop decisions for worker tool loops."""

from __future__ import annotations

from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.execution_policy import should_continue_after_step


def should_stop_tool_loop(
    *,
    task: TodoItem,
    step: int,
    max_inner_steps: int,
    bundle: ToolExecutionBundle,
    prior_steps: list[dict[str, object]],
) -> bool:
    if bundle.state_delta.flag_candidates:
        return True
    if step == max_inner_steps - 1:
        return True
    return not should_continue_after_step(
        task, prior_steps, max_inner_steps=max_inner_steps
    )
