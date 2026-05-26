"""Hard execution constraints derived from prior guard failures."""

from __future__ import annotations

from typing import Any

from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.workers.corrections.counters import (
    bounded_counter_candidates,
    large_counter_values,
)


def execution_constraints(
    *,
    state: RunState,
    task: TodoItem,
    correction_context: dict[str, Any],
    prior_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build hard execution hints from prior runtime guard failures."""
    failure_kind = str(correction_context.get("failure_kind") or "")
    if failure_kind not in {"timeout", "unbounded_loop_guard"}:
        return {}
    failure_text = "\n".join(
        (
            str(correction_context.get(key) or "")
            for key in ("last_stderr", "last_stdout", "failure_detail")
        )
    )
    for step in prior_steps[-2:]:
        failure_text += "\n" + str(step.get("stderr_preview") or "")
        failure_text += "\n" + str(step.get("stdout_preview") or "")
    blocked = large_counter_values(failure_text)
    bounded = bounded_counter_candidates(state=state, task=task)
    constraints: dict[str, Any] = {}
    if blocked:
        constraints["do_not_iterate_values"] = blocked
    if bounded:
        constraints["bounded_counter_candidates"] = bounded
    if blocked or bounded:
        constraints["rule"] = (
            "Do not repeat oversized counters from prior guard failures. Before any linear loop, choose a bounded evidence-backed counter or prove a logarithmic fast-forward."
        )
    return constraints
