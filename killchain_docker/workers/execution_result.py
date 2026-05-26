"""Final result assembly for worker tool loops."""

from __future__ import annotations

from killchain_docker.state.domain import Hypothesis
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.execution_agent import LoopExecutionAgent
from killchain_docker.workers.execution_policy import tool_success
from killchain_docker.workers.result_assembly import worker_result_from_bundle
from killchain_docker.workers.result_enrichment import enrich_worker_result


def final_loop_result(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    last_bundle: ToolExecutionBundle | None,
    last_capability: ToolCapability | None,
    last_rationale: str,
    prior_steps: list[dict[str, object]],
    accumulated_hypotheses: list[Hypothesis],
    accumulated_memory: dict[str, str],
) -> WorkerResult:
    if last_bundle is None or last_capability is None:
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=agent.name,
            success=False,
            summary=f"{agent.name} did not execute a tool.",
            error="no tool execution",
            retryable=False,
        )
    output_context = dict(last_bundle.tool_output.output_context)
    success = tool_success(last_capability, last_bundle, output_context)
    if len(prior_steps) > 1:
        output_context["react_steps"] = len(prior_steps)
    result = worker_result_from_bundle(
        todo=task,
        worker_name=agent.name,
        capability=last_capability,
        output_context=output_context,
        summary=last_bundle.tool_output.summary,
        success=success,
        bundle=last_bundle,
        rationale=last_rationale,
    )
    return enrich_worker_result(
        result,
        worker_name=agent.name,
        task=task,
        state=state,
        last_bundle=last_bundle,
        output_context=output_context,
        hypotheses=accumulated_hypotheses,
        memory_updates=accumulated_memory,
    )
