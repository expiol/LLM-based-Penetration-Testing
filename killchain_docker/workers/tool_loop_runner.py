"""Run LLM-selected worker tools until the loop policy stops."""

from __future__ import annotations

from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.workers.execution_agent import LoopExecutionAgent
from killchain_docker.workers.execution_result import final_loop_result
from killchain_docker.workers.execution_step import run_tool_step
from killchain_docker.workers.execution_step_history import executed_step
from killchain_docker.workers.tool_loop_policy import should_stop_tool_loop
from killchain_docker.workers.tool_loop_state import ToolLoopState


def run_worker_tool_loop(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    max_inner_steps: int,
    max_metadata_retries: int,
) -> WorkerResult:
    loop_state = ToolLoopState()
    for step in range(max_inner_steps):
        step_result = run_tool_step(
            agent,
            task,
            state,
            step=step,
            prior_steps=loop_state.prior_steps,
            max_metadata_retries=max_metadata_retries,
            accumulated_hypotheses=loop_state.accumulated_hypotheses,
            accumulated_memory=loop_state.accumulated_memory,
        )
        if isinstance(step_result, WorkerResult):
            return step_result
        capability, rationale, bundle = step_result
        output_context = dict(bundle.tool_output.output_context)
        loop_state.record_step(
            bundle=bundle,
            capability=capability,
            rationale=rationale,
            step_record=executed_step(
                step, capability, rationale, bundle, output_context
            ),
        )
        if should_stop_tool_loop(
            task=task,
            step=step,
            max_inner_steps=max_inner_steps,
            bundle=bundle,
            prior_steps=loop_state.prior_steps,
        ):
            break
    return final_loop_result(
        agent,
        task,
        state,
        last_bundle=loop_state.last_bundle,
        last_capability=loop_state.last_capability,
        last_rationale=loop_state.last_rationale,
        prior_steps=loop_state.prior_steps,
        accumulated_hypotheses=loop_state.accumulated_hypotheses,
        accumulated_memory=loop_state.accumulated_memory,
    )
