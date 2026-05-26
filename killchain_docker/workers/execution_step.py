"""Single-step selection and execution for worker tool loops."""

from __future__ import annotations

from killchain_docker.state.domain import Hypothesis
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle, ToolExecutionError
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.workers.execution_agent import LoopExecutionAgent
from killchain_docker.workers.execution_failures import metadata_failure_result
from killchain_docker.workers.execution_metadata import prepare_execution_metadata
from killchain_docker.workers.execution_step_history import validation_error_step
from killchain_docker.workers.tool_selection import (
    choose_capability,
    choose_fixed_capability,
    fixed_llm_capability,
)


def run_tool_step(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    prior_steps: list[dict[str, object]],
    max_metadata_retries: int,
    accumulated_hypotheses: list[Hypothesis],
    accumulated_memory: dict[str, str],
) -> tuple[ToolCapability, str, ToolExecutionBundle] | WorkerResult:
    metadata_retries = 0
    capability = None
    rationale = ""
    while True:
        try:
            capability, selected_metadata, rationale, hypothesis_text, mem_updates = (
                select_step_tool(agent, task, state, step=step, prior_steps=prior_steps)
            )
            if hypothesis_text:
                accumulated_hypotheses.append(Hypothesis(title=hypothesis_text))
            if mem_updates:
                accumulated_memory.update(mem_updates)
            bundle = execute_step(
                agent,
                task,
                state,
                step=step,
                capability=capability,
                selected_metadata=selected_metadata,
            )
            return (capability, rationale, bundle)
        except (ToolExecutionError, ValueError) as exc:
            error_text = str(exc)
            failure_kind = ToolGuardPolicy.metadata_failure_kind(error_text, capability)
            metadata_retries += 1
            if metadata_retries > max_metadata_retries:
                return metadata_failure_result(
                    task, agent.name, capability, error_text, failure_kind
                )
            prior_steps.append(
                validation_error_step(
                    step, capability, rationale, error_text, failure_kind
                )
            )


def select_step_tool(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    prior_steps: list[dict[str, object]],
):
    fixed_capability = fixed_llm_capability(task, agent.allowed_capabilities)
    if fixed_capability is not None:
        agent.report_progress(
            state,
            task,
            f"{agent.name} preparing {fixed_capability.value} for step {step + 1}",
        )
        selected = choose_fixed_capability(
            agent,
            fixed_capability,
            task,
            state,
            prior_steps=prior_steps if prior_steps else None,
        )
    else:
        agent.report_progress(
            state, task, f"{agent.name} choosing tool for step {step + 1}"
        )
        selected = choose_capability(
            agent,
            task,
            state,
            allowed_capabilities=agent.allowed_capabilities,
            prior_steps=prior_steps if prior_steps else None,
        )
    capability = selected[0]
    agent.report_progress(
        state, task, f"{agent.name} selected {capability.value} for step {step + 1}"
    )
    return selected


def execute_step(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    capability: ToolCapability,
    selected_metadata: dict[str, object],
) -> ToolExecutionBundle:
    metadata = prepare_execution_metadata(
        capability=capability,
        todo=task,
        state=state,
        selected_metadata=selected_metadata,
        worker_name=agent.name,
    )
    timeout_raw = metadata.pop("timeout_s", None)
    timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
    agent.report_progress(
        state, task, f"{agent.name} executing {capability.value} for step {step + 1}"
    )
    bundle = agent.run_capability(
        task=task, capability=capability, metadata=metadata, timeout_s=timeout_s
    )
    agent.report_progress(
        state, task, f"{agent.name} completed {capability.value} for step {step + 1}"
    )
    if bundle.state_delta.flag_candidates:
        agent.report_flag_candidates(state, task, bundle.state_delta.flag_candidates)
    return bundle
