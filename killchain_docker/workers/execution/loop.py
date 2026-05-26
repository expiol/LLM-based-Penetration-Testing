"""Run LLM-selected worker tools until the loop policy stops."""

from __future__ import annotations

from dataclasses import dataclass, field

from killchain_docker.state.domain import Hypothesis
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.execution.policy import (
    should_continue_after_step,
    tool_success,
)
from killchain_docker.workers.execution.step import (
    LoopExecutionAgent,
    run_tool_step,
)
from killchain_docker.workers.results.assembly import worker_result_from_bundle
from killchain_docker.workers.results.enrichment import enrich_worker_result


@dataclass
class _ToolLoopState:
    """Tracks prior tool attempts and final-result inputs for one worker run."""

    prior_steps: list[dict[str, object]] = field(default_factory=list)
    last_bundle: ToolExecutionBundle | None = None
    last_capability: ToolCapability | None = None
    last_rationale: str = ""
    accumulated_hypotheses: list[Hypothesis] = field(default_factory=list)
    accumulated_memory: dict[str, str] = field(default_factory=dict)

    def record_step(
        self,
        *,
        bundle: ToolExecutionBundle,
        capability: ToolCapability,
        rationale: str,
        step_record: dict[str, object],
    ) -> None:
        self.last_bundle = bundle
        self.last_capability = capability
        self.last_rationale = rationale
        self.prior_steps.append(step_record)


def run_worker_tool_loop(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    max_inner_steps: int,
    max_metadata_retries: int,
) -> WorkerResult:
    loop_state = _ToolLoopState()
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
            step_record=_executed_step(
                step, capability, rationale, bundle, output_context
            ),
        )
        if _should_stop_tool_loop(
            task=task,
            step=step,
            max_inner_steps=max_inner_steps,
            bundle=bundle,
            prior_steps=loop_state.prior_steps,
        ):
            break
    return _final_loop_result(
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


def _should_stop_tool_loop(
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


def _executed_step(
    step: int,
    capability: ToolCapability,
    rationale: str,
    bundle: ToolExecutionBundle,
    output_context: dict[str, object],
) -> dict[str, object]:
    return {
        "step": step,
        "capability": capability.value,
        "rationale": rationale,
        "summary": bundle.tool_output.summary,
        "flag_candidates": output_context.get("flag_candidates", []),
        "near_miss_candidates": output_context.get("near_miss_candidates", []),
        "traceback": str(output_context.get("traceback", "")),
        "stdout_preview": str(output_context.get("stdout", ""))[:2000],
        "stderr_preview": str(output_context.get("stderr", ""))[:1500],
        "returncode": output_context.get("returncode"),
        "failure_kind": output_context.get("failure_kind"),
        "failure_detail": output_context.get("failure_detail"),
        "executed": True,
    }


def _final_loop_result(
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


__all__ = ["run_worker_tool_loop"]
