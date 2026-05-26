"""Deterministic direct-capability execution path."""

from __future__ import annotations

from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability, direct_tool_capabilities
from killchain_docker.tools.core import ToolExecutionError
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.workers.execution.intent import artifact_triage_intent_is_direct
from killchain_docker.workers.execution.policy import tool_success
from killchain_docker.workers.execution.step import (
    LoopExecutionAgent,
    prepare_execution_metadata,
)
from killchain_docker.workers.results.assembly import worker_result_from_bundle


def run_direct_capability(
    agent: LoopExecutionAgent, task: TodoItem, state: RunState
) -> WorkerResult | None:
    capability = _direct_capability(task, agent.allowed_capabilities)
    if capability is None:
        return None
    rationale = f"deterministic {capability.value} fast path"
    try:
        agent.report_progress(
            state,
            task,
            f"{agent.name} selected {capability.value} from task dispatch intent",
        )
        metadata = prepare_execution_metadata(
            capability=capability,
            todo=task,
            state=state,
            selected_metadata={},
            worker_name=agent.name,
        )
        timeout_raw = metadata.pop("timeout_s", None)
        timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
        agent.report_progress(state, task, f"{agent.name} executing {capability.value}")
        bundle = agent.run_capability(
            task=task, capability=capability, metadata=metadata, timeout_s=timeout_s
        )
        agent.report_progress(state, task, f"{agent.name} completed {capability.value}")
    except (ToolExecutionError, ValueError) as exc:
        return _direct_failure(task, agent.name, capability, str(exc))
    if bundle.state_delta.flag_candidates:
        agent.report_flag_candidates(state, task, bundle.state_delta.flag_candidates)
    output_context = dict(bundle.tool_output.output_context)
    success = tool_success(capability, bundle, output_context)
    return worker_result_from_bundle(
        todo=task,
        worker_name=agent.name,
        capability=capability,
        output_context=output_context,
        summary=bundle.tool_output.summary,
        success=success,
        bundle=bundle,
        rationale=rationale,
    )


def _direct_capability(
    task: TodoItem, allowed_capabilities: tuple[ToolCapability, ...]
) -> ToolCapability | None:
    intent = DispatchIntent.from_context(task.context)
    raw = str(intent.required_capability or "").strip()
    try:
        capability = ToolCapability(raw)
    except ValueError:
        return None
    if capability == ToolCapability.ARTIFACT_TRIAGE and (
        not artifact_triage_intent_is_direct(task)
    ):
        return None
    if capability not in direct_tool_capabilities():
        return None
    if capability not in allowed_capabilities:
        return None
    return capability


def _direct_failure(
    task: TodoItem, worker_name: str, capability: ToolCapability, error_text: str
) -> WorkerResult:
    failure_kind = ToolGuardPolicy.metadata_failure_kind(error_text, capability)
    return WorkerResult(
        todo_id=task.todo_id,
        worker_name=worker_name,
        success=False,
        summary=f"{worker_name} failed deterministic {capability.value}: {error_text}",
        error=error_text,
        retryable=False,
        result_quality=failure_kind,
        output_context={
            "capability": capability.value,
            "failure_kind": failure_kind,
            "failure_detail": error_text,
            "executed": False,
        },
    )


__all__ = ["run_direct_capability"]
