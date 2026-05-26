"""WorkerResult assembly from executed tool bundles."""

from __future__ import annotations

from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.execution_policy import INFRASTRUCTURE_FAILURE_KINDS
from killchain_docker.workers.task_intent import is_execution_closure_task


def worker_result_from_bundle(
    *,
    todo: TodoItem,
    worker_name: str,
    capability: ToolCapability,
    output_context: dict[str, object],
    summary: str,
    success: bool,
    bundle: ToolExecutionBundle,
    rationale: str,
) -> WorkerResult:
    state_delta = bundle.state_delta
    flag_values = [candidate.value for candidate in state_delta.flag_candidates]
    partial = False
    partial_reason = None
    result_quality = str(output_context.get("result_quality") or "")
    failure_kind = str(output_context.get("failure_kind") or "").strip()
    if failure_kind in INFRASTRUCTURE_FAILURE_KINDS:
        output_context["result_quality"] = failure_kind
        output_context["worker_rationale"] = rationale
        output_context["capability"] = capability.value
        return WorkerResult(
            todo_id=todo.todo_id,
            worker_name=worker_name,
            success=False,
            summary=summary,
            error=str(output_context.get("failure_detail") or summary),
            output_context=output_context,
            asset_updates=bundle.tool_output.assets,
            finding_updates=bundle.tool_output.findings,
            credential_updates=bundle.tool_output.credentials,
            network_updates=bundle.tool_output.network_edges,
            state_delta=state_delta,
            evidence_updates=[bundle.evidence],
            notes=list(bundle.tool_output.notes),
            retryable=True,
            partial=False,
            result_quality=failure_kind,
        )
    needs_closure = is_execution_closure_task(todo)
    if (
        capability == ToolCapability.SCRIPT_EXEC
        and success
        and (not flag_values)
        and needs_closure
    ):
        has_near_miss = bool(output_context.get("near_miss_candidates"))
        partial = True
        if not has_near_miss:
            partial_reason = (
                str(output_context.get("partial_reason") or "").strip()
                or "script completed for a flag-recovery task but produced no flag candidate"
            )
            result_quality = result_quality or "partial_no_candidate"
            output_context["agent_handoff"] = {
                "reason": "script_exec_completed_without_candidate",
                "target": "planner",
            }
        else:
            partial_reason = (
                str(output_context.get("partial_reason") or "").strip()
                or "script completed with near-miss candidates but no valid flag candidate"
            )
            result_quality = result_quality or "near_miss"
            output_context["agent_handoff"] = {
                "reason": "script_exec_near_miss_without_candidate",
                "target": "planner",
            }
        output_context["result_quality"] = result_quality
        output_context["partial_reason"] = partial_reason
    elif capability == ToolCapability.SCRIPT_EXEC and (not success) and needs_closure:
        partial = True
        failure_detail = str(output_context.get("failure_detail") or "").strip()
        partial_reason = (
            failure_detail
            or failure_kind
            or "script execution failed before recovering a flag"
        )
        result_quality = result_quality or failure_kind or "script_failed"
        output_context["result_quality"] = result_quality
        output_context["partial_reason"] = partial_reason
    output_context["worker_rationale"] = rationale
    output_context["capability"] = capability.value
    return WorkerResult(
        todo_id=todo.todo_id,
        worker_name=worker_name,
        success=success,
        summary=summary,
        output_context=output_context,
        asset_updates=bundle.tool_output.assets,
        finding_updates=bundle.tool_output.findings,
        credential_updates=bundle.tool_output.credentials,
        network_updates=bundle.tool_output.network_edges,
        state_delta=state_delta,
        evidence_updates=[bundle.evidence],
        notes=list(bundle.tool_output.notes),
        retryable=False,
        partial=partial,
        result_quality=result_quality or None,
        partial_reason=partial_reason,
    )
