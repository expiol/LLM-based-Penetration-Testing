"""Correction context assembled from recent worker failures."""

from __future__ import annotations

from typing import Any

from killchain_docker.prompt_bounds import trim_text
from killchain_docker.state.execution_projection import ExecutionProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.workers.corrections.instructions import (
    script_correction_instruction,
    shell_correction_instruction,
)


def correction_context(
    *, state: RunState, task: TodoItem, prior_steps: list[dict[str, Any]] | None = None
) -> dict[str, Any] | None:
    """Build bounded correction context from local steps and recent evidence."""
    context = recent_script_failure_context(state, task)
    if not prior_steps:
        return context
    last = prior_steps[-1]
    if last.get("capability") == "script.exec" and (
        last.get("returncode") not in (None, 0) or not last.get("flag_candidates")
    ):
        failure_kind = last.get("failure_kind")
        if not failure_kind and last.get("near_miss_candidates"):
            failure_kind = "near_miss"
        local_context = {
            "instruction": script_correction_instruction(failure_kind),
            "last_traceback": trim_text(last.get("traceback", ""), width=2000),
            "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
            "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
            "failure_kind": failure_kind,
            "failure_detail": last.get("failure_detail"),
        }
        if is_critical_script_failure(context):
            local_context["previous_critical_failure"] = context
        else:
            context = local_context
    elif last.get("capability") == "shell.exec" and last.get("returncode") not in (
        None,
        0,
    ):
        failure_kind = last.get("failure_kind") or "shell_failure"
        context = {
            "instruction": shell_correction_instruction(failure_kind),
            "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
            "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
            "failure_kind": failure_kind,
            "failure_detail": last.get("failure_detail"),
        }
    elif last.get("failure_kind") == "non_http_url_blocked":
        context = {
            "instruction": "The previous tool choice used curl for a non-HTTP endpoint. Curl is only for HTTP/HTTPS. For tcp:// or custom services, choose script.exec and write a small stdlib socket harness with connect/read timeouts <=5 seconds, an overall deadline <=45 seconds, explicit send/receive framing, and concise diagnostics.",
            "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
            "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
            "failure_kind": "non_http_url_blocked",
            "failure_detail": last.get("failure_detail"),
        }
    return context


def is_critical_script_failure(context: dict[str, Any] | None) -> bool:
    if not context:
        return False
    return str(context.get("failure_kind") or "") in {"timeout", "unbounded_loop_guard"}


def recent_script_failure_context(
    state: RunState, task: TodoItem
) -> dict[str, Any] | None:
    failure = ExecutionProjection(state).recent_script_failure_context(
        task_id=getattr(task, "todo_id", "")
    )
    if failure is None:
        return None
    evidence = failure["evidence"]
    ctx = failure["context"]
    failure_kind = failure["failure_kind"]
    return {
        "instruction": script_correction_instruction(failure_kind),
        "last_traceback": trim_text(ctx.get("traceback", ""), width=2000),
        "last_stderr": trim_text(ctx.get("stderr", ""), width=700),
        "last_stdout": trim_text(ctx.get("stdout", ""), width=700),
        "failure_kind": failure_kind,
        "failure_detail": ctx.get("failure_detail"),
        "source_evidence_id": evidence.evidence_id,
    }
