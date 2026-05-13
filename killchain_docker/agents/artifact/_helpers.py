"""Shared helpers for artifact-stage workers.

Provides:

- :class:`PluginInvoker` - run a plugin via :class:`ExecutionPlane`
- :func:`evidence_review_guidance` - request grounded LLM synthesis for an evidence-heavy plugin
- :func:`merge_review_outputs` - apply guidance into output_context
- :func:`success_report` / :func:`tool_failure` / :func:`missing_execution_plane`
- :data:`ARTIFACT_FILES_ROOT` - default container path
"""

from __future__ import annotations

import json
from typing import Any

from killchain_docker.agents._helpers.strings import merge_unique_strings
from killchain_docker.agents.base import WorkerAgent
from killchain_docker.agents.reasoning import EvidenceReviewGuidance
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.tools import (
    ExecutionPlane,
    ToolExecutionBundle,
    ToolExecutionError,
    ToolExecutionRequest,
)


ARTIFACT_FILES_ROOT = "/home/ctfplayer/ctf_files"


def files_root_of(task: Task) -> str:
    return str(task.input_context.get("files_root") or ARTIFACT_FILES_ROOT)


def category_of(state: GlobalState) -> str:
    return str(state.metadata.get("challenge", {}).get("category") or "").lower()


def challenge_meta(state: GlobalState) -> dict[str, Any]:
    return state.metadata.get("challenge", {}) or {}


def run_plugin(
    plane: ExecutionPlane,
    *,
    task_id: str,
    tool_name: str,
    timeout_s: int,
    metadata: dict[str, Any],
    parser_name: str = "jsonl_signals",
) -> ToolExecutionBundle:
    """Submit a plugin call and return the bundle (raises ToolExecutionError on failure)."""
    request = ToolExecutionRequest(
        tool_name=tool_name,
        parser_name=parser_name,
        timeout_s=timeout_s,
        metadata=metadata,
    )
    return plane.execute(task_id, request)


def evidence_review_guidance(
    worker: WorkerAgent,
    *,
    state: GlobalState,
    task: Task,
    summary: str,
    output_context: dict[str, Any],
    guidance_label: str,
    role_addition: str = "",
) -> EvidenceReviewGuidance:
    """Ask the LLM to synthesize :class:`EvidenceReviewGuidance` for an evidence bundle."""
    cm = challenge_meta(state)
    system_prompt = (
        f"You analyze structured {guidance_label} evidence from an authorized CTF workflow. "
        "Return only JSON matching the EvidenceReviewGuidance schema. "
        "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
        "observed evidence. "
        + role_addition
    )
    user_prompt = json.dumps(
        {
            "objective": state.objective,
            "task_id": task.task_id,
            "worker": guidance_label,
            "challenge": {
                "category": cm.get("category"),
                "flag_format": cm.get("flag_format"),
            },
            "summary": summary,
            "output_context": output_context,
            "known_assets": [
                {"asset_id": asset.asset_id, "base_url": asset.base_url}
                for asset in state.assets.values()
                if asset.base_url
            ],
        },
        ensure_ascii=True,
        indent=2,
    )
    return worker.generate_structured_output(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        schema=EvidenceReviewGuidance,
    )


def merge_review_outputs(
    bundle_output_context: dict[str, Any],
    guidance: EvidenceReviewGuidance,
    *,
    flag_limit: int = 12,
    checks_limit: int = 8,
) -> tuple[dict[str, Any], list[str]]:
    """Merge LLM guidance into the plugin's output_context.  Returns ``(merged_ctx, flag_candidates)``."""
    flag_candidates = merge_unique_strings(
        list(bundle_output_context.get("flag_candidates") or []),
        list(guidance.grounded_flag_candidates),
        limit=flag_limit,
    )
    manual_checks = merge_unique_strings(
        list(bundle_output_context.get("manual_checks") or []),
        list(guidance.recommended_checks),
        limit=checks_limit,
    )
    merged = {
        **bundle_output_context,
        "flag_candidates": flag_candidates,
        "manual_checks": manual_checks,
        "llm_summary": guidance.summary,
    }
    return merged, flag_candidates


def success_report(
    *,
    worker_name: str,
    task: Task,
    bundle: ToolExecutionBundle,
    output_context: dict[str, Any],
    new_tasks: list[Task],
    notes: list[str],
    success: bool = True,
    error: str | None = None,
) -> WorkerReport:
    return WorkerReport(
        task_id=task.task_id,
        worker_name=worker_name,
        success=success,
        summary=bundle.parsed.summary,
        output_context=output_context,
        asset_updates=list(bundle.parsed.asset_updates),
        finding_updates=list(bundle.parsed.finding_updates),
        credential_updates=list(bundle.parsed.credential_updates),
        network_updates=list(bundle.parsed.network_updates),
        evidence_updates=[bundle.evidence],
        new_tasks=new_tasks,
        notes=notes,
        error=error,
        retryable=False,
    )


def tool_failure(
    *,
    worker_name: str,
    task: Task,
    label: str,
    exc: Exception,
) -> WorkerReport:
    return WorkerReport(
        task_id=task.task_id,
        worker_name=worker_name,
        success=False,
        summary=f"{label} execution failed.",
        error=str(exc),
    )


def missing_execution_plane(*, worker_name: str, task: Task, hint: str) -> WorkerReport:
    return WorkerReport(
        task_id=task.task_id,
        worker_name=worker_name,
        success=False,
        summary=f"{worker_name} requires an execution plane; none is configured.",
        error=hint,
        retryable=False,
    )


def attempt_plugin(
    worker: WorkerAgent,
    *,
    task: Task,
    tool_name: str,
    timeout_s: int,
    metadata: dict[str, Any],
    label: str,
) -> tuple[ToolExecutionBundle | None, WorkerReport | None]:
    """Convenience: returns (bundle, None) on success, (None, fail_report) on failure."""
    if worker.execution_plane is None:
        return None, missing_execution_plane(
            worker_name=worker.name,
            task=task,
            hint=f"{type(worker).__name__}.execution_plane is None - register the {tool_name!r} plugin",
        )
    try:
        bundle = run_plugin(
            worker.execution_plane,
            task_id=task.task_id,
            tool_name=tool_name,
            timeout_s=timeout_s,
            metadata=metadata,
        )
    except ToolExecutionError as exc:
        return None, tool_failure(worker_name=worker.name, task=task, label=label, exc=exc)
    return bundle, None
