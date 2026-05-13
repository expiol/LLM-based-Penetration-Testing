"""Reusable simple-review template for plugin-backed artifact workers.

Used by binary/sqlite/pcap/repo workers - they all share the same shape:

    plugin -> bundle -> LLM grounding -> follow-up flag.validate / web.path_probe.
"""

from __future__ import annotations

from killchain_docker.agents.artifact._helpers import (
    attempt_plugin,
    evidence_review_guidance,
    files_root_of,
    merge_review_outputs,
    success_report,
)
from killchain_docker.agents.base import WorkerAgent
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
)


def run_simple_review(
    worker: WorkerAgent,
    task: Task,
    state: GlobalState,
    *,
    tool_name: str,
    evidence_label: str,
    input_field: str,
    processed_field: str,
    max_files_default: int,
    timeout_default: int,
    summary_suffix: str,
    role_addition: str = "",
) -> WorkerReport:
    """Run an evidence-review plugin and synthesize follow-ups.

    If the plugin processed zero items in *processed_field*, the worker
    returns ``success=False`` so the LLM receives a clear "no work done"
    signal instead of a silent success that encourages re-scheduling
    the same no-op task.
    """
    bundle, fail = attempt_plugin(
        worker,
        task=task,
        tool_name=tool_name,
        timeout_s=int(task.input_context.get("timeout_s", timeout_default)),
        metadata={
            "files_root": files_root_of(task),
            input_field: task.input_context.get(input_field, []),
            "max_files": task.input_context.get("max_files", max_files_default),
        },
        label=evidence_label,
    )
    if fail is not None:
        return fail
    assert bundle is not None

    worker_notes = list(bundle.parsed.notes)
    guidance = evidence_review_guidance(
        worker,
        state=state,
        task=task,
        summary=bundle.parsed.summary,
        output_context=bundle.parsed.output_context,
        guidance_label=evidence_label,
        role_addition=role_addition,
    )
    merged_ctx, flag_candidates = merge_review_outputs(
        bundle.parsed.output_context, guidance,
    )

    new_tasks = build_flag_validation_tasks(flag_candidates, source=tool_name)
    new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

    processed_items = list(merged_ctx.get(processed_field) or [])
    success = bool(processed_items)
    error: str | None = None
    notes_tail: list[str] = []
    if not success:
        input_items = task.input_context.get(input_field) or []
        error = (
            f"{tool_name}: 0 item(s) in {processed_field!r}; "
            f"plugin found nothing to inspect among {len(input_items)} input file(s)."
        )
        notes_tail.append(
            f"{worker.name} found 0 processable {processed_field}; do not reschedule with the same input."
        )

    return success_report(
        worker_name=worker.name,
        task=task,
        bundle=bundle,
        output_context=merged_ctx,
        new_tasks=new_tasks if success else [],
        notes=worker_notes + [f"{worker.name} {summary_suffix}."] + notes_tail,
        success=success,
        error=error,
    )
