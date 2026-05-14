"""Reusable simple-review template for capability-backed artifact workers.

Used by binary/sqlite/pcap/repo workers - they all share the same shape:

    capability -> bundle -> LLM grounding -> follow-up flag.validate / web.path_probe.
"""

from __future__ import annotations

from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.artifact._helpers import (
    evidence_review_guidance,
    files_root_of,
    merge_review_outputs,
    run_capability,
    success_report,
)
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
)
from killchain_docker.tools import ToolCapability, capability_source


def run_simple_review(
    worker: WorkerAgent,
    task: Task,
    state: GlobalState,
    *,
    capability: ToolCapability,
    evidence_label: str,
    input_field: str,
    processed_field: str,
    max_files_default: int,
    timeout_default: int,
    summary_suffix: str,
    role_addition: str = "",
) -> WorkerReport:
    """Run an evidence-review capability and synthesize follow-ups.

    If the capability processed zero items in *processed_field*, the worker
    returns ``success=False`` so the LLM receives a clear "no work done"
    signal instead of a silent success that encourages re-scheduling
    the same no-op task.
    """
    bundle, fail = run_capability(
        worker,
        task=task,
        capability=capability,
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

    source = capability_source(capability)
    suggested_tasks = build_flag_validation_tasks(flag_candidates, source=source)
    suggested_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

    processed_items = list(merged_ctx.get(processed_field) or [])
    success = bool(processed_items)
    error: str | None = None
    notes_tail: list[str] = []
    if not success:
        input_items = task.input_context.get(input_field) or []
        error = (
            f"{source}: 0 item(s) in {processed_field!r}; "
            f"capability found nothing to inspect among {len(input_items)} input file(s)."
        )
        notes_tail.append(
            f"{worker.name} found 0 processable {processed_field}; do not reschedule with the same input."
        )

    return success_report(
        worker_name=worker.name,
        task=task,
        bundle=bundle,
        output_context=merged_ctx,
        planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks if success else []),
        notes=worker_notes + [f"{worker.name} {summary_suffix}."] + notes_tail,
        success=success,
        error=error,
    )
