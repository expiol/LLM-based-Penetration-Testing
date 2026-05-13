"""Archive triage worker - extract members and fan out source review."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.artifact._helpers import (
    attempt_plugin,
    evidence_review_guidance,
    files_root_of,
    merge_review_outputs,
    success_report,
)
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import (
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
    build_source_review_task,
)


class ArchiveTriageAgent(WorkerAgent):
    """Extract bundled archives and propose follow-up source/flag review."""

    name = "archive-triage-agent"
    supported_task_types = ("artifact.archive_triage", "artifact.deep_review")
    required_context_keys = ("archive_files",)
    routing_summary = "Extract bundled .zip/.tar/.gz archives and surface source-like inner files for review."
    preferred_challenge_categories = ("web", "forensics", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type == "artifact.archive_triage":
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind == "archive"
        return False

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        bundle, fail = attempt_plugin(
            self,
            task=task,
            tool_name="archive_triage",
            timeout_s=int(task.input_context.get("timeout_s", 120)),
            metadata={
                "files_root": files_root_of(task),
                "archive_files": task.input_context.get("archive_files", []),
                "max_files": task.input_context.get("max_files", 8),
            },
            label="Archive triage",
        )
        if fail is not None:
            return fail
        assert bundle is not None

        worker_notes = list(bundle.parsed.notes)
        guidance = evidence_review_guidance(
            self,
            state=state,
            task=task,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            guidance_label="archive triage",
        )
        merged_ctx, flag_candidates = merge_review_outputs(
            bundle.parsed.output_context, guidance,
        )

        source_like_members = list(
            merged_ctx.get("qualified_source_like_members")
            or merged_ctx.get("source_like_members")
            or []
        )
        new_tasks: list[Task] = build_flag_validation_tasks(
            flag_candidates, source="archive_triage"
        )
        if source_like_members:
            new_tasks.append(
                build_source_review_task(
                    files_root=str(merged_ctx.get("files_root") or "/home/ctfplayer/ctf_files"),
                    source_files=source_like_members[:12],
                )
            )
        new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=merged_ctx,
            new_tasks=new_tasks,
            notes=worker_notes + [f"{self.name} reviewed bundled archives."],
        )
