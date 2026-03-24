"""Source artifact review worker."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_http_path_probe_task,
)
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class SourceReviewAgent(WorkerAgent):
    """Inspects bundled source files for routes, secrets, and flags."""

    name = "source-review-agent"
    supported_task_types = ("artifact.source_review",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Source review requires an execution plane; none is configured.",
                error=(
                    "SourceReviewAgent.execution_plane is None — "
                    "register the source_review plugin before dispatching artifact.source_review tasks"
                ),
            )

        request = ToolExecutionRequest(
            tool_name="source_review",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 12),
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Source review execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        interesting_routes = list(bundle.parsed.output_context.get("interesting_routes") or [])
        new_tasks = [
            build_flag_validation_task(candidate, source="source_review")
            for candidate in flag_candidates
        ]
        for asset in state.assets.values():
            if asset.base_url and interesting_routes:
                new_tasks.append(
                    build_http_path_probe_task(
                        asset_id=asset.asset_id,
                        base_url=asset.base_url,
                        paths=interesting_routes,
                    )
                )

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=bundle.parsed.notes + [f"{self.name} reviewed bundled source files."],
        )
