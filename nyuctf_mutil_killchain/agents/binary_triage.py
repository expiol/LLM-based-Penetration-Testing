"""Binary artifact triage worker."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import WorkerAgent, build_flag_validation_task
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class BinaryTriageAgent(WorkerAgent):
    """Performs deeper inspection on bundled binaries."""

    name = "binary-triage-agent"
    supported_task_types = ("artifact.binary_triage",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Binary triage requires an execution plane; none is configured.",
                error=(
                    "BinaryTriageAgent.execution_plane is None — "
                    "register the binary_triage plugin before dispatching artifact.binary_triage tasks"
                ),
            )

        request = ToolExecutionRequest(
            tool_name="binary_triage",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "binary_files": task.input_context.get("binary_files", []),
                "max_files": task.input_context.get("max_files", 6),
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Binary triage execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        new_tasks = [
            build_flag_validation_task(candidate, source="binary_triage")
            for candidate in flag_candidates
        ]

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
            notes=bundle.parsed.notes + [f"{self.name} inspected bundled binaries."],
        )
