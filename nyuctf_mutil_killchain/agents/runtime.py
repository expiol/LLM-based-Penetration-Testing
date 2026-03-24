"""Runtime execution probe worker for bundled script artifacts."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import WorkerAgent, build_flag_validation_task
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class RuntimeProbeAgent(WorkerAgent):
    """Executes bundled scripts and captures stdout/stderr-derived signals."""

    name = "runtime-probe-agent"
    supported_task_types = ("artifact.runtime_probe",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Runtime probe requires an execution plane; none is configured.",
                error=(
                    "RuntimeProbeAgent.execution_plane is None — "
                    "register the runtime_probe plugin before dispatching artifact.runtime_probe tasks"
                ),
            )

        challenge_meta = state.metadata.get("challenge", {})
        request = ToolExecutionRequest(
            tool_name="runtime_probe",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 60),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 8),
                "flag_format": challenge_meta.get("flag_format"),
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Runtime probe execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        new_tasks = [
            build_flag_validation_task(candidate, source="runtime_probe")
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
            notes=bundle.parsed.notes + [f"{self.name} executed bundled script artifacts."],
        )
