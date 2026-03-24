"""Challenge file triage worker."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import (
    build_computation_analysis_task,
    build_archive_triage_task,
    build_runtime_probe_task,
    WorkerAgent,
    build_binary_triage_task,
    build_flag_validation_task,
    build_pcap_review_task,
    build_repo_review_task,
    build_sqlite_review_task,
    build_source_review_task,
)
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class ArtifactTriageAgent(WorkerAgent):
    """Inventories challenge files copied into the NYU agent container."""

    name = "artifact-triage-agent"
    supported_task_types = ("artifact.triage",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Artifact triage requires an execution plane; none is configured.",
                error=(
                    "ArtifactTriageAgent.execution_plane is None — "
                    "register the artifact_triage plugin before dispatching artifact.triage tasks"
                ),
            )

        challenge_meta = state.metadata.get("challenge", {})
        request = ToolExecutionRequest(
            tool_name="artifact_triage",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 90),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "challenge_files": challenge_meta.get("files", []),
                "max_files": task.input_context.get("max_files", 80),
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Artifact triage execution failed.",
                error=str(exc),
            )

        challenge_meta = state.metadata.get("challenge", {})
        challenge_category = str(challenge_meta.get("category") or "").lower()
        output_context = bundle.parsed.output_context
        files_root = str(output_context.get("files_root") or "/home/ctfplayer/ctf_files")
        binary_files = list(output_context.get("binary_files") or [])
        archive_files = list(output_context.get("archive_files") or [])
        database_files = list(output_context.get("database_files") or [])
        pcap_files = list(output_context.get("pcap_files") or [])
        repo_paths = list(output_context.get("repo_paths") or [])
        source_files = list(output_context.get("web_source_files") or [])
        script_files = list(output_context.get("script_files") or [])
        flag_candidates = list(output_context.get("flag_candidates") or [])

        new_tasks = [
            build_flag_validation_task(candidate, source="artifact_triage")
            for candidate in flag_candidates
        ]
        if archive_files:
            new_tasks.append(
                build_archive_triage_task(
                    files_root=files_root,
                    archive_files=archive_files[:8],
                )
            )
        if binary_files and challenge_category in {"rev", "pwn", "crypto", "misc"}:
            new_tasks.append(
                build_binary_triage_task(
                    files_root=files_root,
                    binary_files=binary_files[:8],
                )
            )
        if database_files:
            new_tasks.append(
                build_sqlite_review_task(
                    files_root=files_root,
                    database_files=database_files[:8],
                )
            )
        if pcap_files:
            new_tasks.append(
                build_pcap_review_task(
                    files_root=files_root,
                    pcap_files=pcap_files[:8],
                )
            )
        if repo_paths:
            new_tasks.append(
                build_repo_review_task(
                    files_root=files_root,
                    repo_paths=repo_paths[:6],
                )
            )
        if source_files:
            new_tasks.append(
                build_source_review_task(
                    files_root=files_root,
                    source_files=source_files[:12],
                )
            )
            if script_files and challenge_category in {"rev", "crypto", "misc"}:
                new_tasks.append(
                    build_runtime_probe_task(
                        files_root=files_root,
                        source_files=script_files[:12],
                    )
                )
            if challenge_category in {"rev", "crypto", "misc"}:
                new_tasks.append(
                    build_computation_analysis_task(
                        files_root=files_root,
                        source_files=source_files[:12],
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
            notes=bundle.parsed.notes + [f"{self.name} inventoried challenge files."],
        )
