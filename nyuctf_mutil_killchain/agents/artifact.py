"""Challenge file triage worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_artifact_deep_review_task,
    build_flag_validation_task,
    build_source_review_task,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import (
    ArtifactTriageGuidance,
    boost_prioritized_tasks,
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
        worker_notes = list(bundle.parsed.notes)
        files_root = str(output_context.get("files_root") or "/home/ctfplayer/ctf_files")
        binary_files = list(output_context.get("binary_files") or [])
        archive_files = list(output_context.get("archive_files") or [])
        database_files = list(output_context.get("database_files") or [])
        pcap_files = list(output_context.get("pcap_files") or [])
        repo_paths = list(output_context.get("repo_paths") or [])
        source_files = list(output_context.get("web_source_files") or [])
        script_files = list(output_context.get("script_files") or [])
        flag_candidates = list(output_context.get("flag_candidates") or [])
        manual_checks = list(output_context.get("manual_checks") or [])

        source_routing_intent = "static"
        if script_files and challenge_category in {"rev", "crypto"}:
            source_routing_intent = "computation"
        elif script_files and challenge_category in {"misc", "pwn"}:
            source_routing_intent = "runtime"

        follow_up_tasks = []
        if archive_files:
            follow_up_tasks.append(
                build_artifact_deep_review_task(
                    files_root=files_root,
                    analysis_kind="archive",
                    context_field="archive_files",
                    items=archive_files[:8],
                    priority=83,
                )
            )
        if binary_files and challenge_category in {"rev", "pwn", "crypto", "misc"}:
            follow_up_tasks.append(
                build_artifact_deep_review_task(
                    files_root=files_root,
                    analysis_kind="binary",
                    context_field="binary_files",
                    items=binary_files[:8],
                    priority=84,
                )
            )
        if database_files:
            follow_up_tasks.append(
                build_artifact_deep_review_task(
                    files_root=files_root,
                    analysis_kind="sqlite",
                    context_field="database_files",
                    items=database_files[:8],
                    priority=81,
                )
            )
        if pcap_files:
            follow_up_tasks.append(
                build_artifact_deep_review_task(
                    files_root=files_root,
                    analysis_kind="pcap",
                    context_field="pcap_files",
                    items=pcap_files[:8],
                    priority=80,
                )
            )
        if repo_paths:
            follow_up_tasks.append(
                build_artifact_deep_review_task(
                    files_root=files_root,
                    analysis_kind="repo",
                    context_field="repo_paths",
                    items=repo_paths[:6],
                    priority=79,
                )
            )
        if source_files:
            follow_up_tasks.append(
                build_source_review_task(
                    files_root=files_root,
                    source_files=source_files[:12],
                    routing_intent=source_routing_intent,
                )
            )

        llm_guidance = self.generate_structured_output(
            system_prompt=(
                "You prioritize follow-up work for an authorized CTF artifact-analysis pipeline. "
                "Return only JSON matching the ArtifactTriageGuidance schema. "
                "Only rank task types or analysis kinds that are already present in the supplied follow_up_tasks list. "
                "Use source_routing_intent to steer the initial source-analysis worker choice when source files exist. "
                "Only emit extra_flag_candidates that are directly grounded in the provided evidence or "
                "that fit the provided flag_format hint without inventing new content."
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "name": challenge_meta.get("name"),
                        "category": challenge_category,
                        "flag_format": challenge_meta.get("flag_format"),
                        "files": challenge_meta.get("files", []),
                    },
                    "artifact_summary": bundle.parsed.summary,
                    "artifact_output_context": output_context,
                    "follow_up_tasks": [
                        {
                            "task_type": candidate.task_type,
                            "priority": candidate.priority,
                            "analysis_kind": candidate.input_context.get("analysis_kind"),
                            "routing_intent": candidate.input_context.get("routing_intent"),
                            "files_hint": (
                                candidate.input_context.get("source_files")
                                or candidate.input_context.get("binary_files")
                                or candidate.input_context.get("archive_files")
                                or candidate.input_context.get("database_files")
                                or candidate.input_context.get("pcap_files")
                                or candidate.input_context.get("repo_paths")
                                or []
                            )[:4],
                        }
                        for candidate in follow_up_tasks
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=ArtifactTriageGuidance,
            fallback_notes=worker_notes,
            failure_label="Artifact triage LLM guidance",
        )

        if llm_guidance is not None:
            flag_candidates = merge_unique_strings(
                flag_candidates,
                llm_guidance.extra_flag_candidates,
                limit=12,
            )
            manual_checks = merge_unique_strings(
                manual_checks,
                llm_guidance.manual_checks,
                limit=8,
            )
            if llm_guidance.source_routing_intent:
                source_routing_intent = llm_guidance.source_routing_intent
            updated_follow_ups: list[Task] = []
            for candidate in follow_up_tasks:
                if candidate.task_type == "artifact.source_review":
                    candidate.input_context["routing_intent"] = source_routing_intent
                    candidate.metadata["routing_intent"] = source_routing_intent
                    if llm_guidance.preferred_source_workers:
                        candidate.metadata["preferred_workers"] = llm_guidance.preferred_source_workers[:6]
                updated_follow_ups.append(candidate)
            follow_up_tasks = updated_follow_ups
            boost_prioritized_tasks(
                follow_up_tasks,
                llm_guidance.prioritized_task_types,
                llm_guidance.prioritized_analysis_kinds,
            )
            output_context = {
                **output_context,
                "manual_checks": manual_checks,
                "llm_summary": llm_guidance.summary,
                "llm_focus_files": llm_guidance.focus_files[:12],
                "llm_prioritized_task_types": llm_guidance.prioritized_task_types[:8],
                "llm_prioritized_analysis_kinds": llm_guidance.prioritized_analysis_kinds[:8],
                "source_routing_intent": source_routing_intent,
            }
        elif source_files:
            output_context = {
                **output_context,
                "source_routing_intent": source_routing_intent,
            }

        new_tasks = [
            build_flag_validation_task(candidate, source="artifact_triage")
            for candidate in flag_candidates
        ] + follow_up_tasks

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + [f"{self.name} inventoried challenge files."],
        )
