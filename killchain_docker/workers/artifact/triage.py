"""Top-level artifact triage worker - inventories challenge files."""

from __future__ import annotations

import json

from killchain_docker.workers._helpers.strings import merge_unique_strings
from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.artifact._helpers import (
    category_of,
    challenge_meta,
    files_root_of,
    run_capability,
    success_report,
)
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.reasoning import (
    ArtifactTriageGuidance,
    boost_prioritized_tasks,
)
from killchain_docker.prompts import (
    get_analysis_strategy,
    get_worker_system_prompt,
)
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_artifact_deep_review_task,
    build_flag_validation_tasks,
    build_source_review_task,
)
from killchain_docker.tools import ToolCapability, capability_source


class ArtifactTriageAgent(WorkerAgent):
    """Inventory bundled challenge files and propose follow-up reviews."""

    name = "artifact-triage-agent"
    supported_task_types = ("artifact.triage",)
    routing_summary = (
        "Top-level inventory of bundled challenge files. Classifies them and "
        "fans out per-kind deep-review tasks (binary, archive, source, sqlite, pcap, repo)."
    )
    preferred_challenge_categories = ("misc", "forensics", "rev", "crypto", "web", "pwn")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        cm = challenge_meta(state)
        capability = ToolCapability.ARTIFACT_TRIAGE
        bundle, fail = run_capability(
            self,
            task=task,
            capability=capability,
            timeout_s=int(task.input_context.get("timeout_s", 90)),
            metadata={
                "files_root": files_root_of(task),
                "challenge_files": cm.get("files", []),
                "max_files": task.input_context.get("max_files", 80),
            },
            label="Artifact triage",
        )
        if fail is not None:
            return fail
        assert bundle is not None

        category = category_of(state)
        worker_notes = list(bundle.parsed.notes)
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
        manual_checks = list(output_context.get("manual_checks") or [])

        source_routing_intent = "static"
        if script_files and category in {"rev", "crypto"}:
            source_routing_intent = "computation"
        elif script_files and category in {"misc", "pwn"}:
            source_routing_intent = "runtime"

        follow_up_tasks: list[Task] = []
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
        if binary_files and category in {"rev", "pwn", "crypto", "misc"}:
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

        guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                category,
                worker_role=(
                    "You prioritize follow-up work for artifact analysis. "
                    "Rank task types and analysis kinds based on which are most likely to yield the flag. "
                    "Use source_routing_intent to steer the initial source-analysis worker choice. "
                    + get_analysis_strategy(category)
                ),
                evidence_type="artifact triage",
                output_schema="ArtifactTriageGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "name": cm.get("name"),
                        "category": category,
                        "flag_format": cm.get("flag_format"),
                        "files": cm.get("files", []),
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
        )

        flag_candidates = merge_unique_strings(flag_candidates, guidance.extra_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, guidance.manual_checks, limit=8)
        if guidance.source_routing_intent:
            source_routing_intent = guidance.source_routing_intent

        for candidate in follow_up_tasks:
            if candidate.task_type == "artifact.source_review":
                candidate.input_context["routing_intent"] = source_routing_intent
                candidate.metadata["routing_intent"] = source_routing_intent
                if guidance.preferred_source_workers:
                    candidate.metadata["preferred_workers"] = guidance.preferred_source_workers[:6]

        boost_prioritized_tasks(
            follow_up_tasks,
            guidance.prioritized_task_types,
            guidance.prioritized_analysis_kinds,
        )

        merged_context = {
            **output_context,
            "manual_checks": manual_checks,
            "llm_summary": guidance.summary,
            "llm_focus_files": guidance.focus_files[:12],
            "llm_prioritized_task_types": guidance.prioritized_task_types[:8],
            "llm_prioritized_analysis_kinds": guidance.prioritized_analysis_kinds[:8],
            "source_routing_intent": source_routing_intent,
        }

        suggested_tasks = build_flag_validation_tasks(
            flag_candidates, source=capability_source(capability)
        ) + follow_up_tasks

        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=merged_context,
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks),
            notes=worker_notes + [f"{self.name} inventoried challenge files."],
        )
