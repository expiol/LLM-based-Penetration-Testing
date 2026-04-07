"""Source artifact review worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    build_source_review_task,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import EvidenceReviewGuidance
from nyuctf_mutil_killchain.prompts import get_worker_system_prompt, get_analysis_strategy
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class SourceReviewAgent(WorkerAgent):
    """Inspects bundled source files for routes, secrets, and flags."""

    name = "source-review-agent"
    supported_task_types = ("artifact.source_review",)
    routing_summary = "Static source analysis for routes, templates, secrets, and flag-like literals."
    preferred_challenge_categories = ("web", "misc", "forensics", "rev", "crypto")
    required_context_keys = ("source_files",)

    def routing_score(self, task: Task, state: GlobalState) -> int:
        score = super().routing_score(task, state)
        intent = str(
            task.input_context.get("routing_intent")
            or task.metadata.get("routing_intent")
            or ""
        ).lower()
        if intent in {"", "static", "source", "review"}:
            score += 24
        source_files = [str(item).lower() for item in task.input_context.get("source_files") or []]
        if any(
            name.endswith((".html", ".htm", ".js", ".php", ".tera", ".sql", ".yaml", ".yml"))
            for name in source_files
        ):
            score += 16
        if any(asset.base_url for asset in state.assets.values()):
            score += 8
        return score

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

        challenge_meta = state.metadata.get("challenge", {})
        challenge_category = str(challenge_meta.get("category") or "").lower()
        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        interesting_routes = list(bundle.parsed.output_context.get("interesting_routes") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])

        llm_guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze source code from bundled challenge files. "
                    "Look for routes, secrets, hardcoded credentials, SQL queries, "
                    "template injection points, and flag-like tokens. "
                    + get_analysis_strategy(challenge_category) + " "
                    "Use promote_runtime_probe when scripts should be executed, or "
                    "promote_computation_analysis when reversible transforms are found."
                ),
                evidence_type="source-review",
                output_schema="EvidenceReviewGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "category": challenge_category,
                        "flag_format": challenge_meta.get("flag_format"),
                    },
                    "source_review_summary": bundle.parsed.summary,
                    "source_review_output_context": bundle.parsed.output_context,
                    "known_assets": [
                        {"asset_id": asset.asset_id, "base_url": asset.base_url}
                        for asset in state.assets.values()
                        if asset.base_url
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=EvidenceReviewGuidance,
            fallback_notes=worker_notes,
            failure_label="Source review LLM guidance",
        )
        if llm_guidance is not None:
            flag_candidates = merge_unique_strings(
                flag_candidates,
                llm_guidance.grounded_flag_candidates,
                limit=12,
            )
            interesting_routes = merge_unique_strings(
                interesting_routes,
                llm_guidance.interesting_paths,
                limit=20,
            )
            manual_checks = merge_unique_strings(
                manual_checks,
                llm_guidance.recommended_checks,
                limit=8,
            )

        new_tasks = [
            build_flag_validation_task(candidate, source="source_review")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, interesting_routes))

        source_files = list(task.input_context.get("source_files") or [])
        if source_files and llm_guidance is not None and challenge_category in {"rev", "crypto", "misc"}:
            if llm_guidance.promote_runtime_probe:
                new_tasks.append(
                    build_source_review_task(
                        files_root=task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                        source_files=source_files[:12],
                        routing_intent="runtime",
                        exclude_workers=[self.name],
                        routing_notes=[llm_guidance.summary],
                    )
                )
            if llm_guidance.promote_computation_analysis:
                new_tasks.append(
                    build_source_review_task(
                        files_root=task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                        source_files=source_files[:12],
                        routing_intent="computation",
                        exclude_workers=[self.name],
                        routing_notes=[llm_guidance.summary],
                    )
                )

        output_context = {
            **bundle.parsed.output_context,
            "interesting_routes": interesting_routes,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
        }
        if llm_guidance is not None:
            output_context["llm_summary"] = llm_guidance.summary

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
            notes=worker_notes + [f"{self.name} reviewed bundled source files."],
        )
