"""Flag-centric CTF worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import StageAnalysisGuidance
from nyuctf_mutil_killchain.prompts import get_worker_system_prompt, get_flag_hints
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class FlagHuntAgent(WorkerAgent):
    """Searches challenge artifacts broadly for grounded flag candidates and submission breadcrumbs."""

    name = "flag-hunt-agent"
    supported_task_types = ("flag.hunt",)
    routing_summary = "Cross-artifact flag hunting for direct flag candidates, decoded blobs, and flag-bearing routes."
    preferred_challenge_categories = ("rev", "crypto", "forensics", "misc", "web", "pwn")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Flag hunting requires an execution plane; none is configured.",
                error="FlagHuntAgent.execution_plane is None",
            )

        request = ToolExecutionRequest(
            tool_name="flag_harvest",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "seed_terms": task.input_context.get("seed_terms", []),
                "max_files": task.input_context.get("max_files", 120),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Flag harvesting execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        output_context = dict(bundle.parsed.output_context)
        flag_candidates = list(output_context.get("flag_candidates") or [])
        interesting_paths = list(output_context.get("interesting_paths") or [])
        manual_checks = list(output_context.get("manual_checks") or [])

        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
        flag_hints = get_flag_hints(challenge_category)
        llm_guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze flag-harvesting evidence to identify the real flag. "
                    "Category-specific hints:\n" +
                    "\n".join(f"- {hint}" for hint in flag_hints) + "\n"
                    "Do not invent flags. Only emit candidates grounded in the evidence."
                ),
                evidence_type="flag-harvesting",
                output_schema="StageAnalysisGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "summary": bundle.parsed.summary,
                    "output_context": output_context,
                    "recent_findings": [
                        {
                            "finding_id": finding.finding_id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "evidence_refs": finding.evidence_refs,
                        }
                        for finding in list(state.findings.values())[-8:]
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=StageAnalysisGuidance,
            fallback_notes=worker_notes,
            failure_label="Flag hunting LLM guidance",
        )

        if llm_guidance is not None:
            flag_candidates = merge_unique_strings(
                flag_candidates,
                llm_guidance.grounded_flag_candidates,
                limit=16,
            )
            interesting_paths = merge_unique_strings(
                interesting_paths,
                llm_guidance.interesting_paths,
                limit=20,
            )
            manual_checks = merge_unique_strings(
                manual_checks,
                llm_guidance.manual_checks,
                limit=8,
            )

        output_context = {
            **output_context,
            "flag_candidates": flag_candidates,
            "interesting_paths": interesting_paths,
            "manual_checks": manual_checks,
        }
        if llm_guidance is not None:
            output_context["llm_summary"] = llm_guidance.summary

        new_tasks = [
            build_flag_validation_task(candidate, source="flag_harvest")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, interesting_paths, priority=76))

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
            notes=worker_notes + [f"{self.name} searched challenge artifacts for direct flag candidates."],
        )
