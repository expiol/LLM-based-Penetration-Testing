"""Binary artifact triage worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import EvidenceReviewGuidance
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class BinaryTriageAgent(WorkerAgent):
    """Performs deeper inspection on bundled binaries."""

    name = "binary-triage-agent"
    supported_task_types = ("artifact.binary_triage", "artifact.deep_review")
    routing_summary = "Binary strings and metadata review for executables, shared objects, and packed artifacts."
    preferred_challenge_categories = ("rev", "pwn", "crypto", "misc")
    required_context_keys = ("binary_files",)

    def routing_score(self, task: Task, state: GlobalState) -> int:
        score = super().routing_score(task, state)
        analysis_kind = str(
            task.input_context.get("analysis_kind")
            or task.metadata.get("analysis_kind")
            or ""
        ).lower()
        if analysis_kind == "binary":
            score += 40
        return score

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

        challenge_meta = state.metadata.get("challenge", {})
        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        llm_guidance = self.generate_structured_output(
            system_prompt=(
                "You analyze structured binary-triage evidence from an authorized CTF workflow. "
                "Return only JSON matching the EvidenceReviewGuidance schema. "
                "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
                "observed strings, URLs, or command paths in the binary evidence."
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "category": challenge_meta.get("category"),
                        "flag_format": challenge_meta.get("flag_format"),
                    },
                    "binary_triage_summary": bundle.parsed.summary,
                    "binary_triage_output_context": bundle.parsed.output_context,
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
            failure_label="Binary triage LLM guidance",
        )
        if llm_guidance is not None:
            flag_candidates = merge_unique_strings(
                flag_candidates,
                llm_guidance.grounded_flag_candidates,
                limit=12,
            )
            manual_checks = merge_unique_strings(
                manual_checks,
                llm_guidance.recommended_checks,
                limit=8,
            )

        new_tasks = [
            build_flag_validation_task(candidate, source="binary_triage")
            for candidate in flag_candidates
        ]
        if llm_guidance is not None:
            new_tasks.extend(build_path_probe_tasks_for_assets(state, llm_guidance.interesting_paths))

        output_context = {
            **bundle.parsed.output_context,
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
            notes=worker_notes + [f"{self.name} inspected bundled binaries."],
        )
