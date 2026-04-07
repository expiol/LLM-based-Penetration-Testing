"""Computation-heavy source analysis worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import EvidenceReviewGuidance
from nyuctf_mutil_killchain.prompts import get_worker_system_prompt, get_exploit_strategy
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class ComputationAnalysisAgent(WorkerAgent):
    """Executes source artifacts and attempts to recover plaintext from transform pipelines."""

    name = "computation-analysis-agent"
    supported_task_types = ("artifact.computation_analysis", "artifact.source_review")
    routing_summary = "Computation-heavy reversing for transform pipelines, checker logic, and encoded blobs."
    preferred_challenge_categories = ("rev", "crypto", "misc")
    required_context_keys = ("source_files",)

    _TRANSFORM_MARKERS = ("checker", "encode", "decode", "decrypt", "cipher", "crypto", "transform", "solve")

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        allowed, reason = super().can_route_task(task, state)
        if not allowed:
            return allowed, reason

        intent = str(
            task.input_context.get("routing_intent")
            or task.metadata.get("routing_intent")
            or ""
        ).lower()
        source_files = [str(item).lower() for item in task.input_context.get("source_files") or []]
        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "").lower()
        has_transform_signal = any(marker in name for marker in self._TRANSFORM_MARKERS for name in source_files)
        if task.task_type == "artifact.source_review":
            if intent in {"computation", "decode", "transform", "reverse"}:
                return True, None
            if task.input_context.get("blob_candidates") or task.metadata.get("blob_candidates"):
                return True, None
            if not has_transform_signal and challenge_category not in {"rev", "crypto"}:
                return False, "no transform-heavy source signals present"
        return True, None

    def routing_score(self, task: Task, state: GlobalState) -> int:
        score = super().routing_score(task, state)
        intent = str(
            task.input_context.get("routing_intent")
            or task.metadata.get("routing_intent")
            or ""
        ).lower()
        if intent in {"computation", "decode", "transform", "reverse"}:
            score += 38
        source_files = [str(item).lower() for item in task.input_context.get("source_files") or []]
        if any(marker in name for marker in self._TRANSFORM_MARKERS for name in source_files):
            score += 20
        if task.input_context.get("blob_candidates") or task.metadata.get("blob_candidates"):
            score += 16
        return score

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Computation analysis requires an execution plane; none is configured.",
                error=(
                    "ComputationAnalysisAgent.execution_plane is None — "
                    "register the computation_analysis plugin before dispatching artifact.computation_analysis tasks"
                ),
            )

        challenge_meta = state.metadata.get("challenge", {})
        request = ToolExecutionRequest(
            tool_name="computation_analysis",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 180),
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
                summary="Computation analysis execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        challenge_category = str(challenge_meta.get("category") or "misc").lower()
        llm_guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze computation-heavy source artifacts: transform pipelines, "
                    "cipher implementations, encoding chains, and checker functions. "
                    + get_exploit_strategy(challenge_category) + " "
                    "Focus on recovering concrete plaintext or flag candidates from "
                    "the recovered functions, constants, and bitstring data."
                ),
                evidence_type="computation-analysis",
                output_schema="EvidenceReviewGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "category": challenge_meta.get("category"),
                        "flag_format": challenge_meta.get("flag_format"),
                    },
                    "computation_analysis_summary": bundle.parsed.summary,
                    "computation_analysis_output_context": bundle.parsed.output_context,
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
            build_flag_validation_task(candidate, source="computation_analysis")
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
            notes=worker_notes + [f"{self.name} analyzed computation-heavy source files."],
        )
