"""Runtime execution probe worker for bundled script artifacts."""

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
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class RuntimeProbeAgent(WorkerAgent):
    """Executes bundled scripts and captures stdout/stderr-derived signals."""

    name = "runtime-probe-agent"
    supported_task_types = ("artifact.runtime_probe", "artifact.source_review")
    routing_summary = "Dynamic source execution for script-like artifacts, prompts, and encoded runtime output."
    preferred_challenge_categories = ("rev", "crypto", "misc")
    required_context_keys = ("source_files",)

    _SCRIPT_SUFFIXES = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".rb", ".pl", ".php", ".lua")

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        allowed, reason = super().can_route_task(task, state)
        if not allowed:
            return allowed, reason

        source_files = [str(item).lower() for item in task.input_context.get("source_files") or []]
        intent = str(
            task.input_context.get("routing_intent")
            or task.metadata.get("routing_intent")
            or ""
        ).lower()
        if task.task_type == "artifact.source_review":
            if intent in {"runtime", "dynamic", "execute", "script"}:
                return True, None
            if not any(name.endswith(self._SCRIPT_SUFFIXES) for name in source_files):
                return False, "no runnable script-like sources present"
        return True, None

    def routing_score(self, task: Task, state: GlobalState) -> int:
        score = super().routing_score(task, state)
        intent = str(
            task.input_context.get("routing_intent")
            or task.metadata.get("routing_intent")
            or ""
        ).lower()
        if intent in {"runtime", "dynamic", "execute", "script"}:
            score += 36
        source_files = [str(item).lower() for item in task.input_context.get("source_files") or []]
        if any(name.endswith(self._SCRIPT_SUFFIXES) for name in source_files):
            score += 18
        if task.input_context.get("blob_candidates"):
            score += 12
        return score

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
                retryable=False,
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

        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        challenge_meta = state.metadata.get("challenge", {})
        challenge_category = str(challenge_meta.get("category") or "").lower()
        llm_guidance = self.generate_structured_output(
            system_prompt=(
                "You analyze structured runtime-probe evidence from an authorized CTF workflow. "
                "Return only JSON matching the EvidenceReviewGuidance schema. "
                "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
                "runtime outputs, blob candidates, or observed prompts. "
                "Set promote_computation_analysis when the runtime output suggests reversible transforms, "
                "encoded blobs, or arithmetic-style decoding."
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": {
                        "category": challenge_category,
                        "flag_format": challenge_meta.get("flag_format"),
                    },
                    "runtime_probe_summary": bundle.parsed.summary,
                    "runtime_probe_output_context": bundle.parsed.output_context,
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
            build_flag_validation_task(candidate, source="runtime_probe")
            for candidate in flag_candidates
        ]
        if llm_guidance is not None:
            new_tasks.extend(build_path_probe_tasks_for_assets(state, llm_guidance.interesting_paths))
            if llm_guidance.promote_computation_analysis and challenge_category in {"rev", "crypto", "misc"}:
                new_tasks.append(
                    build_source_review_task(
                        files_root=task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                        source_files=list(task.input_context.get("source_files") or [])[:12],
                        routing_intent="computation",
                        exclude_workers=[self.name],
                        routing_notes=[llm_guidance.summary],
                    )
                )

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
            notes=worker_notes + [f"{self.name} executed bundled script artifacts."],
        )
