"""Computation analysis worker - dynamic probe of source transforms."""

from __future__ import annotations

import json
from pathlib import Path

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
from killchain_docker.reasoning import EvidenceReviewGuidance
from killchain_docker.prompts import get_exploit_strategy, get_worker_system_prompt
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
)
from killchain_docker.tools import ToolCapability, capability_source


class ComputationAnalysisAgent(WorkerAgent):
    """Run computation analysis and synthesize plaintext/flag candidates."""

    name = "computation-analysis-agent"
    supported_task_types = ("artifact.computation_analysis",)
    required_context_keys = ("source_files",)
    routing_summary = (
        "Execute bundled source transform pipelines, recover plaintext and flag "
        "candidates from cipher / encoding implementations."
    )
    preferred_challenge_categories = ("rev", "crypto", "misc")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        cm = challenge_meta(state)
        category = category_of(state) or "misc"
        input_files = list(task.input_context.get("source_files") or [])
        source_files = [
            path for path in input_files
            if Path(str(path)).suffix.lower() == ".py"
        ]
        skipped_files = [path for path in input_files if path not in source_files]
        if not source_files:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=True,
                summary="Computation analysis skipped because no Python source files were provided.",
                output_context={
                    "source_files": [],
                    "skipped_files": skipped_files,
                    "skip_reason": "no_python_source_files",
                },
                notes=[
                    f"{self.name} skipped {len(skipped_files)} non-Python file(s).",
                ],
                retryable=False,
            )

        capability = ToolCapability.ARTIFACT_COMPUTATION
        bundle, fail = run_capability(
            self,
            task=task,
            capability=capability,
            timeout_s=int(task.input_context.get("timeout_s", 180)),
            metadata={
                "files_root": files_root_of(task),
                "source_files": source_files,
                "max_files": task.input_context.get("max_files", 8),
                "flag_format": cm.get("flag_format"),
            },
            label="Computation analysis",
        )
        if fail is not None:
            return fail
        assert bundle is not None

        worker_notes = list(bundle.parsed.notes)
        guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                category,
                worker_role=(
                    "You analyze computation-heavy source artifacts: transform pipelines, "
                    "cipher implementations, encoding chains, and checker functions. "
                    + get_exploit_strategy(category) + " "
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
                        "category": cm.get("category"),
                        "flag_format": cm.get("flag_format"),
                    },
                    "computation_analysis_summary": bundle.parsed.summary,
                    "computation_analysis_output_context": bundle.parsed.output_context,
                    "known_assets": [
                        {"asset_id": asset.asset_id, "base_url": asset.base_url}
                        for asset in state.assets.values() if asset.base_url
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=EvidenceReviewGuidance,
        )

        flag_candidates = merge_unique_strings(
            list(bundle.parsed.output_context.get("flag_candidates") or []),
            guidance.grounded_flag_candidates,
            limit=12,
        )
        manual_checks = merge_unique_strings(
            list(bundle.parsed.output_context.get("manual_checks") or []),
            guidance.recommended_checks,
            limit=8,
        )

        suggested_tasks: list[Task] = build_flag_validation_tasks(
            flag_candidates, source=capability_source(capability)
        )
        suggested_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

        output_context = {
            **bundle.parsed.output_context,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
            "llm_summary": guidance.summary,
        }

        inspected = list(output_context.get("inspected_sources") or [])
        success = bool(inspected)
        error: str | None = None
        notes_tail: list[str] = []
        if not success:
            error = (
                f"{capability_source(capability)}: 0 source(s) inspected; "
                f"none of the {len(input_files)} input file(s) were Python sources."
            )
            notes_tail.append(
                f"{self.name} inspected 0 sources; do not reschedule with the same source_files."
            )

        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=output_context,
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks if success else []),
            notes=worker_notes + [f"{self.name} analyzed computation-heavy source files."] + notes_tail,
            success=success,
            error=error,
        )
