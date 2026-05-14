"""Runtime probe worker - execute bundled scripts inside the container."""

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
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
    build_source_review_task,
)
from killchain_docker.tools import ToolCapability, capability_source

_RUNTIME_SCRIPT_EXTS = frozenset({
    ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".rb", ".pl",
    ".php", ".lua",
})


class RuntimeProbeAgent(WorkerAgent):
    """Run bundled scripts and capture flag candidates / blob outputs."""

    name = "runtime-probe-agent"
    supported_task_types = ("artifact.runtime_probe",)
    required_context_keys = ("source_files",)
    routing_summary = (
        "Execute bundled scripts in the container; capture stdout, blob candidates, "
        "and observed prompts for grounded follow-up reasoning."
    )
    preferred_challenge_categories = ("misc", "pwn", "forensics")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        cm = challenge_meta(state)
        category = category_of(state)
        input_files = list(task.input_context.get("source_files") or [])
        source_files = [
            path for path in input_files
            if Path(str(path)).suffix.lower() in _RUNTIME_SCRIPT_EXTS
        ]
        skipped_files = [path for path in input_files if path not in source_files]
        if not source_files:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=True,
                summary="Runtime probe skipped because no executable script files were provided.",
                output_context={
                    "source_files": [],
                    "skipped_files": skipped_files,
                    "skip_reason": "no_executable_script_files",
                },
                notes=[
                    f"{self.name} skipped {len(skipped_files)} non-script file(s).",
                ],
                retryable=False,
            )

        capability = ToolCapability.ARTIFACT_RUNTIME
        bundle, fail = run_capability(
            self,
            task=task,
            capability=capability,
            timeout_s=int(task.input_context.get("timeout_s", 60)),
            metadata={
                "files_root": files_root_of(task),
                "source_files": source_files,
                "max_files": task.input_context.get("max_files", 8),
                "flag_format": cm.get("flag_format"),
            },
            label="Runtime probe",
        )
        if fail is not None:
            return fail
        assert bundle is not None

        worker_notes = list(bundle.parsed.notes)
        guidance = self.generate_structured_output(
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
                        "category": category,
                        "flag_format": cm.get("flag_format"),
                    },
                    "runtime_probe_summary": bundle.parsed.summary,
                    "runtime_probe_output_context": bundle.parsed.output_context,
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
        if guidance.promote_computation_analysis and category in {"rev", "crypto", "misc"}:
            suggested_tasks.append(
                build_source_review_task(
                    files_root=files_root_of(task),
                    source_files=source_files[:12],
                    routing_intent="computation",
                    exclude_workers=["runtime-probe-agent"],
                    routing_notes=[guidance.summary],
                )
            )

        output_context = {
            **bundle.parsed.output_context,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
            "llm_summary": guidance.summary,
        }

        executed_scripts = list(output_context.get("executed_scripts") or [])
        success = bool(executed_scripts)
        error: str | None = None
        notes_tail: list[str] = []
        if not success:
            error = (
                f"{capability_source(capability)}: 0 script(s) executed; "
                f"none of the {len(input_files)} input file(s) had executable script extensions "
                f"(.py/.sh/.js/.rb/.pl/.php/.lua)."
            )
            notes_tail.append(
                f"{self.name} executed 0 scripts; do not reschedule with the same source_files."
            )

        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=output_context,
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks if success else []),
            notes=worker_notes + [f"{self.name} executed bundled script artifacts."] + notes_tail,
            success=success,
            error=error,
        )
