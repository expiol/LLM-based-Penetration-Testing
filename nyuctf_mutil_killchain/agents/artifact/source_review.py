"""Source review worker - static analysis of bundled source files."""

from __future__ import annotations

import json
import re

from nyuctf_mutil_killchain.agents._helpers.flag import extract_flag_candidates
from nyuctf_mutil_killchain.agents._helpers.strings import merge_unique_strings
from nyuctf_mutil_killchain.agents.artifact._helpers import (
    attempt_plugin,
    category_of,
    challenge_meta,
    files_root_of,
    success_report,
)
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.reasoning import EvidenceReviewGuidance
from nyuctf_mutil_killchain.prompts import get_analysis_strategy, get_worker_system_prompt
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import (
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    build_source_review_task,
)


_ASCII_PRINTABLE_RE = re.compile(r"^[\x20-\x7e]+$")
_MAX_FLAG_VALIDATIONS = 6


def _extract_flag_prefix(flag_format: str | None) -> str | None:
    if not flag_format:
        return None
    normalized = str(flag_format).strip()
    if not normalized or "{" not in normalized:
        return None
    prefix = normalized.split("{", 1)[0].strip()
    return prefix if prefix else None


def _filter_candidates(candidates: list[str], flag_format: str | None) -> list[str]:
    refined: list[str] = []
    for candidate in candidates:
        cleaned = str(candidate).strip()
        if not cleaned or not _ASCII_PRINTABLE_RE.match(cleaned):
            continue
        extracted = extract_flag_candidates(cleaned)
        if not extracted:
            continue
        for item in extracted:
            if item not in refined:
                refined.append(item)
    prefix = _extract_flag_prefix(flag_format)
    if prefix:
        preferred = [item for item in refined if item.startswith(f"{prefix}{{")]
        if preferred:
            return preferred[:_MAX_FLAG_VALIDATIONS]
    return refined[:_MAX_FLAG_VALIDATIONS]


class SourceReviewAgent(WorkerAgent):
    """Review bundled source files for routes, secrets, and flag tokens."""

    name = "source-review-agent"
    supported_task_types = ("artifact.source_review",)
    required_context_keys = ("source_files",)
    routing_summary = (
        "Static review of bundled source files - routes, SQL queries, secrets, "
        "template injection points. Honors routing_intent=runtime/computation to "
        "promote dynamic follow-ups."
    )
    preferred_challenge_categories = ("web", "crypto", "rev", "misc")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        cm = challenge_meta(state)
        category = category_of(state)

        bundle, fail = attempt_plugin(
            self,
            task=task,
            tool_name="source_review",
            timeout_s=int(task.input_context.get("timeout_s", 120)),
            metadata={
                "files_root": files_root_of(task),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 12),
            },
            label="Source review",
        )
        if fail is not None:
            return fail
        assert bundle is not None

        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        interesting_routes = list(bundle.parsed.output_context.get("interesting_routes") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])

        guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                category,
                worker_role=(
                    "You analyze source code from bundled challenge files. "
                    "Look for routes, secrets, hardcoded credentials, SQL queries, "
                    "template injection points, and flag-like tokens. "
                    + get_analysis_strategy(category) + " "
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
                        "category": category,
                        "flag_format": cm.get("flag_format"),
                    },
                    "source_review_summary": bundle.parsed.summary,
                    "source_review_output_context": bundle.parsed.output_context,
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

        flag_candidates = merge_unique_strings(flag_candidates, guidance.grounded_flag_candidates, limit=12)
        interesting_routes = merge_unique_strings(interesting_routes, guidance.interesting_paths, limit=20)
        manual_checks = merge_unique_strings(manual_checks, guidance.recommended_checks, limit=8)
        flag_candidates = _filter_candidates(flag_candidates, cm.get("flag_format"))

        new_tasks: list[Task] = [
            build_flag_validation_task(candidate, source="source_review")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, interesting_routes))

        source_files = list(task.input_context.get("source_files") or [])
        if source_files and category in {"rev", "crypto", "misc"}:
            if guidance.promote_runtime_probe:
                new_tasks.append(
                    build_source_review_task(
                        files_root=files_root_of(task),
                        source_files=source_files[:12],
                        routing_intent="runtime",
                        exclude_workers=["source-review-agent"],
                        routing_notes=[guidance.summary],
                    )
                )
            if guidance.promote_computation_analysis:
                new_tasks.append(
                    build_source_review_task(
                        files_root=files_root_of(task),
                        source_files=source_files[:12],
                        routing_intent="computation",
                        exclude_workers=["source-review-agent"],
                        routing_notes=[guidance.summary],
                    )
                )

        output_context = {
            **bundle.parsed.output_context,
            "interesting_routes": interesting_routes,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
            "llm_summary": guidance.summary,
        }

        inspected = list(output_context.get("inspected_sources") or [])
        success = bool(inspected)
        error: str | None = None
        notes_tail: list[str] = []
        if not success:
            input_files = list(task.input_context.get("source_files") or [])
            error = (
                f"source_review: 0 source(s) inspected; "
                f"none of the {len(input_files)} input file(s) were source-like."
            )
            notes_tail.append(
                f"{self.name} inspected 0 sources; do not reschedule with the same source_files."
            )

        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=output_context,
            new_tasks=new_tasks if success else [],
            notes=worker_notes + [f"{self.name} reviewed bundled source files."] + notes_tail,
            success=success,
            error=error,
        )
