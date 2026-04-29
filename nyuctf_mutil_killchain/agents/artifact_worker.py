"""Consolidated artifact-stage worker.

A single :class:`ArtifactWorker` class replaces nine former agents
(triage, binary, archive, sqlite, pcap, repo, computation, runtime,
source-review) with one dispatch table.  The worker translates each
``artifact.*`` task into the matching plugin call, handles the LLM
post-processing via :mod:`agents.reasoning`, and constructs deterministic
follow-up tasks.

Routing-intent and analysis-kind specialization is kept inside the worker
(rather than spread across multiple classes) so the orchestrator only has
to know about one ``ArtifactWorker`` for the entire artifact stage.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nyuctf_mutil_killchain.agents._helpers.flag import extract_flag_candidates
from nyuctf_mutil_killchain.agents._helpers.strings import merge_unique_strings
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.reasoning import (
    ArtifactTriageGuidance,
    EvidenceReviewGuidance,
    boost_prioritized_tasks,
)
from nyuctf_mutil_killchain.prompts import get_analysis_strategy, get_exploit_strategy, get_worker_system_prompt
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import (
    build_artifact_deep_review_task,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    build_source_review_task,
)
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest

# ===========================================================================
# Plugin dispatch table
# ===========================================================================
# Each (analysis_kind/routing_intent) maps to (tool_name, default_timeout, request_field).

_DEEP_REVIEW_PLUGINS: dict[str, tuple[str, int, str]] = {
    "binary": ("binary_triage", 120, "binary_files"),
    "archive": ("archive_triage", 120, "archive_files"),
    "sqlite": ("sqlite_review", 120, "database_files"),
    "pcap": ("pcap_review", 120, "pcap_files"),
    "repo": ("repo_review", 120, "repo_paths"),
}

_SOURCE_INTENT_PLUGIN: dict[str, tuple[str, int]] = {
    "computation": ("computation_analysis", 180),
    "decode": ("computation_analysis", 180),
    "transform": ("computation_analysis", 180),
    "reverse": ("computation_analysis", 180),
    "runtime": ("runtime_probe", 60),
    "dynamic": ("runtime_probe", 60),
    "execute": ("runtime_probe", 60),
    "script": ("runtime_probe", 60),
    "static": ("source_review", 120),
    "source": ("source_review", 120),
    "review": ("source_review", 120),
}

_TRANSFORM_MARKERS = ("checker", "encode", "decode", "decrypt", "cipher", "crypto", "transform", "solve")
_SCRIPT_SUFFIXES = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".rb", ".pl", ".php", ".lua")
_ASCII_PRINTABLE_RE = re.compile(r"^[\x20-\x7e]+$")
_MAX_FLAG_VALIDATIONS_FROM_SOURCE_REVIEW = 6


# ===========================================================================
# Helpers
# ===========================================================================

def _challenge(state: GlobalState) -> dict[str, Any]:
    return state.metadata.get("challenge", {}) or {}


def _category(state: GlobalState) -> str:
    return str(_challenge(state).get("category") or "").lower()


def _files_root(task: Task) -> str:
    return str(task.input_context.get("files_root") or "/home/ctfplayer/ctf_files")


def _extract_flag_prefix(flag_format: str | None) -> str | None:
    if not flag_format:
        return None
    normalized = str(flag_format).strip()
    if not normalized or "{" not in normalized:
        return None
    prefix = normalized.split("{", 1)[0].strip()
    return prefix if prefix else None


def _filter_source_review_candidates(candidates: list[str], flag_format: str | None) -> list[str]:
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
            return preferred[:_MAX_FLAG_VALIDATIONS_FROM_SOURCE_REVIEW]
    return refined[:_MAX_FLAG_VALIDATIONS_FROM_SOURCE_REVIEW]


def _evidence_role(label: str, *, role_addition: str = "") -> str:
    return (
        f"You analyze structured {label} evidence from an authorized CTF workflow. "
        "Return only JSON matching the EvidenceReviewGuidance schema. "
        "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
        "observed evidence. "
        + role_addition
    )


# ===========================================================================
# ArtifactWorker
# ===========================================================================


class ArtifactWorker(WorkerAgent):
    """Single worker handling every ``artifact.*`` task type.

    The :meth:`run` method delegates to a private handler for each task type:

    - ``artifact.triage``: top-level inventory + fan-out
    - ``artifact.deep_review``: routed to ``binary``/``archive``/``sqlite``/``pcap``/``repo`` plugin
    - ``artifact.source_review``: routed to ``source_review``/``computation_analysis``/``runtime_probe``
      based on ``routing_intent``
    - ``artifact.binary_triage``, ``artifact.archive_triage``, ``artifact.sqlite_review``,
      ``artifact.pcap_review``, ``artifact.repo_review``, ``artifact.computation_analysis``,
      ``artifact.runtime_probe``: direct plugin dispatch
    """

    name = "artifact-worker"
    supported_task_types = (
        "artifact.triage",
        "artifact.deep_review",
        "artifact.source_review",
        "artifact.binary_triage",
        "artifact.archive_triage",
        "artifact.sqlite_review",
        "artifact.pcap_review",
        "artifact.repo_review",
        "artifact.computation_analysis",
        "artifact.runtime_probe",
    )
    routing_summary = "Unified artifact-stage worker for triage, deep review, and source/binary inspection."
    preferred_challenge_categories = ("misc", "forensics", "rev", "crypto", "web", "pwn")

    # -- routing -----------------------------------------------------------

    def supports(self, task: Task) -> bool:
        return task.task_type.startswith("artifact.")

    def routing_score(self, task: Task, state: GlobalState) -> int:
        score = super().routing_score(task, state)
        analysis_kind = str(
            task.input_context.get("analysis_kind") or task.metadata.get("analysis_kind") or ""
        ).lower()
        if analysis_kind in _DEEP_REVIEW_PLUGINS:
            score += 32
        intent = str(task.input_context.get("routing_intent") or task.metadata.get("routing_intent") or "").lower()
        if intent in _SOURCE_INTENT_PLUGIN:
            score += 24
        return score

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        allowed, reason = super().can_route_task(task, state)
        if not allowed:
            return allowed, reason

        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or task.metadata.get("analysis_kind") or "").lower()
            if kind not in _DEEP_REVIEW_PLUGINS:
                return False, f"deep_review missing supported analysis_kind (got {kind!r})"
            field = _DEEP_REVIEW_PLUGINS[kind][2]
            if not task.input_context.get(field):
                return False, f"deep_review {kind!r} missing {field!r} context"

        elif task.task_type == "artifact.source_review":
            if not task.input_context.get("source_files"):
                return False, "source_review missing source_files context"

        elif task.task_type in {
            "artifact.binary_triage",
            "artifact.archive_triage",
            "artifact.sqlite_review",
            "artifact.pcap_review",
            "artifact.repo_review",
            "artifact.computation_analysis",
            "artifact.runtime_probe",
        }:
            kind = task.task_type.split(".", 1)[1]
            kind_to_field = {
                "binary_triage": "binary_files",
                "archive_triage": "archive_files",
                "sqlite_review": "database_files",
                "pcap_review": "pcap_files",
                "repo_review": "repo_paths",
                "computation_analysis": "source_files",
                "runtime_probe": "source_files",
            }
            if not task.input_context.get(kind_to_field[kind]):
                return False, f"{task.task_type} missing {kind_to_field[kind]!r} context"

        return True, None

    # -- entry point -------------------------------------------------------

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return self._missing_execution_plane(task)

        if task.task_type == "artifact.triage":
            return self._run_triage(task, state)
        if task.task_type == "artifact.deep_review":
            return self._run_deep_review(task, state)
        if task.task_type == "artifact.source_review":
            return self._run_source_review(task, state)
        if task.task_type == "artifact.binary_triage":
            return self._run_simple_review(
                task, state,
                tool_name="binary_triage",
                evidence_label="binary triage",
                input_field="binary_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="inspected bundled binaries",
                role_addition=(
                    "Pay special attention to interesting strings, URLs, and command paths in the binary."
                ),
            )
        if task.task_type == "artifact.archive_triage":
            return self._run_archive_triage(task, state)
        if task.task_type == "artifact.sqlite_review":
            return self._run_simple_review(
                task, state,
                tool_name="sqlite_review",
                evidence_label="sqlite review",
                input_field="database_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="reviewed bundled SQLite databases",
                role_addition="Look for credentials, session tokens, and challenge state rows.",
            )
        if task.task_type == "artifact.pcap_review":
            return self._run_simple_review(
                task, state,
                tool_name="pcap_review",
                evidence_label="pcap review",
                input_field="pcap_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="reviewed packet capture artifacts",
                role_addition="Look for credentials, hostnames, URLs, and exfiltrated content in packet streams.",
            )
        if task.task_type == "artifact.repo_review":
            return self._run_simple_review(
                task, state,
                tool_name="repo_review",
                evidence_label="repository review",
                input_field="repo_paths",
                max_files_default=4,
                timeout_default=120,
                summary_suffix="reviewed embedded repositories",
                role_addition="Inspect commit history for reverted secrets and challenge breadcrumbs.",
            )
        if task.task_type == "artifact.computation_analysis":
            return self._run_computation_analysis(task, state)
        if task.task_type == "artifact.runtime_probe":
            return self._run_runtime_probe(task, state)

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=False,
            summary=f"ArtifactWorker has no handler for task type {task.task_type!r}.",
            error="Unknown artifact task type.",
            retryable=False,
        )

    # -- triage ------------------------------------------------------------

    def _run_triage(self, task: Task, state: GlobalState) -> WorkerReport:
        challenge_meta = _challenge(state)
        request = ToolExecutionRequest(
            tool_name="artifact_triage",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 90),
            metadata={
                "files_root": _files_root(task),
                "challenge_files": challenge_meta.get("files", []),
                "max_files": task.input_context.get("max_files", 80),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, "Artifact triage", exc)

        challenge_category = _category(state)
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
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You prioritize follow-up work for artifact analysis. "
                    "Rank task types and analysis kinds based on which are most likely to yield the flag. "
                    "Use source_routing_intent to steer the initial source-analysis worker choice. "
                    + get_analysis_strategy(challenge_category)
                ),
                evidence_type="artifact triage",
                output_schema="ArtifactTriageGuidance",
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
        )

        flag_candidates = merge_unique_strings(flag_candidates, llm_guidance.extra_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, llm_guidance.manual_checks, limit=8)
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

        new_tasks = [
            build_flag_validation_task(candidate, source="artifact_triage")
            for candidate in flag_candidates
        ] + follow_up_tasks

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} inventoried challenge files."],
        )

    # -- deep review (analysis_kind dispatch) -----------------------------

    def _run_deep_review(self, task: Task, state: GlobalState) -> WorkerReport:
        kind = str(task.input_context.get("analysis_kind") or task.metadata.get("analysis_kind") or "").lower()
        if kind not in _DEEP_REVIEW_PLUGINS:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"Unknown analysis_kind {kind!r} for artifact.deep_review.",
                error=f"analysis_kind must be one of {sorted(_DEEP_REVIEW_PLUGINS)}",
                retryable=False,
            )

        if kind == "binary":
            return self._run_simple_review(
                task, state,
                tool_name="binary_triage",
                evidence_label="binary triage",
                input_field="binary_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="inspected bundled binaries",
                role_addition="Pay special attention to interesting strings, URLs, and command paths in the binary.",
            )
        if kind == "archive":
            return self._run_archive_triage(task, state)
        if kind == "sqlite":
            return self._run_simple_review(
                task, state,
                tool_name="sqlite_review",
                evidence_label="sqlite review",
                input_field="database_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="reviewed bundled SQLite databases",
                role_addition="Look for credentials, session tokens, and challenge state rows.",
            )
        if kind == "pcap":
            return self._run_simple_review(
                task, state,
                tool_name="pcap_review",
                evidence_label="pcap review",
                input_field="pcap_files",
                max_files_default=6,
                timeout_default=120,
                summary_suffix="reviewed packet capture artifacts",
                role_addition="Look for credentials, hostnames, URLs, and exfiltrated content in packet streams.",
            )
        if kind == "repo":
            return self._run_simple_review(
                task, state,
                tool_name="repo_review",
                evidence_label="repository review",
                input_field="repo_paths",
                max_files_default=4,
                timeout_default=120,
                summary_suffix="reviewed embedded repositories",
                role_addition="Inspect commit history for reverted secrets and challenge breadcrumbs.",
            )
        return WorkerReport(  # pragma: no cover - guarded above
            task_id=task.task_id,
            worker_name=self.name,
            success=False,
            summary="ArtifactWorker reached unreachable branch.",
            error="Internal routing error.",
            retryable=False,
        )

    # -- simple evidence-review template ----------------------------------

    def _run_simple_review(
        self,
        task: Task,
        state: GlobalState,
        *,
        tool_name: str,
        evidence_label: str,
        input_field: str,
        max_files_default: int,
        timeout_default: int,
        summary_suffix: str,
        role_addition: str,
    ) -> WorkerReport:
        request = ToolExecutionRequest(
            tool_name=tool_name,
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", timeout_default),
            metadata={
                "files_root": _files_root(task),
                input_field: task.input_context.get(input_field, []),
                "max_files": task.input_context.get("max_files", max_files_default),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, evidence_label, exc)

        worker_notes = list(bundle.parsed.notes)
        guidance = self._review_with_llm(task, state, bundle, evidence_label, role_addition=role_addition)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        flag_candidates = merge_unique_strings(flag_candidates, guidance.grounded_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, guidance.recommended_checks, limit=8)

        new_tasks = [
            build_flag_validation_task(candidate, source=tool_name)
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

        output_context = {
            **bundle.parsed.output_context,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
        }
        output_context["llm_summary"] = guidance.summary

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} {summary_suffix}."],
        )

    # -- archive triage (special: also fans out source_review) ------------

    def _run_archive_triage(self, task: Task, state: GlobalState) -> WorkerReport:
        request = ToolExecutionRequest(
            tool_name="archive_triage",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": _files_root(task),
                "archive_files": task.input_context.get("archive_files", []),
                "max_files": task.input_context.get("max_files", 8),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, "Archive triage", exc)

        worker_notes = list(bundle.parsed.notes)
        guidance = self._review_with_llm(task, state, bundle, "archive triage")
        output_context = dict(bundle.parsed.output_context)
        flag_candidates = list(output_context.get("flag_candidates") or [])
        manual_checks = list(output_context.get("manual_checks") or [])
        flag_candidates = merge_unique_strings(flag_candidates, guidance.grounded_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, guidance.recommended_checks, limit=8)
        output_context["llm_summary"] = guidance.summary
        output_context["flag_candidates"] = flag_candidates
        output_context["manual_checks"] = manual_checks

        source_like_members = list(
            output_context.get("qualified_source_like_members")
            or output_context.get("source_like_members")
            or []
        )
        new_tasks: list[Task] = [
            build_flag_validation_task(candidate, source="archive_triage")
            for candidate in flag_candidates
        ]
        if source_like_members:
            new_tasks.append(
                build_source_review_task(
                    files_root=str(output_context.get("files_root") or "/home/ctfplayer/ctf_files"),
                    source_files=source_like_members[:12],
                )
            )
        new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} reviewed bundled archives."],
        )

    # -- source_review (intent-routed) -----------------------------------

    def _run_source_review(self, task: Task, state: GlobalState) -> WorkerReport:
        intent = str(task.input_context.get("routing_intent") or task.metadata.get("routing_intent") or "").lower()
        if intent in _SOURCE_INTENT_PLUGIN and _SOURCE_INTENT_PLUGIN[intent][0] != "source_review":
            tool_name, default_timeout = _SOURCE_INTENT_PLUGIN[intent]
            if tool_name == "computation_analysis":
                return self._run_computation_analysis(task, state)
            if tool_name == "runtime_probe":
                return self._run_runtime_probe(task, state)

        return self._run_static_source_review(task, state)

    def _run_static_source_review(self, task: Task, state: GlobalState) -> WorkerReport:
        challenge_meta = _challenge(state)
        challenge_category = _category(state)
        request = ToolExecutionRequest(
            tool_name="source_review",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": _files_root(task),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 12),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, "Source review", exc)

        worker_notes = list(bundle.parsed.notes)
        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        interesting_routes = list(bundle.parsed.output_context.get("interesting_routes") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])

        guidance = self.generate_structured_output(
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

        flag_candidates = _filter_source_review_candidates(flag_candidates, challenge_meta.get("flag_format"))
        new_tasks: list[Task] = [
            build_flag_validation_task(candidate, source="source_review")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, interesting_routes))

        source_files = list(task.input_context.get("source_files") or [])
        if source_files and challenge_category in {"rev", "crypto", "misc"}:
            if guidance.promote_runtime_probe:
                new_tasks.append(
                    build_source_review_task(
                        files_root=_files_root(task),
                        source_files=source_files[:12],
                        routing_intent="runtime",
                        exclude_workers=["source-review-agent"],
                        routing_notes=[guidance.summary],
                    )
                )
            if guidance.promote_computation_analysis:
                new_tasks.append(
                    build_source_review_task(
                        files_root=_files_root(task),
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
        }
        output_context["llm_summary"] = guidance.summary

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} reviewed bundled source files."],
        )

    def _run_computation_analysis(self, task: Task, state: GlobalState) -> WorkerReport:
        challenge_meta = _challenge(state)
        challenge_category = _category(state) or "misc"
        request = ToolExecutionRequest(
            tool_name="computation_analysis",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 180),
            metadata={
                "files_root": _files_root(task),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 8),
                "flag_format": challenge_meta.get("flag_format"),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, "Computation analysis", exc)

        worker_notes = list(bundle.parsed.notes)
        guidance = self.generate_structured_output(
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
                        for asset in state.assets.values() if asset.base_url
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=EvidenceReviewGuidance,
        )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        flag_candidates = merge_unique_strings(flag_candidates, guidance.grounded_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, guidance.recommended_checks, limit=8)

        new_tasks: list[Task] = [
            build_flag_validation_task(candidate, source="computation_analysis")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))

        output_context = {
            **bundle.parsed.output_context,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
        }
        output_context["llm_summary"] = guidance.summary

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} analyzed computation-heavy source files."],
        )

    def _run_runtime_probe(self, task: Task, state: GlobalState) -> WorkerReport:
        challenge_meta = _challenge(state)
        challenge_category = _category(state)
        request = ToolExecutionRequest(
            tool_name="runtime_probe",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 60),
            metadata={
                "files_root": _files_root(task),
                "source_files": task.input_context.get("source_files", []),
                "max_files": task.input_context.get("max_files", 8),
                "flag_format": challenge_meta.get("flag_format"),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return self._tool_failure(task, "Runtime probe", exc)

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
                        "category": challenge_category,
                        "flag_format": challenge_meta.get("flag_format"),
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

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        manual_checks = list(bundle.parsed.output_context.get("manual_checks") or [])
        flag_candidates = merge_unique_strings(flag_candidates, guidance.grounded_flag_candidates, limit=12)
        manual_checks = merge_unique_strings(manual_checks, guidance.recommended_checks, limit=8)

        new_tasks: list[Task] = [
            build_flag_validation_task(candidate, source="runtime_probe")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, guidance.interesting_paths))
        if guidance.promote_computation_analysis and challenge_category in {"rev", "crypto", "misc"}:
            new_tasks.append(
                build_source_review_task(
                    files_root=_files_root(task),
                    source_files=list(task.input_context.get("source_files") or [])[:12],
                    routing_intent="computation",
                    exclude_workers=["runtime-probe-agent"],
                    routing_notes=[guidance.summary],
                )
            )

        output_context = {
            **bundle.parsed.output_context,
            "flag_candidates": flag_candidates,
            "manual_checks": manual_checks,
        }
        output_context["llm_summary"] = guidance.summary

        return self._success_report(
            task, bundle, output_context, new_tasks,
            notes=worker_notes + [f"{self.name} executed bundled script artifacts."],
        )

    # -- shared infra -----------------------------------------------------

    def _review_with_llm(
        self,
        task: Task,
        state: GlobalState,
        bundle: Any,
        evidence_label: str,
        *,
        role_addition: str = "",
    ) -> EvidenceReviewGuidance:
        challenge_meta = _challenge(state)
        return self.generate_structured_output(
            system_prompt=_evidence_role(evidence_label, role_addition=role_addition),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "worker": evidence_label,
                    "challenge": {
                        "category": challenge_meta.get("category"),
                        "flag_format": challenge_meta.get("flag_format"),
                    },
                    "summary": bundle.parsed.summary,
                    "output_context": bundle.parsed.output_context,
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

    def _missing_execution_plane(self, task: Task) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=False,
            summary=f"{self.name} requires an execution plane; none is configured.",
            error=(
                f"{type(self).__name__}.execution_plane is None — "
                "register the artifact plugins before dispatching artifact.* tasks"
            ),
            retryable=False,
        )

    def _tool_failure(self, task: Task, label: str, exc: Exception) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=False,
            summary=f"{label} execution failed.",
            error=str(exc),
        )

    def _success_report(
        self,
        task: Task,
        bundle: Any,
        output_context: dict[str, Any],
        new_tasks: list[Task],
        *,
        notes: list[str],
    ) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=output_context,
            asset_updates=list(bundle.parsed.asset_updates),
            finding_updates=list(bundle.parsed.finding_updates),
            credential_updates=list(bundle.parsed.credential_updates),
            network_updates=list(bundle.parsed.network_updates),
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=notes,
        )
