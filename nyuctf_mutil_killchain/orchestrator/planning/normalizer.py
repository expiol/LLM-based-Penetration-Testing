"""Task input_context normalization.

Fills missing context fields the LLM may have omitted using the canonical
file_classification table and asset inference helpers.  This is purely
data-shape consolidation - it does not filter or re-prioritize tasks.
"""

from __future__ import annotations

import re
from typing import Any

from nyuctf_mutil_killchain.orchestrator.planning.schemas import PlannedTask
from nyuctf_mutil_killchain.state import (
    FileKind,
    GlobalState,
    classify,
    files_by_kind,
)


_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"

# Real Task ids look like ``task-<10 hex>`` — see ``state.models._task_id``.
# The LLM does not see these random ids in its prompt, so any "dependency"
# string it emits (e.g. ``"binary_triage_stfu"``, ``"recon_step_1"``) is
# fabricated and will deadlock the queue because ``Task.is_ready`` checks
# ``deps.issubset(completed_ids)``.
_REAL_TASK_ID_RE = re.compile(r"^task-[0-9a-f]{10}$")

_ARTIFACT_FIELD_MAP: dict[str, FileKind] = {
    "binary_files": FileKind.BINARY,
    "archive_files": FileKind.ARCHIVE,
    "pcap_files": FileKind.PCAP,
    "database_files": FileKind.SQLITE,
}


class TaskNormalizer:
    """Normalize task input_context against challenge metadata and known assets."""

    def fill(self, task: PlannedTask, state: GlobalState) -> None:
        # Drop fabricated dependency ids before anything else — see comment
        # on ``_REAL_TASK_ID_RE`` for why this matters.  Without this the
        # whole queue can deadlock on a single hallucinated id.
        self._clean_dependencies(task, state)

        ctx = task.input_context
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files: list[str] = list(challenge_meta.get("files", []) or [])

        # The agent container always exposes challenge files under a single
        # known path; allowing the LLM to override this just produces ENOENT
        # in the worker (e.g. ``/challenge`` for a NYU CTF run).  Force the
        # canonical value so downstream tools always see the right root.
        if task.task_type.startswith(("artifact.", "solve.", "credential.", "flag.")):
            ctx["files_root"] = _DEFAULT_FILES_ROOT

        # Source-derived contexts ------------------------------------------------
        if task.task_type in (
            "artifact.source_review",
            "artifact.computation_analysis",
            "artifact.runtime_probe",
        ) and not ctx.get("source_files"):
            ctx["source_files"] = (
                self._infer_source_files(state, challenge_files)
                or challenge_files
            )

        # Per-kind artifact contexts --------------------------------------------
        kinds = files_by_kind(challenge_files)
        for field, kind in _ARTIFACT_FIELD_MAP.items():
            if task.task_type == f"artifact.{kind.value}_review" or (
                task.task_type == "artifact.binary_triage" and kind == FileKind.BINARY
            ) or (
                task.task_type == "artifact.archive_triage" and kind == FileKind.ARCHIVE
            ) or (
                task.task_type == "artifact.pcap_review" and kind == FileKind.PCAP
            ) or (
                task.task_type == "artifact.sqlite_review" and kind == FileKind.SQLITE
            ):
                inferred = list(kinds.get(kind, []))
                if inferred and not ctx.get(field):
                    ctx[field] = inferred

        if task.task_type == "artifact.deep_review":
            self._normalize_deep_review_context(ctx, challenge_files, kinds)

        # Network-targeted tasks ------------------------------------------------
        if task.task_type.startswith(("web.", "host.", "vuln.", "exploit.")):
            state.infer_asset_identity(ctx)

        if task.task_type.startswith("vuln.") and not ctx.get("target"):
            ctx["target"] = ctx.get("base_url") or ctx.get("hostname") or ""

        if task.task_type == "web.form_probe" and not ctx.get("page_url") and ctx.get("base_url"):
            ctx["page_url"] = ctx["base_url"]

    @staticmethod
    def _clean_dependencies(task: PlannedTask, state: GlobalState) -> None:
        """Drop dependency ids the planner hallucinated.

        The planner LLM does not see real ``task-<hex>`` ids in its prompt,
        so anything it puts under ``dependencies`` is invented (typical
        garbage: ``"binary_triage_stfu"``, ``"step_1"``, ``"recon_done"``).
        Such strings will never match :meth:`TaskChain.completed_task_ids`,
        so the task stays PENDING forever and the orchestrator eventually
        halts on an empty-queue stall.

        Resolution: keep only deps that (a) look like a real id AND (b)
        exist on the live task chain.  Anything else is dropped silently;
        the planner intent ("this task depends on triage") is preserved
        anyway by task priorities + the cycle re-plan.
        """
        if not task.dependencies:
            return
        known_ids = {t.task_id for t in state.task_chain.tasks}
        filtered = [
            dep for dep in task.dependencies
            if _REAL_TASK_ID_RE.match(dep) and dep in known_ids
        ]
        if len(filtered) != len(task.dependencies):
            dropped = [d for d in task.dependencies if d not in filtered]
            task.metadata.setdefault("_dropped_dependencies", []).extend(dropped)
        task.dependencies = filtered

    @staticmethod
    def _infer_source_files(
        state: GlobalState, challenge_files: list[str],
    ) -> list[str]:
        for finding in state.findings.values():
            meta = finding.metadata
            if meta.get("source") == "artifact_triage":
                for key in ("web_source_files", "source_web_files", "source_files"):
                    files = meta.get(key)
                    if isinstance(files, list) and files:
                        return list(files)
        return [name for name in challenge_files if classify(name) == FileKind.SOURCE]

    @staticmethod
    def _normalize_deep_review_context(
        ctx: dict[str, Any],
        challenge_files: list[str],
        kinds: dict[FileKind, list[str]],
    ) -> None:
        kind_to_field = {
            "binary": "binary_files",
            "archive": "archive_files",
            "sqlite": "database_files",
            "database": "database_files",
            "pcap": "pcap_files",
            "repo": "repo_paths",
            "git": "repo_paths",
        }
        kind_for: dict[FileKind, str] = {
            FileKind.BINARY: "binary",
            FileKind.ARCHIVE: "archive",
            FileKind.SQLITE: "sqlite",
            FileKind.PCAP: "pcap",
            FileKind.REPO: "repo",
        }

        known_fields = (
            "binary_files", "source_files", "archive_files",
            "database_files", "pcap_files", "repo_paths",
        )
        has_files = any(ctx.get(field) for field in known_fields)
        analysis_kind = str(ctx.get("analysis_kind", "")).lower()

        # Path 1: LLM gave file lists -> derive analysis_kind from them if missing.
        if has_files and not analysis_kind:
            for field, kind_name in (
                ("binary_files", "binary"),
                ("archive_files", "archive"),
                ("database_files", "sqlite"),
                ("pcap_files", "pcap"),
                ("repo_paths", "repo"),
                ("source_files", "source"),
            ):
                if ctx.get(field):
                    ctx["analysis_kind"] = kind_name
                    break
            return

        if has_files:
            return

        # Path 2: LLM gave neither file list nor analysis_kind -> infer from challenge files.
        # When the challenge has only one non-empty file kind, fill both analysis_kind and
        # the matching file list from challenge metadata.
        if not analysis_kind and not has_files:
            non_empty_kinds = [
                kind for kind, files in kinds.items()
                if files and kind in kind_for
            ]
            if len(non_empty_kinds) == 1:
                only_kind = non_empty_kinds[0]
                kind_name = kind_for[only_kind]
                ctx["analysis_kind"] = kind_name
                ctx[kind_to_field[kind_name]] = list(kinds[only_kind])
                return

        # Path 3: alternate field names (target_files / files) -> normalize.
        alt_files = ctx.pop("target_files", None) or ctx.pop("files", None) or []
        if not alt_files:
            return

        for keyword, field in kind_to_field.items():
            if keyword in analysis_kind:
                ctx[field] = alt_files
                return

        sources = [name for name in alt_files if classify(name) == FileKind.SOURCE]
        if sources:
            ctx["source_files"] = alt_files
            ctx.setdefault("analysis_kind", "source")
        else:
            ctx["binary_files"] = alt_files
            ctx.setdefault("analysis_kind", "binary")
