"""Task input_context normalization.

Fills missing context fields the LLM may have omitted using the canonical
file_classification table and asset inference helpers.  This is purely
data-shape consolidation - it does not filter or re-prioritize tasks.
"""

from __future__ import annotations

from typing import Any

from nyuctf_mutil_killchain.orchestrator.planning.schemas import PlannedTask
from nyuctf_mutil_killchain.state import (
    FileKind,
    GlobalState,
    classify,
    files_by_kind,
)


_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"

_ARTIFACT_FIELD_MAP: dict[str, FileKind] = {
    "binary_files": FileKind.BINARY,
    "archive_files": FileKind.ARCHIVE,
    "pcap_files": FileKind.PCAP,
    "database_files": FileKind.SQLITE,
}


class TaskNormalizer:
    """Normalize task input_context against challenge metadata and known assets."""

    def fill(self, task: PlannedTask, state: GlobalState) -> None:
        ctx = task.input_context
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files: list[str] = list(challenge_meta.get("files", []) or [])

        if task.task_type.startswith(("artifact.", "solve.", "credential.", "flag.")):
            ctx.setdefault("files_root", _DEFAULT_FILES_ROOT)

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
        known_fields = (
            "binary_files", "source_files", "archive_files",
            "database_files", "pcap_files", "repo_paths",
        )
        if any(ctx.get(field) for field in known_fields):
            return

        alt_files = ctx.pop("target_files", None) or ctx.pop("files", None) or []
        if not alt_files:
            return

        analysis_kind = str(ctx.get("analysis_kind", "")).lower()
        kind_to_field = {
            "binary": "binary_files",
            "archive": "archive_files",
            "sqlite": "database_files",
            "database": "database_files",
            "pcap": "pcap_files",
            "repo": "repo_paths",
            "git": "repo_paths",
        }
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
