"""Service-banner and web-path-probe enrichment workers.

The four artifact-review agents that lived here historically (Archive, SQLite,
Pcap, Repo) have been consolidated into :class:`ArtifactWorker` in
:mod:`agents.artifact_worker`.  They remain importable from this module via
backwards-compat aliases.
"""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents._helpers.network import infer_web_urls_from_banners
from nyuctf_mutil_killchain.agents._helpers.strings import merge_unique_strings
from nyuctf_mutil_killchain.agents.artifact_worker import ArtifactWorker
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.llm_guidance import EvidenceReviewGuidance
from nyuctf_mutil_killchain.state import GlobalState, Task, TaskErrorCode, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import (
    build_flag_validation_task,
    build_web_content_task,
    build_web_review_task,
)
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


# ---------------------------------------------------------------------------
# Backwards-compat aliases for the consolidated artifact worker
# ---------------------------------------------------------------------------

ArchiveTriageAgent = ArtifactWorker
SQLiteReviewAgent = ArtifactWorker
PcapReviewAgent = ArtifactWorker
RepoReviewAgent = ArtifactWorker


def _apply_evidence_guidance(
    worker: WorkerAgent,
    *,
    state: GlobalState,
    task: Task,
    summary: str,
    output_context: dict[str, object],
    guidance_label: str,
) -> tuple[EvidenceReviewGuidance, list[str], dict[str, object]]:
    """Apply grounded LLM synthesis to an evidence-review worker."""

    challenge_meta = state.metadata.get("challenge", {})
    guidance = worker.generate_structured_output(
        system_prompt=(
            "You analyze structured evidence from an authorized CTF workflow. "
            "Return only JSON matching the EvidenceReviewGuidance schema. "
            "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
            "provided evidence. "
            "Do not invent vulnerabilities, hidden files, or challenge secrets."
        ),
        user_prompt=json.dumps(
            {
                "objective": state.objective,
                "task_id": task.task_id,
                "worker": guidance_label,
                "challenge": {
                    "category": challenge_meta.get("category"),
                    "flag_format": challenge_meta.get("flag_format"),
                },
                "summary": summary,
                "output_context": output_context,
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

    flag_candidates = list(output_context.get("flag_candidates") or [])
    manual_checks = list(output_context.get("manual_checks") or [])
    flag_candidates = merge_unique_strings(
        flag_candidates,
        guidance.grounded_flag_candidates,
        limit=12,
    )
    manual_checks = merge_unique_strings(
        manual_checks,
        guidance.recommended_checks,
        limit=8,
    )

    guided_output_context: dict[str, object] = {
        **output_context,
        "flag_candidates": flag_candidates,
        "manual_checks": manual_checks,
    }
    guided_output_context["llm_summary"] = guidance.summary
    return guidance, flag_candidates, guided_output_context


class ServiceBannerAgent(WorkerAgent):
    """Collects banners from exposed TCP services."""

    name = "service-banner-agent"
    supported_task_types = ("host.banner_grab", "host.service_fingerprint")
    required_context_keys = ("asset_id", "hostname", "ports")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Service banner review requires an execution plane; none is configured.",
                error="ServiceBannerAgent.execution_plane is None",
                retryable=False,
            )

        asset_id = task.input_context.get("asset_id")
        hostname = task.input_context.get("hostname")
        if not asset_id or not hostname:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing host context for banner collection.",
                error="asset_id and hostname are required in task.input_context",
                error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
                retryable=False,
            )

        request = ToolExecutionRequest(
            tool_name="tcp_banner_probe",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 45),
            metadata={
                "asset_id": asset_id,
                "hostname": hostname,
                "ports": task.input_context.get("ports", []),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Service banner review execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        guidance, flag_candidates, output_context = _apply_evidence_guidance(
            self,
            state=state,
            task=task,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            guidance_label="service banner review",
        )
        asset = state.assets.get(asset_id) if asset_id else None
        web_review_targets = infer_web_urls_from_banners(
            hostname=hostname or (asset.hostname if asset is not None else None),
            ip_address=asset.ip_address if asset is not None else None,
            banner_hits=output_context.get("banner_hits") or {},
        )
        new_tasks = [
            build_flag_validation_task(candidate, source="tcp_banner_probe")
            for candidate in flag_candidates
        ]
        if asset_id:
            new_tasks.extend(
                build_web_review_task(asset_id, base_url)
                for base_url in web_review_targets
            )
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
            notes=worker_notes + [f"{self.name} collected service banners."],
        )


class WebPathProbeAgent(WorkerAgent):
    """Fetches interesting application paths to extend web coverage."""

    name = "web-path-probe-agent"
    supported_task_types = ("web.path_probe",)
    required_context_keys = ("asset_id", "base_url", "paths")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web path probing requires an execution plane; none is configured.",
                error="WebPathProbeAgent.execution_plane is None",
                retryable=False,
            )

        asset_id = task.input_context.get("asset_id")
        base_url = task.input_context.get("base_url")
        request = ToolExecutionRequest(
            tool_name="http_path_probe",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 40),
            metadata={
                "asset_id": asset_id,
                "base_url": base_url,
                "paths": task.input_context.get("paths", []),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web path probe execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        _, flag_candidates, output_context = _apply_evidence_guidance(
            self,
            state=state,
            task=task,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            guidance_label="web path probe",
        )
        new_tasks = [
            build_flag_validation_task(candidate, source="http_path_probe")
            for candidate in flag_candidates
        ]
        for probe_url in list(output_context.get("interesting_paths") or [])[:8]:
            if not isinstance(probe_url, str) or not probe_url.strip():
                continue
            new_tasks.append(
                build_web_content_task(
                    asset_id=str(asset_id or ""),
                    base_url=probe_url,
                    priority=75,
                )
            )
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
            notes=worker_notes + [f"{self.name} probed interesting HTTP paths."],
        )


__all__ = [
    "ArchiveTriageAgent",
    "PcapReviewAgent",
    "RepoReviewAgent",
    "SQLiteReviewAgent",
    "ServiceBannerAgent",
    "WebPathProbeAgent",
]
