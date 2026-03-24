"""Additional enrichment workers for artifact, service, and path analysis."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_source_review_task,
    build_web_review_task,
    infer_web_urls_from_banners,
)
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class ArchiveTriageAgent(WorkerAgent):
    """Inspects bundled archive files for embedded paths and flag-like content."""

    name = "archive-triage-agent"
    supported_task_types = ("artifact.archive_triage",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Archive triage requires an execution plane; none is configured.",
                error="ArchiveTriageAgent.execution_plane is None",
            )

        request = ToolExecutionRequest(
            tool_name="archive_triage",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "archive_files": task.input_context.get("archive_files", []),
                "max_files": task.input_context.get("max_files", 8),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Archive triage execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        source_like_members = list(
            bundle.parsed.output_context.get("qualified_source_like_members")
            or bundle.parsed.output_context.get("source_like_members")
            or []
        )
        new_tasks = [
            build_flag_validation_task(candidate, source="archive_triage")
            for candidate in flag_candidates
        ]
        if source_like_members:
            new_tasks.append(
                build_source_review_task(
                    files_root=str(bundle.parsed.output_context.get("files_root") or "/home/ctfplayer/ctf_files"),
                    source_files=source_like_members[:12],
                )
            )
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=bundle.parsed.notes + [f"{self.name} reviewed bundled archives."],
        )


class SQLiteReviewAgent(WorkerAgent):
    """Inspects bundled SQLite databases for sensitive rows and flags."""

    name = "sqlite-review-agent"
    supported_task_types = ("artifact.sqlite_review",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="SQLite review requires an execution plane; none is configured.",
                error="SQLiteReviewAgent.execution_plane is None",
            )

        request = ToolExecutionRequest(
            tool_name="sqlite_review",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "database_files": task.input_context.get("database_files", []),
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
                summary="SQLite review execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=[
                build_flag_validation_task(candidate, source="sqlite_review")
                for candidate in flag_candidates
            ],
            notes=bundle.parsed.notes + [f"{self.name} reviewed bundled SQLite databases."],
        )


class PcapReviewAgent(WorkerAgent):
    """Inspects bundled packet captures for hosts, URLs, credentials, and flags."""

    name = "pcap-review-agent"
    supported_task_types = ("artifact.pcap_review",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="PCAP review requires an execution plane; none is configured.",
                error="PcapReviewAgent.execution_plane is None",
            )

        request = ToolExecutionRequest(
            tool_name="pcap_review",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "pcap_files": task.input_context.get("pcap_files", []),
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
                summary="PCAP review execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=[
                build_flag_validation_task(candidate, source="pcap_review")
                for candidate in flag_candidates
            ],
            notes=bundle.parsed.notes + [f"{self.name} reviewed packet capture artifacts."],
        )


class RepoReviewAgent(WorkerAgent):
    """Inspects bundled git repositories for useful history and leaked secrets."""

    name = "repo-review-agent"
    supported_task_types = ("artifact.repo_review",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Repository review requires an execution plane; none is configured.",
                error="RepoReviewAgent.execution_plane is None",
            )

        request = ToolExecutionRequest(
            tool_name="repo_review",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "repo_paths": task.input_context.get("repo_paths", []),
                "max_files": task.input_context.get("max_files", 4),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Repository review execution failed.",
                error=str(exc),
            )

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=[
                build_flag_validation_task(candidate, source="repo_review")
                for candidate in flag_candidates
            ],
            notes=bundle.parsed.notes + [f"{self.name} reviewed embedded repositories."],
        )


class ServiceBannerAgent(WorkerAgent):
    """Collects banners from exposed TCP services."""

    name = "service-banner-agent"
    supported_task_types = ("host.banner_grab",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Service banner review requires an execution plane; none is configured.",
                error="ServiceBannerAgent.execution_plane is None",
            )

        asset_id = task.input_context.get("asset_id")
        hostname = task.input_context.get("hostname")
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

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        asset = state.assets.get(asset_id) if asset_id else None
        web_review_targets = infer_web_urls_from_banners(
            hostname=hostname or (asset.hostname if asset is not None else None),
            ip_address=asset.ip_address if asset is not None else None,
            banner_hits=bundle.parsed.output_context.get("banner_hits") or {},
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
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=bundle.parsed.notes + [f"{self.name} collected service banners."],
        )


class WebPathProbeAgent(WorkerAgent):
    """Fetches interesting application paths to extend web coverage."""

    name = "web-path-probe-agent"
    supported_task_types = ("web.path_probe",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web path probing requires an execution plane; none is configured.",
                error="WebPathProbeAgent.execution_plane is None",
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

        flag_candidates = list(bundle.parsed.output_context.get("flag_candidates") or [])
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=bundle.parsed.output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=[
                build_flag_validation_task(candidate, source="http_path_probe")
                for candidate in flag_candidates
            ],
            notes=bundle.parsed.notes + [f"{self.name} probed interesting HTTP paths."],
        )
