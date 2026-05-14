"""Recon worker — normalises scope entries into tracked assets with DNS resolution."""

from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urlparse

from killchain_docker.workers._helpers.network import infer_web_urls
from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.reasoning import StageAnalysisGuidance
from killchain_docker.prompts import get_worker_system_prompt
from killchain_docker.state import Asset, AssetKind, GlobalState, Service, Task, WorkerReport
from killchain_docker.state.task_factory import (
    build_credential_hunt_task,
    build_flag_hunt_task,
    build_flag_validation_tasks,
    build_service_banner_task,
    build_web_review_task,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError


def _resolve_hostname(hostname: str) -> str | None:
    """Return the first IPv4/IPv6 address for *hostname*, or None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class ReconAgent(WorkerAgent):
    """Enumerates seed scope entries into normalised assets.

    For URL-scoped targets, performs DNS resolution to obtain the real IP address.
    When an execution plane is configured and the target is a plain host (non-URL),
    delegates to the host inventory capability for a real port scan at recon time.
    """

    name = "recon-agent"
    supported_task_types = ("recon.",)
    required_context_keys = ("scope",)

    def _generate_guidance(
        self,
        *,
        task: Task,
        state: GlobalState,
        scope_entry: str,
        asset: Asset,
        output_context: dict[str, object],
        findings: list[dict[str, object]],
    ) -> StageAnalysisGuidance:
        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
        return self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze recon evidence from scope enumeration. "
                    "Determine what follow-up tasks would be most productive: "
                    "flag hunting, credential harvesting, or service exploitation."
                ),
                evidence_type="recon",
                output_schema="StageAnalysisGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "scope_entry": scope_entry,
                    "asset": asset.model_dump(mode="json"),
                    "output_context": output_context,
                    "findings": findings,
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=StageAnalysisGuidance,
        )

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        # ``Task.normalise_input_context`` already coerces ``scope`` from
        # list to scalar; this is just a final safety net for hand-built
        # tasks (tests, BootstrapSeeder).
        scope_entry = task.input_context.get("scope") or (
            state.authorized_scope[0] if state.authorized_scope else None
        )
        if isinstance(scope_entry, (list, tuple)):
            scope_entry = next((str(x) for x in scope_entry if x), None)
        if not scope_entry or not isinstance(scope_entry, str):
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="No authorized scope configured.",
                error="authorized_scope is empty",
            )

        parsed = urlparse(scope_entry)
        is_url = parsed.scheme in {"http", "https"}
        hostname = parsed.hostname or (scope_entry if not is_url else scope_entry)
        notes: list[str] = []

        # Derive a stable, meaningful asset_id from the context or hostname
        asset_id: str = task.input_context.get("asset_id") or (
            f"asset-{hostname.replace('.', '-').replace(':', '-')}"
        )

        # Resolve IP address via DNS (real network call)
        ip_address: str | None = None
        if _is_ip_address(hostname):
            ip_address = hostname
            notes.append(f"Scope entry {scope_entry!r} is a direct IP address.")
        else:
            ip_address = _resolve_hostname(hostname)
            if ip_address:
                notes.append(f"Resolved {hostname} -> {ip_address}")
            else:
                notes.append(
                    f"DNS resolution failed for {hostname!r}; target may be offline or unreachable."
                )

        # Build initial service list from URL scheme / known port
        services: list[Service] = []
        if parsed.scheme == "https":
            port = parsed.port or 443
            services.append(Service(port=port, protocol="tcp", name="https"))
        elif parsed.scheme == "http":
            port = parsed.port or 80
            services.append(Service(port=port, protocol="tcp", name="http"))
        elif parsed.port:
            services.append(
                Service(
                    port=parsed.port,
                    protocol="tcp",
                    name=parsed.scheme or "tcp",
                )
            )

        asset = Asset(
            asset_id=asset_id,
            kind=AssetKind.WEB_APPLICATION if is_url else AssetKind.HOST,
            hostname=hostname,
            ip_address=ip_address,
            base_url=scope_entry if is_url else None,
            services=services,
            tags={"seed", "recon"},
            metadata={"source_task_id": task.task_id, "source": "recon_agent"},
        )

        # For plain-host scope entries, infer a base_url from known services
        # so that downstream web agents can find a usable web context.
        if not is_url and services:
            inferred_urls = infer_web_urls(
                hostname=hostname, ip_address=ip_address, services=services,
            )
            if inferred_urls:
                asset.base_url = inferred_urls[0]
                asset.kind = AssetKind.WEB_APPLICATION

        # For plain-host scope entries with an execution plane, run an initial port scan
        if not is_url and self.tool_gateway is not None:
            try:
                bundle = self.run_capability(
                    task=task,
                    capability=ToolCapability.HOST_INVENTORY,
                    timeout_s=60,
                    metadata={
                        "asset_id": asset_id,
                        "hostname": hostname,
                    },
                )
                # Merge any services/IP discovered by the port scan into our asset
                for scanned_asset in bundle.parsed.asset_updates:
                    asset.merge(scanned_asset)
                # Update base_url from newly discovered services
                if not asset.base_url:
                    post_scan_urls = infer_web_urls(
                        hostname=asset.hostname,
                        ip_address=asset.ip_address,
                        services=asset.services,
                    )
                    if post_scan_urls:
                        asset.base_url = post_scan_urls[0]
                        asset.kind = AssetKind.WEB_APPLICATION
                output_context = {
                    "asset_id": asset.asset_id,
                    "scope": scope_entry,
                    "ip_address": ip_address,
                    **bundle.parsed.output_context,
                }
                guidance = self._generate_guidance(
                    task=task,
                    state=state,
                    scope_entry=scope_entry,
                    asset=asset,
                    output_context=output_context,
                    findings=[finding.model_dump(mode="json") for finding in bundle.parsed.finding_updates],
                )
                suggested_tasks = [
                    build_web_review_task(asset.asset_id, base_url)
                    for base_url in infer_web_urls(
                        hostname=asset.hostname,
                        ip_address=asset.ip_address,
                        services=asset.services,
                    )
                ]
                banner_ports = sorted({service.port for service in asset.services if service.port})
                if banner_ports and asset.hostname:
                    suggested_tasks.append(
                        build_service_banner_task(
                            asset_id=asset.asset_id,
                            hostname=asset.hostname,
                            ports=banner_ports,
                        )
                    )
                output_context["llm_summary"] = guidance.summary
                output_context["manual_checks"] = guidance.manual_checks
                suggested_tasks.extend(
                    build_flag_validation_tasks(
                        guidance.grounded_flag_candidates, source="recon"
                    )
                )
                if state.metadata.get("challenge", {}).get("files"):
                    if guidance.should_schedule_flag_hunt:
                        suggested_tasks.append(
                            build_flag_hunt_task(
                                files_root="/home/ctfplayer/ctf_files",
                                seed_terms=guidance.interesting_paths or [scope_entry],
                                priority=91,
                            )
                        )
                    if guidance.should_schedule_credential_hunt:
                        suggested_tasks.append(
                            build_credential_hunt_task(
                                files_root="/home/ctfplayer/ctf_files",
                                seed_terms=[scope_entry],
                                priority=87,
                            )
                        )
                notes.extend(bundle.parsed.notes)
                notes.append(
                    f"{self.name} completed initial port scan for {hostname}."
                )
                return WorkerReport(
                    task_id=task.task_id,
                    worker_name=self.name,
                    success=True,
                    summary=f"Enumerated host asset {asset.asset_id} with port scan.",
                    output_context=output_context,
                    asset_updates=[asset],
                    finding_updates=bundle.parsed.finding_updates,
                    state_delta=bundle.state_delta,
                    evidence_updates=[bundle.evidence],
                    planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks),
                    notes=notes,
                )
            except ToolExecutionError as exc:
                notes.append(f"Initial port scan failed: {exc}; asset registered without scan data.")

        output_context = {
            "asset_id": asset.asset_id,
            "scope": scope_entry,
            "ip_address": ip_address,
        }
        guidance = self._generate_guidance(
            task=task,
            state=state,
            scope_entry=scope_entry,
            asset=asset,
            output_context=output_context,
            findings=[],
        )
        output_context["llm_summary"] = guidance.summary
        output_context["manual_checks"] = guidance.manual_checks
        suggested_tasks = build_flag_validation_tasks(
            guidance.grounded_flag_candidates, source="recon"
        )
        if state.metadata.get("challenge", {}).get("files"):
            if guidance.should_schedule_flag_hunt:
                suggested_tasks.append(
                    build_flag_hunt_task(
                        files_root="/home/ctfplayer/ctf_files",
                        seed_terms=guidance.interesting_paths or [scope_entry],
                        priority=91,
                    )
                )
            if guidance.should_schedule_credential_hunt:
                suggested_tasks.append(
                    build_credential_hunt_task(
                        files_root="/home/ctfplayer/ctf_files",
                        seed_terms=[scope_entry],
                        priority=87,
                    )
                )

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=f"Registered asset {asset.asset_id} from scope entry {scope_entry!r}.",
            output_context=output_context,
            asset_updates=[asset],
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks),
            notes=notes,
        )
