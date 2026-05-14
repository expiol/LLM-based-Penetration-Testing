"""Host audit worker — collects real host inventory through the execution plane."""

from __future__ import annotations

import json

from killchain_docker.workers._helpers.network import infer_web_urls
from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.enrichment import ServiceBannerAgent
from killchain_docker.reasoning import StageAnalysisGuidance
from killchain_docker.workers.recon import ReconAgent
from killchain_docker.workers.specs import worker_specs
from killchain_docker.prompts import get_worker_system_prompt
from killchain_docker.state import GlobalState, Task, TaskErrorCode, WorkerReport
from killchain_docker.state.task_factory import (
    build_flag_hunt_task,
    build_flag_validation_tasks,
    build_service_banner_task,
    build_web_review_task,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError


class HostAuditAgent(WorkerAgent):
    """Collects host inventory (open ports, services) via the execution plane.

    Requires an execution plane that can satisfy ``host.inventory``.
    Tasks assigned to this agent without an execution plane will fail with an
    actionable error so the orchestrator can decide whether to retry or skip.
    """

    name = "host-audit-agent"
    supported_task_types = ("host.audit", "host.port_scan")
    required_context_keys = ("asset_id", "hostname")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = task.input_context.get("asset_id")
        hostname = task.input_context.get("hostname")
        if not asset_id and not hostname:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing host task context.",
                error="asset_id or hostname is required in task.input_context",
                retryable=False,
                error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
            )

        if self.tool_gateway is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Host audit requires an execution plane; none is configured.",
                error=(
                    "HostAuditAgent.tool_gateway is None — "
                    f"configure capability {ToolCapability.HOST_INVENTORY.value!r} before dispatching host.audit tasks"
                ),
                retryable=False,
            )

        try:
            bundle = self.run_capability(
                task=task,
                capability=ToolCapability.HOST_INVENTORY,
                timeout_s=task.input_context.get("timeout_s", 90),
                metadata={
                    "asset_id": asset_id,
                    "hostname": hostname,
                    **(
                        {"ports": task.input_context.get("ports")}
                        if task.input_context.get("ports")
                        else {}
                    ),
                },
            )
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"Host audit tool execution failed for {hostname or asset_id}.",
                error=str(exc),
            )

        label = hostname or asset_id
        discovered_assets = bundle.parsed.asset_updates
        primary_asset = next((asset for asset in discovered_assets if asset.asset_id == asset_id), None)
        if primary_asset is None and discovered_assets:
            primary_asset = discovered_assets[0]
        output_context = dict(bundle.parsed.output_context)
        worker_notes = list(bundle.parsed.notes)
        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
        llm_guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze host-audit evidence (open ports, services, banners). "
                    "Determine which services are most promising for exploitation and "
                    "what follow-up tasks would be most productive."
                ),
                evidence_type="host-audit",
                output_schema="StageAnalysisGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "summary": bundle.parsed.summary,
                    "output_context": output_context,
                    "discovered_assets": [asset.model_dump(mode="json") for asset in discovered_assets],
                    "findings": [finding.model_dump(mode="json") for finding in bundle.parsed.finding_updates],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=StageAnalysisGuidance,
        )
        suggested_tasks = []
        if primary_asset is not None:
            suggested_tasks = [
                build_web_review_task(asset_id, base_url)
                for base_url in infer_web_urls(
                    hostname=primary_asset.hostname or hostname,
                    ip_address=primary_asset.ip_address,
                    services=primary_asset.services,
                )
            ]
            banner_ports = [service.port for service in primary_asset.services if service.port]
            if banner_ports and (primary_asset.hostname or hostname):
                suggested_tasks.append(
                    build_service_banner_task(
                        asset_id=asset_id or primary_asset.asset_id,
                        hostname=primary_asset.hostname or hostname,
                        ports=banner_ports,
                    )
                )

        output_context["llm_summary"] = llm_guidance.summary
        output_context["manual_checks"] = llm_guidance.manual_checks
        suggested_tasks.extend(
            build_flag_validation_tasks(
                llm_guidance.grounded_flag_candidates,
                source=ToolCapability.HOST_INVENTORY.value,
            )
        )
        if llm_guidance.should_schedule_flag_hunt and state.metadata.get("challenge", {}).get("files"):
            suggested_tasks.append(
                build_flag_hunt_task(
                    files_root="/home/ctfplayer/ctf_files",
                    seed_terms=llm_guidance.interesting_paths or [label],
                    priority=92,
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
            state_delta=bundle.state_delta,
            evidence_updates=[bundle.evidence],
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks),
            notes=worker_notes + [f"{self.name} completed host audit for {label}."],
        )


GROUP = "host"

WORKER_CLASSES: tuple[type, ...] = (
    ReconAgent,
    HostAuditAgent,
    ServiceBannerAgent,
)

WORKER_SPECS = worker_specs(GROUP, WORKER_CLASSES)
