"""Task planning strategies for the orchestrator."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from nyuctf_mutil_killchain.agents.base import extract_flag_candidates
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.state import Asset, AssetKind, GlobalState, Task, TaskStatus

APPROVED_TASK_TYPES = frozenset(
    {
        # Reconnaissance
        "recon.enumerate_scope",
        "recon.dns_enum",
        "recon.subdomain_discovery",
        # Local artifact triage
        "artifact.triage",
        "artifact.archive_triage",
        "artifact.binary_triage",
        "artifact.computation_analysis",
        "artifact.runtime_probe",
        "artifact.sqlite_review",
        "artifact.pcap_review",
        "artifact.repo_review",
        "artifact.source_review",
        # Host-level assessment
        "host.audit",
        "host.banner_grab",
        "host.port_scan",
        "host.service_fingerprint",
        # Web assessment
        "web.review_surface",
        "web.content_review",
        "web.path_probe",
        "web.crawl",
        "web.header_analysis",
        # Vulnerability scanning
        "vuln.scan",
        "vuln.nuclei_probe",
        "vuln.nikto_scan",
        # Targeted exploitation (requires explicit scope auth)
        "exploit.cve_probe",
        "exploit.sqli",
        "exploit.credential_test",
        # Post-exploitation (requires explicit scope auth)
        "post_exploit.loot",
        "post_exploit.lateral_move",
        # Reporting
        "report.generate",
        # Flag validation
        "flag.validate",
    }
)

# Kept for backward compatibility
SAFE_TASK_TYPES = APPROVED_TASK_TYPES


class PlannedTask(BaseModel):
    """Normalised task specification emitted by a planner."""

    title: str
    description: str
    task_type: str
    priority: int = Field(default=50, ge=0, le=100)
    input_context: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    dedupe_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_task(self) -> Task:
        return Task(
            title=self.title,
            description=self.description,
            task_type=self.task_type,
            priority=self.priority,
            input_context=self.input_context,
            dependencies=self.dependencies,
            dedupe_key=self.dedupe_key,
            metadata=self.metadata,
        )


class PlannerDecision(BaseModel):
    """Planner output before tasks are merged into the live task chain."""

    summary: str
    tasks: list[PlannedTask] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    stop_run: bool = False


class TaskPlanner(ABC):
    """Planner that proposes follow-up work from the latest global state."""

    @abstractmethod
    def plan(self, state: GlobalState) -> PlannerDecision:
        """Return task updates to merge into the task chain."""


class HeuristicPlanner(TaskPlanner):
    """Deterministic planner that drives the standard recon → audit → vuln-scan pipeline."""

    def plan(self, state: GlobalState) -> PlannerDecision:
        tasks: list[PlannedTask] = []
        notes: list[str] = []
        challenge_files = state.metadata.get("challenge", {}).get("files", [])

        artifact_task = self._plan_artifact_triage(state)
        if artifact_task is not None:
            tasks.append(artifact_task)
        tasks.extend(self._plan_flag_validation(state))

        if not state.authorized_scope and not challenge_files:
            notes.append("No authorized scope configured; planner cannot seed recon tasks.")

        for index, scope in enumerate(state.authorized_scope, start=1):
            dedupe_key = f"bootstrap:recon:{scope}"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is None:
                asset_id = (
                    "seed-asset"
                    if len(state.authorized_scope) == 1
                    else f"seed-asset-{index}"
                )
                tasks.append(
                    PlannedTask(
                        title=f"Map authorized surface {index}",
                        description="Normalise a scope entry into a tracked asset with DNS resolution.",
                        task_type="recon.enumerate_scope",
                        priority=100,
                        input_context={"scope": scope, "asset_id": asset_id},
                        dedupe_key=dedupe_key,
                        metadata={"planned_by": "heuristic-planner"},
                    )
                )

        for asset in state.assets.values():
            if asset.kind == AssetKind.HOST and not asset.base_url:
                host_task = self._plan_host_audit(asset, state)
                if host_task is not None:
                    tasks.append(host_task)
                vuln_task = self._plan_vuln_scan(asset, state)
                if vuln_task is not None:
                    tasks.append(vuln_task)
            else:
                web_task = self._plan_web_review(asset, state)
                if web_task is not None:
                    tasks.append(web_task)
                vuln_task = self._plan_vuln_scan(asset, state)
                if vuln_task is not None:
                    tasks.append(vuln_task)

        summary = f"Planner proposed {len(tasks)} task(s)."
        return PlannerDecision(summary=summary, tasks=tasks, notes=notes)

    def _plan_web_review(self, asset: Asset, state: GlobalState) -> PlannedTask | None:
        if not asset.base_url:
            return None
        dedupe_key = f"web-review:{asset.asset_id}:{asset.base_url}"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None
        return PlannedTask(
            title=f"Review web surface for {asset.asset_id}",
            description="Collect HTTP metadata and create an evidence-based assessment note.",
            task_type="web.review_surface",
            priority=80,
            input_context={"asset_id": asset.asset_id, "base_url": asset.base_url},
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

    def _plan_artifact_triage(self, state: GlobalState) -> PlannedTask | None:
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])
        if not challenge_files:
            return None

        dedupe_key = "artifact-triage:challenge-files"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        return PlannedTask(
            title="Inventory challenge files",
            description="Enumerate bundled files in /home/ctfplayer/ctf_files and classify interesting artifacts.",
            task_type="artifact.triage",
            priority=95,
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "max_files": 80,
            },
            dedupe_key=dedupe_key,
            metadata={
                "planned_by": "heuristic-planner",
                "challenge_files": challenge_files,
            },
        )

    def _plan_flag_validation(self, state: GlobalState) -> list[PlannedTask]:
        tasks: list[PlannedTask] = []
        if state.solved:
            return tasks

        candidate_sources: list[tuple[str, str]] = []
        for finding in state.findings.values():
            if finding.metadata.get("validated") is True:
                continue
            for candidate in extract_flag_candidates(
                finding.description or "",
                *[str(ref) for ref in finding.evidence_refs],
            ):
                candidate_sources.append((candidate, f"finding:{finding.finding_id}"))

        for candidate, source in candidate_sources[:12]:
            dedupe_key = f"flag-validate:{candidate}"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
                continue
            tasks.append(
                PlannedTask(
                    title="Validate candidate flag",
                    description="Compare a discovered flag candidate against the expected challenge flag.",
                    task_type="flag.validate",
                    priority=99,
                    input_context={
                        "candidate_flag": candidate,
                        "candidate_source": source,
                    },
                    dedupe_key=dedupe_key,
                    metadata={"planned_by": "heuristic-planner"},
                )
            )
        return tasks

    def _plan_host_audit(self, asset: Asset, state: GlobalState) -> PlannedTask | None:
        dedupe_key = f"host-audit:{asset.asset_id}"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        known_ports = sorted({service.port for service in asset.services})
        return PlannedTask(
            title=f"Audit host for {asset.asset_id}",
            description="Run a port scan and service fingerprint via nmap (or socket fallback).",
            task_type="host.audit",
            priority=70,
            input_context={
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "ports": ",".join(str(port) for port in known_ports) if known_ports else None,
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

    def _plan_vuln_scan(self, asset: Asset, state: GlobalState) -> PlannedTask | None:
        dedupe_key = f"vuln-scan:{asset.asset_id}"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        # Only propose vuln scan once the prior-layer scan (web review or host audit)
        # has successfully COMPLETED and produced real evidence. This prevents orphaned
        # vuln.scan tasks being blocked when no VulnScanAgent worker is registered.
        web_task_completed = any(
            task.dedupe_key is not None
            and task.dedupe_key.startswith(f"web-review:{asset.asset_id}:")
            and task.status == TaskStatus.COMPLETED
            for task in state.task_chain.tasks
        )
        host_task = state.task_chain.find_by_dedupe_key(f"host-audit:{asset.asset_id}")
        prerequisite_completed = (
            web_task_completed
            or (host_task is not None and host_task.status == TaskStatus.COMPLETED)
        )
        if not prerequisite_completed:
            return None

        target = asset.base_url or asset.hostname or asset.ip_address
        if not target:
            return None

        return PlannedTask(
            title=f"Vulnerability scan for {asset.asset_id}",
            description="Run nuclei/nikto vulnerability scanner against the target.",
            task_type="vuln.scan",
            priority=60,
            input_context={
                "asset_id": asset.asset_id,
                "target": target,
                "base_url": asset.base_url,
                "hostname": asset.hostname,
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )


class LLMPlanner(TaskPlanner):
    """Planner that asks an LLM for context-aware next-step task proposals."""

    def __init__(self, llm_client: LLMClient, fallback: TaskPlanner | None = None) -> None:
        self.llm_client = llm_client
        self.fallback = fallback or HeuristicPlanner()

    def plan(self, state: GlobalState) -> PlannerDecision:
        fallback_decision = self.fallback.plan(state)
        try:
            raw_decision = self.llm_client.generate_json(
                system_prompt=self._system_prompt(),
                user_prompt=self._user_prompt(state),
                schema=PlannerDecision,
            )
        except (LLMClientError, ValidationError):
            return fallback_decision

        sanitized_tasks = [
            task for task in raw_decision.tasks if task.task_type in APPROVED_TASK_TYPES
        ]
        if not sanitized_tasks and fallback_decision.tasks:
            return fallback_decision

        for task in sanitized_tasks:
            if not task.dedupe_key:
                task.dedupe_key = self._default_dedupe_key(task)
            task.metadata["planned_by"] = "llm-planner"

        return PlannerDecision(
            summary=raw_decision.summary,
            tasks=sanitized_tasks,
            notes=raw_decision.notes,
            stop_run=raw_decision.stop_run,
        )

    def _default_dedupe_key(self, task: PlannedTask) -> str:
        if task.task_type == "recon.enumerate_scope":
            scope = task.input_context.get("scope", task.title)
            return f"bootstrap:recon:{scope}"
        if task.task_type == "web.review_surface":
            asset_id = task.input_context.get("asset_id", task.title)
            base_url = task.input_context.get("base_url", task.title)
            return f"web-review:{asset_id}:{base_url}"
        if task.task_type == "web.content_review":
            asset_id = task.input_context.get("asset_id", task.title)
            base_url = task.input_context.get("base_url", task.title)
            return f"web-content:{asset_id}:{base_url}"
        if task.task_type == "artifact.triage":
            return "artifact-triage:challenge-files"
        if task.task_type == "artifact.binary_triage":
            files = task.input_context.get("binary_files", [])
            return "artifact-binary-triage:" + ",".join(files[:8])
        if task.task_type == "artifact.computation_analysis":
            files = task.input_context.get("source_files", [])
            return "artifact-computation-analysis:" + ",".join(files[:8])
        if task.task_type == "artifact.runtime_probe":
            files = task.input_context.get("source_files", [])
            return "artifact-runtime-probe:" + ",".join(files[:8])
        if task.task_type == "artifact.archive_triage":
            files = task.input_context.get("archive_files", [])
            return "artifact-archive-triage:" + ",".join(files[:8])
        if task.task_type == "artifact.sqlite_review":
            files = task.input_context.get("database_files", [])
            return "artifact-sqlite-review:" + ",".join(files[:8])
        if task.task_type == "artifact.pcap_review":
            files = task.input_context.get("pcap_files", [])
            return "artifact-pcap-review:" + ",".join(files[:8])
        if task.task_type == "artifact.repo_review":
            files = task.input_context.get("repo_paths", [])
            return "artifact-repo-review:" + ",".join(files[:8])
        if task.task_type == "artifact.source_review":
            files = task.input_context.get("source_files", [])
            return "artifact-source-review:" + ",".join(files[:8])
        if task.task_type in {"host.audit", "host.port_scan"}:
            asset_id = task.input_context.get("asset_id", task.title)
            return f"host-audit:{asset_id}"
        if task.task_type == "host.banner_grab":
            asset_id = task.input_context.get("asset_id", task.title)
            ports = task.input_context.get("ports", [])
            return f"host-banner:{asset_id}:{','.join(str(port) for port in ports[:8])}"
        if task.task_type in {"vuln.scan", "vuln.nuclei_probe"}:
            asset_id = task.input_context.get("asset_id", task.title)
            return f"vuln-scan:{asset_id}"
        if task.task_type == "web.path_probe":
            asset_id = task.input_context.get("asset_id", task.title)
            base_url = task.input_context.get("base_url", task.title)
            paths = task.input_context.get("paths", [])
            return f"web-path-probe:{asset_id}:{base_url}:{','.join(paths[:8])}"
        if task.task_type == "flag.validate":
            candidate = task.input_context.get("candidate_flag", task.title)
            return f"flag-validate:{candidate}"
        return f"{task.task_type}:{task.title}"

    def _system_prompt(self) -> str:
        approved = sorted(APPROVED_TASK_TYPES)
        return (
            "You are the planning component of an authorized penetration testing workflow. "
            "You operate within the explicitly approved scope only. "
            "Return only JSON matching the PlannerDecision schema. "
            f"You may only propose tasks from this approved list: {json.dumps(approved)}. "
            "Exploitation tasks (exploit.*, post_exploit.*) must only be proposed when the "
            "asset is in the authorized_scope AND prior reconnaissance or scanning has "
            "identified a concrete, exploitable finding. "
            "Never propose tasks outside the authorized_scope. "
            "Never fabricate vulnerability details — only reference findings already in state."
        )

    def _user_prompt(self, state: GlobalState) -> str:
        snapshot = {
            "objective": state.objective,
            "authorized_scope": state.authorized_scope,
            "summary": state.summary(),
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "kind": asset.kind,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "base_url": asset.base_url,
                    "services": [
                        {"port": s.port, "name": s.name, "product": s.product, "version": s.version}
                        for s in asset.services
                    ],
                    "tags": sorted(asset.tags),
                }
                for asset in state.assets.values()
            ],
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "asset_refs": finding.asset_refs,
                    "metadata_keys": list(finding.metadata.keys()),
                }
                for finding in state.findings.values()
            ],
            "open_tasks": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status,
                    "dedupe_key": task.dedupe_key,
                    "input_context": task.input_context,
                }
                for task in state.task_chain.tasks
            ],
            "recent_execution_log": [
                {
                    "task_id": record.task_id,
                    "worker_name": record.worker_name,
                    "success": record.success,
                    "summary": record.summary,
                    "error": record.error,
                }
                for record in state.execution_log[-8:]
            ],
        }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)
