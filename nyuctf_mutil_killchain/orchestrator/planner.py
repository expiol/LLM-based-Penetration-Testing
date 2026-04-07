"""Task planning strategies for the orchestrator."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from nyuctf_mutil_killchain.agents.base import extract_flag_candidates, normalize_probe_paths
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.state import Asset, AssetKind, GlobalState, Task, TaskStatus

APPROVED_TASK_TYPES = frozenset(
    {
        # Reconnaissance
        "recon.enumerate_scope",
        "recon.dns_enum",
        "recon.subdomain_discovery",
        # CTF-specific reasoning stages
        "credential.hunt",
        "flag.hunt",
        # Local artifact triage
        "artifact.triage",
        "artifact.archive_triage",
        "artifact.binary_triage",
        "artifact.computation_analysis",
        "artifact.deep_review",
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
        "web.form_probe",
        "web.path_probe",
        "web.crawl",
        "web.header_analysis",
        # Vulnerability scanning
        "vuln.scan",
        "vuln.nuclei_probe",
        "vuln.nikto_scan",
        # Targeted exploitation (requires explicit scope auth)
        "exploit.hypothesis",
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
        credential_task = self._plan_credential_hunt(state)
        if credential_task is not None:
            tasks.append(credential_task)
        flag_hunt_task = self._plan_flag_hunt(state)
        if flag_hunt_task is not None:
            tasks.append(flag_hunt_task)
        exploit_reasoning_task = self._plan_exploit_reasoning(state)
        if exploit_reasoning_task is not None:
            tasks.append(exploit_reasoning_task)
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
                exploit_task = self._plan_cve_probe(asset, state)
                if exploit_task is not None:
                    tasks.append(exploit_task)
                vuln_task = self._plan_vuln_scan(asset, state)
                if vuln_task is not None:
                    tasks.append(vuln_task)
            else:
                web_task = self._plan_web_review(asset, state)
                if web_task is not None:
                    tasks.append(web_task)
                credential_test_task = self._plan_credential_test(asset, state)
                if credential_test_task is not None:
                    tasks.append(credential_test_task)
                exploit_task = self._plan_cve_probe(asset, state)
                if exploit_task is not None:
                    tasks.append(exploit_task)
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

    def _plan_credential_hunt(self, state: GlobalState) -> PlannedTask | None:
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])
        if not challenge_files:
            return None

        dedupe_key = "credential-hunt:/home/ctfplayer/ctf_files"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        return PlannedTask(
            title="Harvest candidate credentials",
            description=(
                "Search bundled challenge files for usernames, passwords, bearer tokens, "
                "cookies, and other credential artifacts that can unlock the next pivot."
            ),
            task_type="credential.hunt",
            priority=90,
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "seed_terms": [
                    challenge_meta.get("name"),
                    challenge_meta.get("category"),
                    challenge_meta.get("server_name"),
                    "login",
                    "admin",
                    "token",
                ],
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

    def _plan_flag_hunt(self, state: GlobalState) -> PlannedTask | None:
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])
        if not challenge_files or state.solved:
            return None

        dedupe_key = "flag-hunt:/home/ctfplayer/ctf_files"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        seed_terms = [
            challenge_meta.get("name"),
            challenge_meta.get("category"),
            challenge_meta.get("flag_format"),
            "flag",
            "submit",
            "secret",
        ]
        seed_terms.extend(
            str(finding.title)
            for finding in list(state.findings.values())[-4:]
            if finding.title
        )
        return PlannedTask(
            title="Hunt for concrete flag candidates",
            description=(
                "Search across bundled challenge artifacts for grounded flag candidates, "
                "decoded blobs, and flag-bearing routes."
            ),
            task_type="flag.hunt",
            priority=96,
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "seed_terms": [term for term in seed_terms if term],
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

    def _plan_exploit_reasoning(self, state: GlobalState) -> PlannedTask | None:
        if state.solved:
            return None
        if not state.assets and not state.findings and not state.credentials:
            return None

        dedupe_key = "exploit-hypothesis"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        focus_asset_ids = [asset.asset_id for asset in list(state.assets.values())[:4]]
        seed_terms: list[str] = []
        for finding in list(state.findings.values())[-4:]:
            if finding.title:
                seed_terms.append(str(finding.title))
            seed_terms.extend(str(ref) for ref in finding.evidence_refs[:4] if ref)
        if not seed_terms:
            for asset in list(state.assets.values())[:4]:
                if asset.base_url:
                    seed_terms.append(asset.base_url)
                elif asset.hostname:
                    seed_terms.append(asset.hostname)
        return PlannedTask(
            title="Synthesize CTF exploit hypotheses",
            description=(
                "Use accumulated findings, credentials, and service metadata to prioritize "
                "the shortest pivot toward the real flag."
            ),
            task_type="exploit.hypothesis",
            priority=76,
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "focus_asset_ids": focus_asset_ids,
                "seed_terms": seed_terms,
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
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

    def _available_credential_ids(self, state: GlobalState, *, asset_id: str | None = None) -> list[str]:
        credential_ids: list[str] = []
        for credential in state.credentials.values():
            if not credential.metadata.get("secret_value"):
                continue
            if asset_id and credential.asset_ref not in {None, "", asset_id, "challenge-files"}:
                continue
            credential_ids.append(credential.credential_id)
        return credential_ids[:8]

    def _plan_credential_test(self, asset: Asset, state: GlobalState) -> PlannedTask | None:
        if not asset.base_url:
            return None
        credential_ids = self._available_credential_ids(state, asset_id=asset.asset_id)
        if not credential_ids:
            return None

        dedupe_key = f"exploit-credential-test:{asset.asset_id}:{','.join(credential_ids[:6])}"
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        seed_paths: list[str] = []
        for finding in state.findings.values():
            if asset.asset_id not in finding.asset_refs:
                continue
            seed_paths.extend(str(ref) for ref in finding.evidence_refs if ref)

        return PlannedTask(
            title=f"Test recovered credentials against {asset.asset_id}",
            description=(
                "Reuse recovered usernames, passwords, tokens, and cookies against the live challenge "
                "application to unlock privileged routes or direct flag access."
            ),
            task_type="exploit.credential_test",
            priority=85,
            input_context={
                "asset_id": asset.asset_id,
                "base_url": asset.base_url,
                "credential_ids": credential_ids,
                "seed_paths": seed_paths[:12],
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

    def _plan_cve_probe(self, asset: Asset, state: GlobalState) -> PlannedTask | None:
        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "").lower()
        relevant_finding = any(
            asset.asset_id in finding.asset_refs
            and finding.severity in {"medium", "high", "critical"}
            for finding in state.findings.values()
        )
        if challenge_category not in {"web", "pwn", "misc"} and not relevant_finding:
            return None
        if not asset.base_url and not asset.hostname:
            return None

        seed_paths: list[str] = []
        for finding in state.findings.values():
            if asset.asset_id not in finding.asset_refs:
                continue
            seed_paths.extend(str(ref) for ref in finding.evidence_refs if ref)
        normalized_seed_paths = normalize_probe_paths(seed_paths, limit=16)
        dedupe_seed_paths = sorted(normalized_seed_paths)

        dedupe_key = (
            f"exploit-cve-probe:{asset.asset_id}:{asset.base_url or asset.hostname}:"
            f"{','.join(str(service.port) for service in asset.services[:6])}:"
            f"{','.join(self._available_credential_ids(state, asset_id=asset.asset_id)[:4])}:"
            f"{','.join(dedupe_seed_paths[:6])}"
        )
        if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
            return None

        grounded_web_task_types = {
            "web.content_review",
            "web.form_probe",
            "web.path_probe",
            "web.crawl",
            "web.header_analysis",
        }
        prerequisite_done = any(
            task.status == TaskStatus.COMPLETED
            and (
                (task.task_type in grounded_web_task_types and task.input_context.get("asset_id") == asset.asset_id)
                or (task.task_type.startswith("vuln.") and task.input_context.get("asset_id") == asset.asset_id)
                or (task.task_type == "host.banner_grab" and task.input_context.get("asset_id") == asset.asset_id)
                or task.task_type == "exploit.hypothesis"
            )
            for task in state.task_chain.tasks
        )
        if not prerequisite_done and not relevant_finding and challenge_category != "pwn":
            return None

        return PlannedTask(
            title=f"Probe targeted exploit paths for {asset.asset_id}",
            description=(
                "Attempt grounded web or TCP interactions against the authorized challenge target "
                "using recovered routes, prompts, and credentials."
            ),
            task_type="exploit.cve_probe",
            priority=78,
            input_context={
                "asset_id": asset.asset_id,
                "base_url": asset.base_url,
                "hostname": asset.hostname,
                "ports": [service.port for service in asset.services if service.port][:12],
                "credential_ids": self._available_credential_ids(state, asset_id=asset.asset_id),
                "seed_paths": normalized_seed_paths[:12],
            },
            dedupe_key=dedupe_key,
            metadata={"planned_by": "heuristic-planner"},
        )

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
        if task.task_type == "credential.hunt":
            return "credential-hunt:" + str(task.input_context.get("files_root", "/home/ctfplayer/ctf_files"))
        if task.task_type == "flag.hunt":
            return "flag-hunt:" + str(task.input_context.get("files_root", "/home/ctfplayer/ctf_files"))
        if task.task_type == "artifact.binary_triage":
            files = task.input_context.get("binary_files", [])
            return "artifact-binary-triage:" + ",".join(files[:8])
        if task.task_type == "artifact.computation_analysis":
            files = task.input_context.get("source_files", [])
            return "artifact-computation-analysis:" + ",".join(files[:8])
        if task.task_type == "artifact.deep_review":
            analysis_kind = task.input_context.get("analysis_kind", task.title)
            for field_name in ("archive_files", "binary_files", "database_files", "pcap_files", "repo_paths"):
                files = task.input_context.get(field_name, [])
                if files:
                    return f"artifact-deep-review:{analysis_kind}:{','.join(files[:8])}"
            return f"artifact-deep-review:{analysis_kind}"
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
        if task.task_type == "exploit.credential_test":
            asset_id = task.input_context.get("asset_id", task.title)
            credential_ids = task.input_context.get("credential_ids", [])
            return f"exploit-credential-test:{asset_id}:{','.join(str(item) for item in credential_ids[:6])}"
        if task.task_type == "exploit.hypothesis":
            focus_asset_ids = task.input_context.get("focus_asset_ids", [])
            seed_terms = task.input_context.get("seed_terms", [])
            return "exploit-hypothesis:" + ",".join(
                [*(str(item) for item in focus_asset_ids[:4]), *(str(item) for item in seed_terms[:4])]
            )
        if task.task_type == "exploit.cve_probe":
            asset_id = task.input_context.get("asset_id", task.title)
            ports = task.input_context.get("ports", [])
            credential_ids = task.input_context.get("credential_ids", [])
            target = task.input_context.get("base_url") or task.input_context.get("hostname") or task.title
            return (
                f"exploit-cve-probe:{asset_id}:{target}:"
                f"{','.join(str(port) for port in ports[:6])}:"
                f"{','.join(str(item) for item in credential_ids[:4])}"
            )
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
            "You are the planning component of an authorized CTF challenge-solving workflow. "
            "You operate within the explicitly approved challenge environment and scope only. "
            "Return only JSON matching the PlannerDecision schema. "
            f"You may only propose tasks from this approved list: {json.dumps(approved)}. "
            "Prioritize the shortest grounded path to the real flag rather than generic coverage. "
            "For rev/crypto/forensics/misc challenges with bundled files, prefer local artifact analysis, "
            "credential hunting, flag hunting, and computation/runtime pivots before broad network work. "
            "For web/pwn challenges, combine service discovery with source review, targeted path probing, "
            "credential reuse, executable exploit probes, and flag-oriented reasoning. "
            "Exploitation tasks (exploit.*, post_exploit.*) must only be proposed when the asset is in the "
            "authorized_scope AND prior evidence identifies a concrete pivot. "
            "Never propose tasks outside the authorized_scope or the provided challenge files. "
            "Never fabricate vulnerability details, credentials, or flag candidates."
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
