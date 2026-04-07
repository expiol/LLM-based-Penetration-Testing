"""Task planning strategies for the orchestrator."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from nyuctf_mutil_killchain.agents.base import extract_flag_candidates, normalize_probe_paths
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.prompts import get_planner_system_prompt, get_prompts
from nyuctf_mutil_killchain.state import Asset, AssetKind, GlobalState, Task, TaskStatus

_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".rb", ".pl", ".sh", ".c", ".cpp", ".h", ".java",
    ".php", ".go", ".rs", ".sage", ".txt", ".md", ".yml", ".yaml",
    ".json", ".xml", ".html", ".css", ".sql", ".lua", ".r",
})

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
        # Flag validation
        "flag.validate",
        # LLM solver code generation and execution
        "solve.generate_script",
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
    """Minimal bootstrap planner that seeds the initial task queue.

    Only handles two concerns:
    1. Bootstrapping recon tasks for authorized scope entries.
    2. Bootstrapping artifact triage when challenge files exist.
    3. Validating flag candidates discovered in findings.

    All deeper planning (escalation, credential hunts, exploit reasoning,
    category-specific pivots) is delegated to the LLM planner.
    """

    def plan(self, state: GlobalState) -> PlannerDecision:
        tasks: list[PlannedTask] = []
        notes: list[str] = []
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])

        # Bootstrap: artifact triage for bundled challenge files
        if challenge_files:
            dedupe_key = "artifact-triage:challenge-files"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is None:
                tasks.append(
                    PlannedTask(
                        title="Inventory challenge files",
                        description="Enumerate bundled files in /home/ctfplayer/ctf_files and classify interesting artifacts.",
                        task_type="artifact.triage",
                        priority=95,
                        input_context={"files_root": "/home/ctfplayer/ctf_files", "max_files": 80},
                        dedupe_key=dedupe_key,
                        metadata={"planned_by": "bootstrap", "challenge_files": challenge_files},
                    )
                )

        # Bootstrap: recon for each authorized scope entry
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
                        metadata={"planned_by": "bootstrap"},
                    )
                )

        # Always: validate any discovered flag candidates in findings
        tasks.extend(self._plan_flag_validation(state))

        summary = f"Bootstrap planner proposed {len(tasks)} task(s)."
        return PlannerDecision(summary=summary, tasks=tasks, notes=notes)

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

        for candidate, source in candidate_sources[:6]:
            dedupe_key = f"flag-validate:{candidate}"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is not None:
                continue
            tasks.append(
                PlannedTask(
                    title="Validate candidate flag",
                    description="Compare a discovered flag candidate against the expected challenge flag.",
                    task_type="flag.validate",
                    priority=99,
                    input_context={"candidate_flag": candidate, "candidate_source": source},
                    dedupe_key=dedupe_key,
                    metadata={"planned_by": "bootstrap"},
                )
            )
        return tasks


class LLMPlanner(TaskPlanner):
    """Primary planner that uses LLM with category-specific prompts for task proposals.

    Falls back to the bootstrap planner only when the LLM call fails.
    The LLM receives the full state snapshot plus category-tuned instructions
    so it can propose the optimal next steps for web, rev, crypto, forensics,
    pwn, or misc challenges.
    """

    def __init__(self, llm_client: LLMClient, fallback: TaskPlanner | None = None) -> None:
        self.llm_client = llm_client
        self.fallback = fallback or HeuristicPlanner()

    def plan(self, state: GlobalState) -> PlannerDecision:
        bootstrap_decision = self.fallback.plan(state)

        try:
            raw_decision = self.llm_client.generate_json(
                system_prompt=self._system_prompt(state),
                user_prompt=self._user_prompt(state),
                schema=PlannerDecision,
            )
        except (LLMClientError, Exception) as exc:
            bootstrap_decision.notes.append(
                f"LLM planner failed ({type(exc).__name__}), using bootstrap fallback."
            )
            return bootstrap_decision

        sanitized_tasks = [
            task for task in raw_decision.tasks if task.task_type in APPROVED_TASK_TYPES
        ]

        merged_tasks = list(bootstrap_decision.tasks)
        existing_dedupe_keys = {t.dedupe_key for t in merged_tasks if t.dedupe_key}
        for task in sanitized_tasks:
            self._normalize_planned_task(task, state)
            if not task.dedupe_key:
                task.dedupe_key = self._default_dedupe_key(task)
            task.metadata["planned_by"] = "llm-planner"
            if task.dedupe_key not in existing_dedupe_keys:
                merged_tasks.append(task)
                existing_dedupe_keys.add(task.dedupe_key)

        return PlannerDecision(
            summary=raw_decision.summary or bootstrap_decision.summary,
            tasks=merged_tasks,
            notes=raw_decision.notes + bootstrap_decision.notes,
            stop_run=raw_decision.stop_run,
        )

    # ------------------------------------------------------------------
    # Task context normalization
    # ------------------------------------------------------------------

    def _normalize_planned_task(self, task: PlannedTask, state: GlobalState) -> None:
        """Fill in missing required input_context fields from state.

        The LLM planner frequently omits required fields like ``source_files``
        or ``files_root``, causing downstream workers to reject the task in
        ``can_route_task``.  This method infers sensible defaults from the
        challenge metadata and accumulated findings before the task enters the
        queue.
        """
        ctx = task.input_context
        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])

        if task.task_type.startswith(("artifact.", "solve.", "credential.", "flag.")):
            ctx.setdefault("files_root", _DEFAULT_FILES_ROOT)

        if task.task_type in (
            "artifact.source_review",
            "artifact.computation_analysis",
            "artifact.runtime_probe",
        ) and not ctx.get("source_files"):
            ctx["source_files"] = (
                self._infer_source_files(state, challenge_files) or challenge_files
            )

        if task.task_type == "artifact.binary_triage" and not ctx.get("binary_files"):
            inferred = self._infer_non_source_files(challenge_files)
            if inferred:
                ctx["binary_files"] = inferred

        if task.task_type == "artifact.deep_review":
            self._normalize_deep_review_context(ctx, challenge_files)

    @staticmethod
    def _infer_source_files(
        state: GlobalState, challenge_files: list[str],
    ) -> list[str]:
        """Infer source file list from findings or file extensions."""
        for finding in state.findings.values():
            meta = finding.metadata
            if meta.get("source") == "artifact_triage":
                for key in ("web_source_files", "source_web_files", "source_files"):
                    files = meta.get(key)
                    if isinstance(files, list) and files:
                        return list(files)

        return [
            f for f in challenge_files
            if "." in f
            and ("." + f.rsplit(".", 1)[-1].lower()) in _SOURCE_EXTENSIONS
        ]

    @staticmethod
    def _infer_non_source_files(challenge_files: list[str]) -> list[str]:
        return [
            f for f in challenge_files
            if "." not in f
            or ("." + f.rsplit(".", 1)[-1].lower()) not in _SOURCE_EXTENSIONS
        ]

    @staticmethod
    def _normalize_deep_review_context(
        ctx: dict[str, Any], challenge_files: list[str],
    ) -> None:
        """Map alternate field names (``target_files``, ``files``) to the
        canonical field expected by deep-review workers."""
        _KNOWN_FIELDS = (
            "binary_files", "source_files", "archive_files",
            "database_files", "pcap_files", "repo_paths",
        )
        if any(ctx.get(field) for field in _KNOWN_FIELDS):
            return

        alt_files = ctx.pop("target_files", None) or ctx.pop("files", None) or []
        if not alt_files:
            return

        analysis_kind = str(ctx.get("analysis_kind", "")).lower()
        _KIND_TO_FIELD = {
            "binary": "binary_files",
            "archive": "archive_files",
            "sqlite": "database_files",
            "database": "database_files",
            "pcap": "pcap_files",
            "repo": "repo_paths",
            "git": "repo_paths",
        }
        for keyword, field in _KIND_TO_FIELD.items():
            if keyword in analysis_kind:
                ctx[field] = alt_files
                return

        source = [
            f for f in alt_files
            if "." in f
            and ("." + f.rsplit(".", 1)[-1].lower()) in _SOURCE_EXTENSIONS
        ]
        if source:
            ctx["source_files"] = alt_files
            ctx.setdefault("analysis_kind", "source")
        else:
            ctx["binary_files"] = alt_files
            ctx.setdefault("analysis_kind", "binary")

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
        if task.task_type == "web.crawl":
            asset_id = task.input_context.get("asset_id", task.title)
            base_url = task.input_context.get("base_url", task.title)
            return f"web-crawl:{asset_id}:{base_url}"
        if task.task_type == "web.header_analysis":
            asset_id = task.input_context.get("asset_id", task.title)
            base_url = task.input_context.get("base_url", task.title)
            return f"web-header-analysis:{asset_id}:{base_url}"
        if task.task_type == "web.form_probe":
            asset_id = task.input_context.get("asset_id", task.title)
            page_url = task.input_context.get("page_url", task.title)
            return f"web-form-probe:{asset_id}:{page_url}"
        if task.task_type in {"host.port_scan", "host.service_fingerprint"}:
            asset_id = task.input_context.get("asset_id", task.title)
            hostname = task.input_context.get("hostname", "")
            return f"{task.task_type}:{asset_id}:{hostname}"
        if task.task_type in {"post_exploit.loot", "post_exploit.lateral_move"}:
            asset_id = task.input_context.get("asset_id", task.title)
            return f"{task.task_type}:{asset_id}"
        if task.task_type == "flag.validate":
            candidate = task.input_context.get("candidate_flag", task.title)
            return f"flag-validate:{candidate}"
        return f"{task.task_type}:{task.title}"

    def _system_prompt(self, state: GlobalState) -> str:
        challenge_meta = state.metadata.get("challenge", {})
        category = str(challenge_meta.get("category") or "misc").lower()
        approved = sorted(APPROVED_TASK_TYPES)
        return get_planner_system_prompt(category, approved)

    @staticmethod
    def _build_progress_assessment(state: GlobalState) -> dict[str, Any]:
        """Build a structured progress assessment for the LLM planner.

        Computes which task types have been completed / attempted / are still
        pending, and derives the current workflow phase so the LLM clearly
        sees what it should propose next.
        """
        completed_types: dict[str, int] = {}
        failed_types: dict[str, int] = {}
        pending_types: dict[str, int] = {}
        for task in state.task_chain.tasks:
            bucket = (
                completed_types if task.status == TaskStatus.COMPLETED
                else failed_types if task.status == TaskStatus.FAILED
                else pending_types
            )
            bucket[task.task_type] = bucket.get(task.task_type, 0) + 1

        has_triage = "artifact.triage" in completed_types
        has_analysis = any(
            t in completed_types
            for t in (
                "artifact.source_review",
                "artifact.computation_analysis",
                "artifact.runtime_probe",
                "artifact.binary_triage",
                "artifact.deep_review",
            )
        )
        solver_ever_tried = (
            "solve.generate_script" in completed_types
            or "solve.generate_script" in pending_types
            or "solve.generate_script" in failed_types
        )
        has_solver = solver_ever_tried
        solver_failed = "solve.generate_script" in failed_types
        has_exploit = any(
            t in completed_types for t in ("exploit.hypothesis", "exploit.cve_probe", "exploit.sqli")
        )
        has_validated_flag = state.solved

        if has_validated_flag:
            phase = "SOLVED"
        elif has_solver or has_exploit:
            phase = "EXPLOITATION"
        elif has_analysis:
            phase = "ANALYSIS_COMPLETE"
        elif has_triage:
            phase = "TRIAGE_COMPLETE"
        else:
            phase = "INITIAL"

        phase_guidance = {
            "INITIAL": "Start with artifact.triage or recon.enumerate_scope to gather initial information.",
            "TRIAGE_COMPLETE": (
                "Triage is done. Schedule analysis tasks (artifact.source_review, "
                "artifact.computation_analysis, artifact.binary_triage) to understand "
                "the challenge internals."
            ),
            "ANALYSIS_COMPLETE": (
                "Analysis is done. You MUST now schedule a 'solve.generate_script' task "
                "to write and execute a solver based on the accumulated evidence. "
                "This is the critical next step — do NOT schedule more analysis. "
                "Priority should be >= 90."
            ),
            "EXPLOITATION": (
                "Solver/exploit attempts are underway. If they failed, schedule "
                "another 'solve.generate_script' with a different approach, or "
                "gather more targeted evidence first."
            ),
            "SOLVED": "The flag has been found. No more tasks are needed (set stop_run=true).",
        }

        return {
            "current_phase": phase,
            "phase_guidance": phase_guidance[phase],
            "completed_task_types": completed_types,
            "failed_task_types": failed_types,
            "pending_task_types": pending_types,
            "solver_attempted": has_solver or solver_failed,
            "solver_succeeded": has_validated_flag,
        }

    def _user_prompt(self, state: GlobalState) -> str:
        challenge_meta = state.metadata.get("challenge", {})
        category = str(challenge_meta.get("category") or "misc").lower()
        prompts = get_prompts(category)

        snapshot = {
            "objective": state.objective,
            "authorized_scope": state.authorized_scope,
            "challenge_category": category,
            "analysis_strategy": prompts.analysis_strategy,
            "exploit_strategy": prompts.exploit_strategy,
            "flag_recovery_hints": prompts.flag_recovery_hints,
            "progress": self._build_progress_assessment(state),
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
                    "description": finding.description,
                    "asset_refs": finding.asset_refs,
                    "evidence_refs": finding.evidence_refs,
                    "metadata_keys": list(finding.metadata.keys()),
                }
                for finding in state.findings.values()
            ],
            "credentials": [
                {
                    "credential_id": cred.credential_id,
                    "username": cred.username,
                    "credential_type": cred.credential_type,
                    "asset_ref": cred.asset_ref,
                }
                for cred in list(state.credentials.values())[-8:]
            ],
            "task_history": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status,
                    "title": task.title,
                    "dedupe_key": task.dedupe_key,
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
