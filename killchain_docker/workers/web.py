"""Web assessment worker — HTTP metadata collection and LLM-assisted review."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from killchain_docker.workers.enrichment import WebPathProbeAgent
from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.specs import worker_specs
from killchain_docker.workers.web_content import WebContentAgent
from killchain_docker.workers.web_form import WebFormProbeAgent
from killchain_docker.llm import LLMClientError
from killchain_docker.prompts import get_worker_system_prompt
from killchain_docker.state import (
    Finding,
    GlobalState,
    Severity,
    StateDelta,
    Task,
    TaskErrorCode,
    WorkerReport,
)
from killchain_docker.state.task_factory import build_web_content_task
from killchain_docker.tools import ToolCapability, ToolExecutionError


class WebReviewNote(BaseModel):
    """Structured review note produced by web assessment."""

    summary: str
    risk_hypotheses: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)


class WebAssessmentAgent(WorkerAgent):
    """Performs HTTP metadata collection and generates a web assessment note.

    When an execution plane is present, makes real HTTP requests to the target
    and uses the response headers to drive risk analysis.  The LLM client, when
    configured, produces a richer narrative from the collected evidence.
    """

    name = "web-assessment-agent"
    supported_task_types = ("web.review_surface", "web.header_analysis")
    required_context_keys = ("asset_id", "base_url")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = task.input_context.get("asset_id")
        base_url = task.input_context.get("base_url")
        if not asset_id or not base_url:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing web task context.",
                error="asset_id and base_url are required in task.input_context",
                retryable=False,
                error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
            )

        evidence_updates = []
        asset_updates = []
        finding_updates = []
        state_delta = StateDelta()
        execution_notes: list[str] = []
        output_context: dict[str, Any] = {"reviewed_asset": asset_id}
        probe_context: dict[str, Any] = {}

        if self.tool_gateway is not None:
            try:
                bundle = self.run_capability(
                    task=task,
                    capability=ToolCapability.HTTP_METADATA,
                    timeout_s=task.input_context.get("timeout_s", 15),
                    metadata={"asset_id": asset_id, "base_url": base_url},
                )
            except ToolExecutionError as exc:
                return WorkerReport(
                    task_id=task.task_id,
                    worker_name=self.name,
                    success=False,
                    summary=f"HTTP metadata collection failed for {base_url}.",
                    error=str(exc),
                )

            evidence_updates.append(bundle.evidence)
            asset_updates.extend(bundle.parsed.asset_updates)
            finding_updates.extend(bundle.parsed.finding_updates)
            state_delta = bundle.state_delta
            execution_notes.extend(bundle.parsed.notes)
            probe_context = bundle.parsed.output_context
            output_context.update(probe_context)

        note = self._generate_note(
            task=task,
            state=state,
            asset_id=asset_id,
            base_url=base_url,
            probe_context=probe_context,
        )
        finding = self._build_review_finding(
            task=task,
            asset_id=asset_id,
            base_url=base_url,
            note=note,
            engine_finding=finding_updates[0] if finding_updates else None,
        )
        finding_updates = [finding, *finding_updates[1:]]
        output_context["manual_checks"] = note.manual_checks

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=f"Web assessment completed for {base_url}.",
            output_context=output_context,
            asset_updates=asset_updates,
            finding_updates=finding_updates,
            state_delta=state_delta,
            evidence_updates=evidence_updates,
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=[build_web_content_task(asset_id, base_url)]),
            notes=execution_notes + [f"{self.name} produced assessment note for {base_url}."],
        )

    def _build_review_finding(
        self,
        *,
        task: Task,
        asset_id: str,
        base_url: str,
        note: WebReviewNote,
        engine_finding: Finding | None,
    ) -> Finding:
        metadata = {
            "source_task_id": task.task_id,
            "mode": "llm-assisted",
            "risk_hypotheses": note.risk_hypotheses,
            "manual_checks": note.manual_checks,
        }

        if engine_finding is None:
            return Finding(
                finding_id=f"finding-{asset_id}-surface-review",
                title="Web surface review completed",
                severity=Severity.INFO,
                description=note.summary,
                asset_refs=[asset_id],
                evidence_refs=[base_url],
                metadata=metadata,
            )

        merged = engine_finding.model_copy(deep=True)
        merged.description = note.summary
        merged.asset_refs = sorted(set(merged.asset_refs) | {asset_id})
        merged.evidence_refs = sorted(set(merged.evidence_refs) | {base_url})
        merged.metadata.update(metadata)
        return merged

    def _generate_note(
        self,
        *,
        task: Task,
        state: GlobalState,
        asset_id: str,
        base_url: str,
        probe_context: dict[str, Any],
    ) -> WebReviewNote:
        if self.llm_client is None:
            raise LLMClientError("WebAssessmentAgent requires an LLM client but none was provided.")

        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "web").lower()
        return self.llm_client.generate_json(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You are a web security assessment analyst for a CTF challenge. "
                    "Generate specific, evidence-based risk hypotheses and actionable "
                    "manual checks based on the HTTP probe data. Focus on attack vectors "
                    "most likely to yield the flag: injection points, auth bypass, "
                    "exposed admin panels, and source code leaks."
                ),
                evidence_type="HTTP probe",
                output_schema="WebReviewNote",
            ),
            user_prompt=(
                f"Objective: {state.objective}\n"
                f"Asset ID: {asset_id}\n"
                f"Base URL: {base_url}\n"
                f"HTTP Status: {probe_context.get('http_status', 'unknown')}\n"
                f"Server: {probe_context.get('server', 'unknown')}\n"
                f"Powered-By: {probe_context.get('powered_by', 'unknown')}\n"
                f"Security Issues Found: {probe_context.get('security_issues', [])}\n"
                f"Response Headers: {probe_context.get('headers', {})}\n"
                f"Task ID: {task.task_id}\n"
                "Generate a concise, evidence-driven web assessment note."
            ),
            schema=WebReviewNote,
        )


GROUP = "web"

WORKER_CLASSES: tuple[type, ...] = (
    WebAssessmentAgent,
    WebContentAgent,
    WebFormProbeAgent,
    WebPathProbeAgent,
)

WORKER_SPECS = worker_specs(GROUP, WORKER_CLASSES)
