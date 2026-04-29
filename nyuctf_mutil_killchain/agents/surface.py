"""Consolidated reconnaissance-surface worker.

A single :class:`SurfaceWorker` exposes both web (assessment, content review,
form probe, path probe) and host (audit, banner) task types under one
orchestrator-facing interface.  Internally it delegates to the existing
per-task worker classes — keeping their well-tested logic intact while
removing the worker-zoo problem at the orchestrator level.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.enrichment import ServiceBannerAgent, WebPathProbeAgent
from nyuctf_mutil_killchain.agents.host import HostAuditAgent
from nyuctf_mutil_killchain.agents.web import WebAssessmentAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.agents.web_form import WebFormProbeAgent
from nyuctf_mutil_killchain.llm import LLMClient
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ExecutionPlane


class SurfaceWorker(WorkerAgent):
    """Stage-level worker for the reconnaissance / surface phase.

    Handles all web and host task types by delegating to the matching internal
    worker.  This collapses six fine-grained agents into one orchestrator-visible
    worker while keeping their behavior unchanged.
    """

    name = "surface-worker"
    supported_task_types = (
        "web.review_surface",
        "web.header_analysis",
        "web.content_review",
        "web.crawl",
        "web.form_probe",
        "web.path_probe",
        "host.audit",
        "host.port_scan",
        "host.banner_grab",
        "host.service_fingerprint",
    )
    routing_summary = "Unified surface worker for web (assessment, content, form, path) and host (audit, banner) tasks."
    preferred_challenge_categories = ("web", "misc", "forensics")

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
    ) -> None:
        super().__init__(llm_client=llm_client, execution_plane=execution_plane)
        kwargs = {"llm_client": llm_client, "execution_plane": execution_plane}
        self._web_assess = WebAssessmentAgent(**kwargs)
        self._web_content = WebContentAgent(**kwargs)
        self._web_form = WebFormProbeAgent(**kwargs)
        self._web_path = WebPathProbeAgent(**kwargs)
        self._host_audit = HostAuditAgent(**kwargs)
        self._host_banner = ServiceBannerAgent(**kwargs)

    def _delegate_for(self, task: Task) -> WorkerAgent | None:
        task_type = task.task_type
        if task_type in {"web.review_surface", "web.header_analysis"}:
            return self._web_assess
        if task_type in {"web.content_review", "web.crawl"}:
            return self._web_content
        if task_type == "web.form_probe":
            return self._web_form
        if task_type == "web.path_probe":
            return self._web_path
        if task_type in {"host.audit", "host.port_scan"}:
            return self._host_audit
        if task_type in {"host.banner_grab", "host.service_fingerprint"}:
            return self._host_banner
        return None

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        delegate = self._delegate_for(task)
        if delegate is None:
            return super().can_route_task(task, state)
        return delegate.can_route_task(task, state)

    def routing_score(self, task: Task, state: GlobalState) -> int:
        delegate = self._delegate_for(task)
        if delegate is None:
            return super().routing_score(task, state)
        return delegate.routing_score(task, state)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        delegate = self._delegate_for(task)
        if delegate is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"SurfaceWorker has no delegate for task type {task.task_type!r}.",
                error="Unknown surface task type.",
                retryable=False,
            )
        report = delegate.run(task, state)
        report.worker_name = self.name
        return report
