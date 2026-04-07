"""Content-aware web review worker."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    build_web_form_probe_task,
    build_http_path_probe_task,
)
from nyuctf_mutil_killchain.llm import LLMClientError
from nyuctf_mutil_killchain.state import Finding, GlobalState, Severity, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class WebContentNote(BaseModel):
    """Structured content-review note produced by the worker."""

    summary: str
    attack_surface: list[str] = Field(default_factory=list)
    interesting_endpoints: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)
    potential_flags: list[str] = Field(default_factory=list)


class WebContentAgent(WorkerAgent):
    """Fetches response bodies and reasons about links, forms, and flag-like content."""

    name = "web-content-agent"
    supported_task_types = ("web.content_review",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = task.input_context.get("asset_id")
        base_url = task.input_context.get("base_url")
        if not asset_id or not base_url:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing web content task context.",
                error="asset_id and base_url are required in task.input_context",
            )

        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web content review requires an execution plane; none is configured.",
                error=(
                    "WebContentAgent.execution_plane is None — "
                    "register the local_http_content plugin before dispatching web.content_review tasks"
                ),
            )

        request = ToolExecutionRequest(
            tool_name="local_http_content",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 20),
            metadata={"asset_id": asset_id, "base_url": base_url},
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"HTTP content review failed for {base_url}.",
                error=str(exc),
            )

        note = self._generate_note(
            state=state,
            task=task,
            asset_id=asset_id,
            base_url=base_url,
            probe_context=bundle.parsed.output_context,
            fallback_notes=bundle.parsed.notes,
        )
        finding = self._build_finding(
            task=task,
            asset_id=asset_id,
            base_url=base_url,
            note=note,
        )

        output_context: dict[str, Any] = {
            **bundle.parsed.output_context,
            "manual_checks": note.manual_checks,
            "attack_surface": note.attack_surface,
            "interesting_endpoints": note.interesting_endpoints,
            "potential_flags": note.potential_flags,
        }
        new_tasks = [
            build_flag_validation_task(candidate, source="web_content")
            for candidate in note.potential_flags
        ]
        if bundle.parsed.output_context.get("forms"):
            new_tasks.append(
                build_web_form_probe_task(
                    asset_id=asset_id,
                    page_url=base_url,
                    forms=list(bundle.parsed.output_context.get("forms") or []),
                )
            )
        if note.interesting_endpoints:
            new_tasks.append(
                build_http_path_probe_task(
                    asset_id=asset_id,
                    base_url=base_url,
                    paths=note.interesting_endpoints,
                )
            )

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=f"Web content review completed for {base_url}.",
            output_context=output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=[finding, *bundle.parsed.finding_updates],
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=bundle.parsed.notes + [f"{self.name} reviewed page content for {base_url}."],
        )

    def _generate_note(
        self,
        *,
        state: GlobalState,
        task: Task,
        asset_id: str,
        base_url: str,
        probe_context: dict[str, Any],
        fallback_notes: list[str],
    ) -> WebContentNote:
        if self.llm_client is not None:
            try:
                return self.llm_client.generate_json(
                    system_prompt=(
                        "You analyze authorized web application content. "
                        "Return only JSON matching the WebContentNote schema. "
                        "Summarize attack surface from links, forms, and content. "
                        "Do not produce exploit steps or payloads."
                    ),
                    user_prompt=(
                        f"Objective: {state.objective}\n"
                        f"Task ID: {task.task_id}\n"
                        f"Asset ID: {asset_id}\n"
                        f"Base URL: {base_url}\n"
                        f"HTML title: {probe_context.get('title', '')}\n"
                        f"Interesting links: {probe_context.get('interesting_links', [])}\n"
                        f"Forms: {probe_context.get('forms', [])}\n"
                        f"Keywords: {probe_context.get('keywords', [])}\n"
                        f"Potential flags: {probe_context.get('potential_flags', [])}\n"
                        "Generate a concise content-review note."
                    ),
                    schema=WebContentNote,
                )
            except (LLMClientError, ValidationError) as exc:
                fallback_notes.append(
                    f"LLM content review unavailable ({type(exc).__name__}: {str(exc)[:200]}); using heuristic fallback."
                )

        return self._derive_note_from_probe(base_url=base_url, probe_context=probe_context)

    def _derive_note_from_probe(
        self,
        *,
        base_url: str,
        probe_context: dict[str, Any],
    ) -> WebContentNote:
        interesting_links: list[str] = probe_context.get("interesting_links", [])
        forms: list[dict[str, Any]] = probe_context.get("forms", [])
        keywords: list[str] = probe_context.get("keywords", [])
        potential_flags: list[str] = probe_context.get("potential_flags", [])

        attack_surface: list[str] = []
        if forms:
            attack_surface.append(f"Detected {len(forms)} HTML form(s)")
        if any("upload" in keyword for keyword in keywords):
            attack_surface.append("Upload-related content discovered")
        if any("admin" in keyword or "debug" in keyword for keyword in keywords):
            attack_surface.append("Administrative or debug content is exposed")
        if any("login" in keyword for keyword in keywords):
            attack_surface.append("Authentication surface discovered")

        manual_checks = [f"Manually inspect the rendered content at {base_url}."]
        if forms:
            manual_checks.append("Review form parameters and server-side validation.")
        if interesting_links:
            manual_checks.append("Inspect interesting links for hidden functionality and unauthenticated access.")
        if potential_flags:
            manual_checks.append("Validate any flag-like tokens recovered from the page body.")

        summary = (
            f"Content review for {base_url}: "
            f"{len(forms)} form(s), {len(interesting_links)} interesting endpoint(s), "
            f"{len(potential_flags)} flag candidate(s)."
        )
        return WebContentNote(
            summary=summary,
            attack_surface=attack_surface,
            interesting_endpoints=interesting_links,
            manual_checks=manual_checks,
            potential_flags=potential_flags,
        )

    def _build_finding(
        self,
        *,
        task: Task,
        asset_id: str,
        base_url: str,
        note: WebContentNote,
    ) -> Finding:
        severity = Severity.HIGH if note.potential_flags else (
            Severity.MEDIUM if note.attack_surface or note.interesting_endpoints else Severity.INFO
        )
        return Finding(
            finding_id=f"finding-{asset_id}-content-review",
            title="Web content review completed",
            severity=severity,
            description=note.summary,
            asset_refs=[asset_id],
            evidence_refs=[base_url, *note.potential_flags],
            metadata={
                "source_task_id": task.task_id,
                "mode": "llm-assisted" if self.llm_client is not None else "heuristic",
                "attack_surface": note.attack_surface,
                "interesting_endpoints": note.interesting_endpoints,
                "manual_checks": note.manual_checks,
                "potential_flags": note.potential_flags,
            },
        )
