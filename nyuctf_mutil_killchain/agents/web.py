"""Web assessment worker — HTTP metadata collection and LLM-assisted review."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError

from nyuctf_mutil_killchain.agents.base import WorkerAgent, build_web_content_task
from nyuctf_mutil_killchain.llm import LLMClientError
from nyuctf_mutil_killchain.state import Finding, GlobalState, Severity, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


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
    supported_task_types = ("web.review_surface",)

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
            )

        evidence_updates = []
        asset_updates = []
        finding_updates = []
        execution_notes: list[str] = []
        output_context: dict[str, Any] = {"reviewed_asset": asset_id}
        probe_context: dict[str, Any] = {}

        if self.execution_plane is not None:
            request = ToolExecutionRequest(
                tool_name="local_http_metadata",
                parser_name="jsonl_signals",
                timeout_s=task.input_context.get("timeout_s", 15),
                metadata={"asset_id": asset_id, "base_url": base_url},
            )
            try:
                bundle = self.execution_plane.execute(task.task_id, request)
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
            execution_notes.extend(bundle.parsed.notes)
            probe_context = bundle.parsed.output_context
            output_context.update(probe_context)

        note = self._generate_note(
            task=task,
            state=state,
            asset_id=asset_id,
            base_url=base_url,
            probe_context=probe_context,
            fallback_notes=execution_notes,
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
            evidence_updates=evidence_updates,
            new_tasks=[build_web_content_task(asset_id, base_url)],
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
            "mode": "llm-assisted" if self.llm_client is not None else "heuristic",
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
        fallback_notes: list[str] | None = None,
    ) -> WebReviewNote:
        if self.llm_client is not None:
            try:
                return self.llm_client.generate_json(
                    system_prompt=(
                        "You are a web security assessment analyst. "
                        "Return only JSON matching the WebReviewNote schema. "
                        "Generate specific, evidence-based risk hypotheses and actionable manual checks. "
                        "Do not generate exploit code, payloads, or attack instructions."
                    ),
                    user_prompt=(
                        f"Objective: {state.objective}\n"
                        f"Asset ID: {asset_id}\n"
                        f"Base URL: {base_url}\n"
                        f"HTTP Status: {probe_context.get('http_status', 'unknown')}\n"
                        f"Server: {probe_context.get('server', 'unknown')}\n"
                        f"Powered-By: {probe_context.get('powered_by', 'unknown')}\n"
                        f"Security Issues Found: {probe_context.get('security_issues', [])}\n"
                        f"Task ID: {task.task_id}\n"
                        "Generate a concise, evidence-driven web assessment note."
                    ),
                    schema=WebReviewNote,
                )
            except (LLMClientError, ValidationError) as exc:
                if fallback_notes is not None:
                    fallback_notes.append(
                        f"LLM web assessment unavailable ({type(exc).__name__}: {str(exc)[:200]}); using heuristic fallback."
                    )
                return self._derive_note_from_probe(
                    asset_id=asset_id, base_url=base_url, probe_context=probe_context
                )

        return self._derive_note_from_probe(asset_id=asset_id, base_url=base_url, probe_context=probe_context)

    def _derive_note_from_probe(
        self,
        *,
        asset_id: str,
        base_url: str,
        probe_context: dict[str, Any],
    ) -> WebReviewNote:
        """Build a risk-grounded review note from real HTTP probe data."""
        security_issues: list[str] = probe_context.get("security_issues", [])
        http_status = probe_context.get("http_status")
        server = probe_context.get("server", "")
        powered_by = probe_context.get("powered_by", "")

        risk_hypotheses: list[str] = []
        manual_checks: list[str] = []

        # Derive hypotheses from real header findings
        for issue in security_issues:
            if "Content-Security-Policy" in issue:
                risk_hypotheses.append(
                    "Missing CSP allows cross-site scripting (XSS) via unsafe inline scripts or eval."
                )
            elif "X-Frame-Options" in issue:
                risk_hypotheses.append(
                    "Missing X-Frame-Options permits clickjacking attacks against authenticated sessions."
                )
            elif "Strict-Transport-Security" in issue:
                risk_hypotheses.append(
                    "Missing HSTS allows SSL-stripping attacks on HTTPS endpoints."
                )
            elif "CORS" in issue:
                risk_hypotheses.append(
                    "Permissive CORS policy may allow cross-origin credential theft."
                )
            elif "HttpOnly" in issue:
                risk_hypotheses.append(
                    "Session cookie without HttpOnly is accessible via JavaScript — XSS cookie theft risk."
                )
            elif "Secure" in issue:
                risk_hypotheses.append(
                    "Session cookie without Secure flag may be transmitted over plain HTTP."
                )

        # Generic hypotheses based on server technology disclosures
        if server:
            risk_hypotheses.append(
                f"Server banner discloses '{server}'; check for known CVEs for this version."
            )
        if powered_by:
            risk_hypotheses.append(
                f"X-Powered-By reveals '{powered_by}'; version-specific vulnerabilities may exist."
            )

        if not risk_hypotheses:
            risk_hypotheses.append(
                "Input validation weaknesses may exist across form fields and URL parameters."
            )

        # Derive manual checks from probe data
        manual_checks.append(f"Confirm all HTTP endpoints at {base_url} are intentionally exposed.")
        if security_issues:
            manual_checks.append(f"Remediate {len(security_issues)} security header issue(s): " + "; ".join(security_issues[:3]))
        manual_checks.append("Inspect authentication and session management flows.")
        manual_checks.append("Test all input fields for injection vulnerabilities (SQLi, XSS, SSRF).")
        if http_status and http_status >= 400:
            manual_checks.append(f"Investigate HTTP {http_status} response — may indicate misconfiguration.")

        http_status_str = f" (HTTP {http_status})" if http_status else ""
        summary = (
            f"Web assessment for {base_url}{http_status_str}. "
            f"{len(security_issues)} security header issue(s) detected. "
            + (f"Server: {server}. " if server else "")
            + (f"Powered-By: {powered_by}. " if powered_by else "")
        ).strip()
        if not summary:
            summary = f"Web assessment note for {asset_id} at {base_url}. Manual verification required."

        return WebReviewNote(
            summary=summary,
            risk_hypotheses=risk_hypotheses,
            manual_checks=manual_checks,
        )
