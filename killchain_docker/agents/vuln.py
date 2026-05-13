"""Vulnerability scanning worker — nuclei, nikto, or HTTP-based fallback."""

from __future__ import annotations

import json

from killchain_docker.agents.base import (
    WorkerAgent,
    build_exploit_hypothesis_task,
    build_flag_hunt_task,
    build_flag_validation_tasks,
    build_path_probe_tasks_for_assets,
)
from killchain_docker.agents.llm_guidance import StageAnalysisGuidance
from killchain_docker.state import GlobalState, Task, TaskErrorCode, WorkerReport
from killchain_docker.tools import ToolExecutionError, ToolExecutionRequest


class VulnScanAgent(WorkerAgent):
    """Runs a vulnerability scan against a target using the execution plane.

    Tool priority:
      1. nuclei — template-based CVE/misconfiguration scanner
      2. nikto  — web server vulnerability scanner
      3. HTTP basic checks — path probing for common exposures (fallback)

    The scanner is selected automatically by the embedded VULN_SCAN_SCRIPT
    based on which tools are installed on the host.
    """

    name = "vuln-scan-agent"
    supported_task_types = ("vuln.",)
    required_context_keys = ("asset_id", "target")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = task.input_context.get("asset_id")
        target = task.input_context.get("target")
        if not asset_id or not target:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing vuln scan context.",
                error="asset_id and target (or base_url/hostname) are required in task.input_context",
                retryable=False,
                error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
            )

        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Vuln scan requires an execution plane; none is configured.",
                error=(
                    "VulnScanAgent.execution_plane is None — "
                    "register the vuln_scan plugin before dispatching vuln.* tasks"
                ),
                retryable=False,
            )

        request = ToolExecutionRequest(
            tool_name="vuln_scan",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 180),
            metadata={
                "asset_id": asset_id,
                "target": target,
                "base_url": task.input_context.get("base_url"),
                "hostname": task.input_context.get("hostname"),
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"Vuln scan execution failed for {target}.",
                error=str(exc),
            )

        output_context = dict(bundle.parsed.output_context)
        vuln_count = output_context.get("vuln_count", len(bundle.parsed.finding_updates))
        scan_method = output_context.get("scan_method", "unknown")
        worker_notes = list(bundle.parsed.notes)
        llm_guidance = self.generate_structured_output(
            system_prompt=(
                "You analyze structured vulnerability-scan evidence from an authorized CTF workflow. "
                "Return only JSON matching the StageAnalysisGuidance schema. "
                "Only emit grounded_flag_candidates or interesting_paths that are directly supported by the findings."
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "asset_id": asset_id,
                    "target": target,
                    "summary": bundle.parsed.summary,
                    "output_context": output_context,
                    "findings": [finding.model_dump(mode="json") for finding in bundle.parsed.finding_updates],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=StageAnalysisGuidance,
        )
        new_tasks = []
        output_context["llm_summary"] = llm_guidance.summary
        output_context["manual_checks"] = llm_guidance.manual_checks
        new_tasks.extend(
            build_flag_validation_tasks(
                llm_guidance.grounded_flag_candidates, source="vuln_scan"
            )
        )
        new_tasks.extend(build_path_probe_tasks_for_assets(state, llm_guidance.interesting_paths, priority=75))
        if llm_guidance.should_schedule_exploit_hypothesis:
            new_tasks.append(
                build_exploit_hypothesis_task(
                    files_root="/home/ctfplayer/ctf_files",
                    focus_asset_ids=[asset_id],
                    seed_terms=[target, scan_method],
                    priority=79,
                )
            )
        if llm_guidance.should_schedule_flag_hunt and state.metadata.get("challenge", {}).get("files"):
            new_tasks.append(
                build_flag_hunt_task(
                    files_root="/home/ctfplayer/ctf_files",
                    seed_terms=[target, scan_method],
                    priority=92,
                )
            )

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=(
                f"Vuln scan via {scan_method} for {target}: "
                f"{vuln_count} finding(s). {bundle.parsed.summary}"
            ),
            output_context={
                "scanned_asset": asset_id,
                "scan_method": scan_method,
                "vuln_count": vuln_count,
                **output_context,
            },
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + [
                f"{self.name} completed {scan_method} scan for {target}: {vuln_count} finding(s)."
            ],
        )
