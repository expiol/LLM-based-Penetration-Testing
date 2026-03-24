"""Vulnerability scanning worker — nuclei, nikto, or HTTP-based fallback."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


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

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        asset_id = task.input_context.get("asset_id")
        target = (
            task.input_context.get("target")
            or task.input_context.get("base_url")
            or task.input_context.get("hostname")
        )
        if not asset_id or not target:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Missing vuln scan context.",
                error="asset_id and target (or base_url/hostname) are required in task.input_context",
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

        vuln_count = bundle.parsed.output_context.get("vuln_count", len(bundle.parsed.finding_updates))
        scan_method = bundle.parsed.output_context.get("scan_method", "unknown")

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
                **bundle.parsed.output_context,
            },
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            notes=bundle.parsed.notes + [
                f"{self.name} completed {scan_method} scan for {target}: {vuln_count} finding(s)."
            ],
        )
