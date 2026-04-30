"""PCAP review worker - inspect bundled packet captures."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.artifact._simple_review import run_simple_review
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport


class PcapReviewAgent(WorkerAgent):
    """Inspect bundled packet captures for hosts, URLs, credentials."""

    name = "pcap-review-agent"
    supported_task_types = ("artifact.pcap_review", "artifact.deep_review")
    required_context_keys = ("pcap_files",)
    routing_summary = "Review bundled .pcap/.pcapng artifacts for cleartext credentials, URLs, and exfiltrated content."
    preferred_challenge_categories = ("forensics", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type == "artifact.pcap_review":
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind == "pcap"
        return False

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return run_simple_review(
            self, task, state,
            tool_name="pcap_review",
            evidence_label="pcap review",
            input_field="pcap_files",
            processed_field="inspected_pcaps",
            max_files_default=6,
            timeout_default=120,
            summary_suffix="reviewed packet capture artifacts",
            role_addition="Look for credentials, hostnames, URLs, and exfiltrated content in packet streams.",
        )
