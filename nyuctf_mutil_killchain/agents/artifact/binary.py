"""Binary triage worker - inspect bundled binary artifacts."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.artifact._simple_review import run_simple_review
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport


class BinaryTriageAgent(WorkerAgent):
    """Run strings/file/objdump-style probes on bundled binaries."""

    name = "binary-triage-agent"
    supported_task_types = ("artifact.binary_triage", "artifact.deep_review")
    required_context_keys = ("binary_files",)
    routing_summary = (
        "Inspect bundled binary artifacts for strings, headers, command paths, "
        "and obvious flag candidates."
    )
    preferred_challenge_categories = ("rev", "pwn", "crypto", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type == "artifact.binary_triage":
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind == "binary"
        return False

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return run_simple_review(
            self, task, state,
            tool_name="binary_triage",
            evidence_label="binary triage",
            input_field="binary_files",
            processed_field="inspected_binaries",
            max_files_default=6,
            timeout_default=120,
            summary_suffix="inspected bundled binaries",
            role_addition=(
                "Pay special attention to interesting strings, URLs, and command paths in the binary."
            ),
        )
