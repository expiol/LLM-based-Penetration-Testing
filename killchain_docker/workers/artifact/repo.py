"""Repo review worker - inspect embedded git repositories."""

from __future__ import annotations

from killchain_docker.workers.artifact._simple_review import run_simple_review
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.state import GlobalState, Task, WorkerReport
from killchain_docker.tools import ToolCapability


class RepoReviewAgent(WorkerAgent):
    """Inspect bundled git repositories for history-leaked secrets."""

    name = "repo-review-agent"
    supported_task_types = ("artifact.repo_review", "artifact.deep_review")
    required_context_keys = ("repo_paths",)
    routing_summary = "Inspect bundled git repositories for interesting commit history, secrets, and flag-like tokens."
    preferred_challenge_categories = ("forensics", "web", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type == "artifact.repo_review":
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind in {"repo", "git"}
        return False

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return run_simple_review(
            self, task, state,
            capability=ToolCapability.ARTIFACT_REPO,
            evidence_label="repository review",
            input_field="repo_paths",
            processed_field="inspected_repos",
            max_files_default=4,
            timeout_default=120,
            summary_suffix="reviewed embedded repositories",
            role_addition="Inspect commit history for reverted secrets and challenge breadcrumbs.",
        )
