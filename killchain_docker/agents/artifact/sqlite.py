"""SQLite review worker - inspect bundled database files."""

from __future__ import annotations

from killchain_docker.agents.artifact._simple_review import run_simple_review
from killchain_docker.agents.base import WorkerAgent
from killchain_docker.state import GlobalState, Task, WorkerReport


class SqliteReviewAgent(WorkerAgent):
    """Inspect bundled SQLite databases for credentials and flag-like rows."""

    name = "sqlite-review-agent"
    supported_task_types = ("artifact.sqlite_review", "artifact.deep_review")
    required_context_keys = ("database_files",)
    routing_summary = "Inspect bundled SQLite databases for tables, credentials, and flag-like rows."
    preferred_challenge_categories = ("forensics", "web", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type == "artifact.sqlite_review":
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind in {"sqlite", "database"}
        return False

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return run_simple_review(
            self, task, state,
            tool_name="sqlite_review",
            evidence_label="sqlite review",
            input_field="database_files",
            processed_field="inspected_databases",
            max_files_default=6,
            timeout_default=120,
            summary_suffix="reviewed bundled SQLite databases",
            role_addition="Look for credentials, session tokens, and challenge state rows.",
        )
