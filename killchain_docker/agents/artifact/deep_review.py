"""Deep-review worker - dispatches by ``analysis_kind`` to the right reviewer.

This is a thin shim that lets the planner schedule a single
``artifact.deep_review`` task with ``analysis_kind`` (binary/archive/sqlite/
pcap/repo).  The agent looks at ``analysis_kind`` and delegates to the
appropriate concrete worker.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.artifact.archive import ArchiveTriageAgent
from nyuctf_mutil_killchain.agents.artifact.binary import BinaryTriageAgent
from nyuctf_mutil_killchain.agents.artifact.pcap import PcapReviewAgent
from nyuctf_mutil_killchain.agents.artifact.repo import RepoReviewAgent
from nyuctf_mutil_killchain.agents.artifact.sqlite import SqliteReviewAgent
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClient
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ExecutionPlane


_KIND_TO_FIELD = {
    "binary": "binary_files",
    "archive": "archive_files",
    "sqlite": "database_files",
    "pcap": "pcap_files",
    "repo": "repo_paths",
}


class DeepReviewAgent(WorkerAgent):
    """Route ``artifact.deep_review`` to the matching kind-specific worker."""

    name = "deep-review-agent"
    supported_task_types = ("artifact.deep_review",)
    required_context_keys = ("analysis_kind",)
    routing_summary = (
        "Multiplex artifact.deep_review by analysis_kind to the correct worker "
        "(binary, archive, sqlite, pcap, repo)."
    )
    preferred_challenge_categories = ("misc", "forensics", "rev", "crypto", "web", "pwn")

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
    ) -> None:
        super().__init__(llm_client=llm_client, execution_plane=execution_plane)
        kwargs = {"llm_client": llm_client, "execution_plane": execution_plane}
        self._delegates: dict[str, WorkerAgent] = {
            "binary": BinaryTriageAgent(**kwargs),
            "archive": ArchiveTriageAgent(**kwargs),
            "sqlite": SqliteReviewAgent(**kwargs),
            "pcap": PcapReviewAgent(**kwargs),
            "repo": RepoReviewAgent(**kwargs),
        }

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        allowed, reason = super().can_route_task(task, state)
        if not allowed:
            return allowed, reason

        kind = str(task.input_context.get("analysis_kind") or "").lower()
        if kind not in _KIND_TO_FIELD:
            return False, f"deep_review missing supported analysis_kind (got {kind!r})"
        field = _KIND_TO_FIELD[kind]
        if not task.input_context.get(field):
            return False, f"deep_review {kind!r} missing {field!r} context"
        return True, None

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        kind = str(task.input_context.get("analysis_kind") or "").lower()
        delegate = self._delegates.get(kind)
        if delegate is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"Unknown analysis_kind {kind!r} for artifact.deep_review.",
                error=f"analysis_kind must be one of {sorted(self._delegates)}",
                retryable=False,
            )

        # Adapt input_context: deep_review carries the file list under the
        # canonical field name; the delegate worker expects the same field, so
        # no transformation is needed.  Just dispatch.
        report = delegate.run(task, state)
        report.worker_name = self.name
        return report
