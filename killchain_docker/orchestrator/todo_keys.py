"""Todo dedupe and structural key policy."""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.orchestrator.todo_context_paths import context_path
from killchain_docker.orchestrator.todo_family import family_for
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoItem

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo


def default_key(todo: "PlannedTodo | TodoItem") -> str:
    context = todo.context or {}
    if not context:
        return f"todo:{todo.phase}:{todo.goal[:80]}"
    family = str(context.get("family") or family_for(todo.goal, context))
    important: list[str] = [str(todo.phase), family]
    for key in (
        "scope",
        "files_root",
        "asset_id",
        "base_url",
        "hostname",
        "candidate_flag",
        "novelty_key",
        "finding_id",
        "vulnerability_id",
        "credential_id",
        "session_id",
        "hypothesis_id",
        "evidence_id",
    ):
        value = context.get(key)
        if value:
            important.append(str(value))
    for key in (
        "challenge_files",
        "source_files",
        "binary_files",
        "archive_files",
        "database_files",
        "pcap_files",
        "repo_paths",
        "paths",
        "seed_terms",
        "finding_ids",
        "vulnerability_ids",
        "credential_ids",
        "session_ids",
        "hypothesis_ids",
        "evidence_ids",
    ):
        value = context.get(key)
        if isinstance(value, list) and value:
            important.append(",".join((str(item) for item in value[:8])))
    return "todo:" + ":".join(important)


def structural_key(todo: "PlannedTodo | TodoItem") -> str | None:
    context = todo.context or {}
    capability = str(
        DispatchIntent.from_context(context).required_capability or ""
    ).strip()
    path = context_path(context)
    if capability == "disk.extract" and path:
        return f"bootstrap:disk-extract:{path}"
    if capability in {"office.inspect", "png.inspect"} and path:
        return f"bootstrap:artifact-followup:{path}"
    if (
        capability == "artifact.triage"
        and path
        and ("/.autopentest_artifacts/" in path)
    ):
        return f"bootstrap:artifact-followup:{path}"
    return None
