"""Prompt-facing projections for shared run-state models.

Prompt bounds are part of the interface between durable state and LLM callers.
Keeping these profiles together makes state-shape changes local and keeps
planner, router, and worker prompts from drifting independently.
"""

from __future__ import annotations
import posixpath
from typing import Any
from killchain_docker.prompt_bounds import bounded_value, trim_text
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.domain import Artifact, ExecutionRecord
from killchain_docker.state.memory_projection import RunMemoryProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem


def dispatch_intent(context: dict[str, Any]) -> dict[str, Any]:
    payload = DispatchIntent.from_context(context).model_dump(
        mode="json", exclude_defaults=True
    )
    payload.pop("completion_contract", None)
    payload.pop("repair_policy_id", None)
    return payload


def context_projection(
    context: dict[str, Any], *, width: int, list_limit: int, dict_limit: int
) -> Any:
    payload = bounded_value(
        context, width=width, list_limit=list_limit, dict_limit=dict_limit
    )
    if isinstance(payload, dict):
        raw_intent = payload.get("dispatch_intent")
        if isinstance(raw_intent, dict):
            raw_intent.pop("completion_contract", None)
            raw_intent.pop("repair_policy_id", None)
    return payload


def planner_todo(todo: TodoItem) -> dict[str, Any]:
    return {
        "todo_id": todo.todo_id,
        "goal": trim_text(todo.goal, width=360),
        "phase": todo.phase,
        "status": todo.status,
        "priority": todo.priority,
        "depends_on": bounded_value(todo.depends_on, width=180, list_limit=8),
        "context": context_projection(
            todo.context, width=360, list_limit=8, dict_limit=14
        ),
        "result_summary": trim_text(todo.result_summary, width=300),
        "error": trim_text(todo.error, width=220),
    }


def router_todo(todo: TodoItem) -> dict[str, object]:
    return {
        "todo_id": todo.todo_id,
        "goal": trim_text(todo.goal, width=360),
        "phase": todo.phase,
        "dispatch_intent": dispatch_intent(todo.context),
        "context": context_projection(
            todo.context, width=360, list_limit=8, dict_limit=14
        ),
        "priority": todo.priority,
        "depends_on": bounded_value(todo.depends_on, width=180, list_limit=8),
        "success_criteria": bounded_value(
            todo.success_criteria, width=240, list_limit=6
        ),
        "constraints": bounded_value(todo.constraints, width=240, list_limit=6),
        "attempts": todo.attempts,
        "error": trim_text(todo.error, width=220),
    }


def worker_todo(task: TodoItem) -> dict[str, Any]:
    return {
        "todo_id": task.todo_id,
        "goal": trim_text(task.goal, width=420),
        "phase": task.phase,
        "dispatch_intent": dispatch_intent(task.context),
        "context": context_projection(
            task.context, width=420, list_limit=8, dict_limit=14
        ),
        "priority": task.priority,
        "depends_on": bounded_value(task.depends_on, width=180, list_limit=8),
        "success_criteria": bounded_value(
            task.success_criteria, width=260, list_limit=6
        ),
        "constraints": bounded_value(task.constraints, width=260, list_limit=6),
        "status": task.status,
        "assigned_worker": task.assigned_worker,
        "result_summary": trim_text(task.result_summary, width=320),
        "dedupe_key": task.dedupe_key,
        "attempts": task.attempts,
        "max_attempts": task.max_attempts,
        "error": trim_text(task.error, width=220),
    }


def execution_record(record: ExecutionRecord) -> dict[str, Any]:
    return {
        "task_id": record.task_id,
        "worker_name": record.worker_name,
        "success": record.success,
        "summary": trim_text(record.summary, width=320),
        "error": trim_text(record.error, width=220),
    }


def artifact_record(artifact: Artifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "path": trim_text(artifact.path, width=420),
        "kind": artifact.kind,
        "source": artifact.source,
        "size": artifact.size,
        "digest": artifact.digest,
        "preview": trim_text(artifact.preview, width=260),
        "metadata": bounded_value(
            artifact.metadata, width=260, list_limit=6, dict_limit=10
        ),
    }


_WORKER_ARTIFACT_METADATA_KEYS = (
    "file_type",
    "mime_type",
    "content_signals",
    "role",
    "artifact_role",
    "origin",
    "relative_path",
    "source_file",
    "signature_count",
    "archive_member_score",
    "evidence_ids",
    "source_task_id",
    "source_capability",
    "interesting_strings",
)


def worker_artifact_record(artifact: Artifact) -> dict[str, Any]:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    compact_metadata = {
        key: metadata[key]
        for key in _WORKER_ARTIFACT_METADATA_KEYS
        if metadata.get(key) not in (None, "", [], {})
    }
    return {
        "artifact_id": artifact.artifact_id,
        "path": trim_text(artifact.path, width=360),
        "kind": artifact.kind,
        "source": artifact.source,
        "size": artifact.size,
        "digest": artifact.digest,
        "metadata": bounded_value(
            compact_metadata, width=180, list_limit=4, dict_limit=8
        ),
    }


def worker_artifacts(
    state: RunState, task: TodoItem | None = None, *, limit: int = 10
) -> list[dict[str, Any]]:
    """Return a compact, task-aware artifact view for worker tool prompts."""
    values = [
        projection.artifact for projection in ArtifactProjectionStore(state).all()
    ]
    if not values:
        return []
    if task is None:
        return [worker_artifact_record(artifact) for artifact in values[-limit:]]
    refs = _artifact_refs_from_task(task)
    scored: list[tuple[float, int, Artifact]] = []
    for index, artifact in enumerate(values):
        score = _artifact_relevance_score(artifact, refs)
        score += min(5.0, (index + 1) / max(1, len(values)) * 5.0)
        scored.append((score, index, artifact))
    positives = [item for item in scored if item[0] > 5.0]
    if positives:
        selected = sorted(positives, key=lambda item: (-item[0], -item[1]))[:limit]
    else:
        selected = scored[-limit:]
    selected = sorted(selected, key=lambda item: item[1])
    return [worker_artifact_record(artifact) for _score, _index, artifact in selected]


def run_memory(state: RunState, *, limit: int = 20, width: int = 360) -> dict[str, str]:
    return RunMemoryProjection(state).prompt_entries(limit=limit, width=width)


def _artifact_refs_from_task(task: TodoItem) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {
        "artifact_ids": set(),
        "evidence_ids": set(),
        "paths": set(),
        "dirs": set(),
        "names": set(),
    }
    _collect_refs(task.context or {}, refs)
    for text in (task.goal, *task.success_criteria, *task.constraints):
        _collect_path_like_text(str(text or ""), refs)
    return refs


def _collect_refs(value: Any, refs: dict[str, set[str]], *, key: str = "") -> None:
    key_norm = key.strip().lower()
    if isinstance(value, dict):
        if key_norm == "dispatch_intent":
            target_refs = value.get("target_refs")
            if isinstance(target_refs, dict):
                _collect_refs(target_refs, refs)
        for child_key, child in value.items():
            _collect_refs(child, refs, key=str(child_key))
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_refs(item, refs, key=key)
        return
    if value in (None, "", [], {}):
        return
    text = str(value).strip()
    if not text:
        return
    if key_norm in {"artifact_id", "artifact_ids"}:
        refs["artifact_ids"].add(text)
        return
    if key_norm in {"evidence_id", "evidence_ids", "prior_evidence_ids"}:
        refs["evidence_ids"].add(text)
        return
    if any((token in key_norm for token in ("path", "file", "dir", "root"))):
        _add_path_ref(
            text, refs, directory="dir" in key_norm or key_norm.endswith("root")
        )


def _collect_path_like_text(text: str, refs: dict[str, set[str]]) -> None:
    for token in text.replace(",", " ").split():
        cleaned = token.strip(" \t\r\n'\"`[](){}<>")
        if "/" in cleaned:
            _add_path_ref(cleaned, refs)


def _add_path_ref(
    text: str, refs: dict[str, set[str]], *, directory: bool = False
) -> None:
    cleaned = text.strip().strip("'\"")
    if not cleaned:
        return
    refs["paths"].add(cleaned)
    name = posixpath.basename(cleaned.rstrip("/"))
    if name and name not in {".", "/"}:
        refs["names"].add(name)
    if directory or cleaned.endswith("/"):
        refs["dirs"].add(cleaned.rstrip("/"))


def _artifact_relevance_score(artifact: Artifact, refs: dict[str, set[str]]) -> float:
    score = 0.0
    path = str(artifact.path or "").strip()
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    relative_path = str(metadata.get("relative_path") or "").strip().strip("/")
    artifact_name = posixpath.basename(path.rstrip("/"))
    relative_name = (
        posixpath.basename(relative_path.rstrip("/")) if relative_path else ""
    )
    if artifact.artifact_id in refs["artifact_ids"]:
        score += 100.0
    evidence_values = metadata.get("evidence_ids") or metadata.get("evidence_id") or []
    if not isinstance(evidence_values, list):
        evidence_values = [evidence_values]
    if refs["evidence_ids"].intersection(
        (str(item).strip() for item in evidence_values)
    ):
        score += 80.0
    if path and path in refs["paths"]:
        score += 90.0
    if relative_path and relative_path in refs["paths"]:
        score += 75.0
    if artifact_name and artifact_name in refs["names"]:
        score += 50.0
    if relative_name and relative_name in refs["names"]:
        score += 50.0
    for directory in refs["dirs"]:
        if directory and path.startswith(directory.rstrip("/") + "/"):
            score += 45.0
            break
    return score
