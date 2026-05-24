"""Prompt-facing projections for shared run-state models.

Prompt bounds are part of the interface between durable state and LLM callers.
Keeping these profiles together makes state-shape changes local and keeps
planner, router, and worker prompts from drifting independently.
"""

from __future__ import annotations

from typing import Any

from killchain_docker.prompt_bounds import bounded_value, trim_text
from killchain_docker.state import Artifact, DispatchIntent, ExecutionRecord, RunState, TodoItem


def dispatch_intent(context: dict[str, Any]) -> dict[str, Any]:
    payload = DispatchIntent.from_context(context).model_dump(
        mode="json",
        exclude_defaults=True,
    )
    payload.pop("completion_contract", None)
    payload.pop("repair_policy_id", None)
    return payload


def context_projection(
    context: dict[str, Any],
    *,
    width: int,
    list_limit: int,
    dict_limit: int,
) -> Any:
    payload = bounded_value(
        context,
        width=width,
        list_limit=list_limit,
        dict_limit=dict_limit,
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
        "context": context_projection(
            todo.context,
            width=360,
            list_limit=8,
            dict_limit=14,
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
            todo.context,
            width=360,
            list_limit=8,
            dict_limit=14,
        ),
        "priority": todo.priority,
        "success_criteria": bounded_value(todo.success_criteria, width=240, list_limit=6),
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
            task.context,
            width=420,
            list_limit=8,
            dict_limit=14,
        ),
        "priority": task.priority,
        "success_criteria": bounded_value(task.success_criteria, width=260, list_limit=6),
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
        "metadata": bounded_value(artifact.metadata, width=260, list_limit=6, dict_limit=10),
    }


def artifacts(state: RunState, *, limit: int = 30) -> list[dict[str, Any]]:
    return [
        artifact_record(artifact)
        for artifact in list(state.artifacts.values())[-limit:]
    ]


def working_memory(state: RunState, *, limit: int = 20, width: int = 360) -> dict[str, str]:
    return {
        str(key): trim_text(value, width=width)
        for key, value in list(state.working_memory.items())[-limit:]
    }
