"""Prompt-facing projections for shared run-state models.

Prompt bounds are part of the interface between durable state and LLM callers.
Keeping these profiles together makes state-shape changes local and keeps
planner, router, and worker prompts from drifting independently.
"""

from __future__ import annotations

from typing import Any

from killchain_docker.prompt_bounds import bounded_value, trim_text
from killchain_docker.state import ExecutionRecord, RunState, TodoItem


def planner_todo(todo: TodoItem) -> dict[str, Any]:
    return {
        "todo_id": todo.todo_id,
        "goal": trim_text(todo.goal, width=360),
        "phase": todo.phase,
        "status": todo.status,
        "priority": todo.priority,
        "context": bounded_value(todo.context, width=360, list_limit=8, dict_limit=14),
        "result_summary": trim_text(todo.result_summary, width=300),
        "error": trim_text(todo.error, width=220),
    }


def router_todo(todo: TodoItem) -> dict[str, object]:
    return {
        "todo_id": todo.todo_id,
        "goal": trim_text(todo.goal, width=360),
        "phase": todo.phase,
        "context": bounded_value(todo.context, width=360, list_limit=8, dict_limit=14),
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
        "context": bounded_value(task.context, width=420, list_limit=8, dict_limit=14),
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


def working_memory(state: RunState, *, limit: int = 20, width: int = 360) -> dict[str, str]:
    return {
        str(key): trim_text(value, width=width)
        for key, value in list(state.working_memory.items())[-limit:]
    }
