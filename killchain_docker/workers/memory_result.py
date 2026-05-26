"""Worker-result memory write policy boundary."""

from __future__ import annotations

from killchain_docker.state.memory_policy import MemoryWritePolicy
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.workers.task_intent import is_execution_closure_task


def trusted_memory_updates(
    todo: TodoItem, result: WorkerResult, updates: dict[str, str]
) -> dict[str, str]:
    return MemoryWritePolicy.trusted_worker_updates(
        todo, result, updates, require_candidate=is_execution_closure_task(todo)
    )


__all__ = ["trusted_memory_updates"]
