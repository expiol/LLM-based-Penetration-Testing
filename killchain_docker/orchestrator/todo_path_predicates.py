"""Todo context path predicates."""

from __future__ import annotations

from killchain_docker.orchestrator.todo_context_paths import context_path


def has_context_path(context: dict[str, object]) -> bool:
    return bool(context_path(context))
