"""Structural signal extraction for dispatch routing."""

from __future__ import annotations

import re

from killchain_docker.state.todos import TodoItem, TodoPhase

FILE_CONTEXT_KEYS = frozenset(
    {
        "artifact_id",
        "artifact_path",
        "binary_files",
        "challenge_files",
        "file_path",
        "files_root",
        "path",
        "paths",
        "source_files",
    }
)
WEB_CONTEXT_KEYS = frozenset(
    {
        "base_url",
        "endpoint_id",
        "endpoint_ids",
        "hostname",
        "port",
        "scope",
        "target_base_url",
        "url",
    }
)
FILE_TERMS = (
    "artifact",
    "binary",
    "bundle",
    "challenge file",
    "document",
    "file",
    "image",
    "pcap",
    "source",
    "zip",
)
SCOPE_TERMS = (
    "authorized scope",
    "host",
    "http",
    "map scope",
    "port",
    "service",
    "url",
)
ACTIVE_EXPLOIT_TERMS = (
    "authenticate",
    "connect",
    "execute",
    "exploit",
    "payload",
    "send",
)


def todo_has_file_signal(todo: TodoItem) -> bool:
    if todo_has_context_key(todo, FILE_CONTEXT_KEYS):
        return True
    text = todo_text(todo)
    return any((contains_term(text, term) for term in FILE_TERMS))


def todo_has_web_signal(todo: TodoItem) -> bool:
    if todo_has_context_key(todo, WEB_CONTEXT_KEYS):
        return True
    text = todo_text(todo)
    return any((contains_term(text, term) for term in SCOPE_TERMS))


def todo_has_context_key(todo: TodoItem, keys: frozenset[str]) -> bool:
    for key in keys:
        value = todo.context.get(key)
        if value not in (None, "", [], {}, ()):
            return True
    return False


def todo_text(todo: TodoItem) -> str:
    return " ".join(
        [todo.goal, " ".join(todo.success_criteria), " ".join(todo.constraints)]
    ).lower()


def contains_term(text: str, term: str) -> bool:
    pattern = "(?<![a-z0-9_])" + re.escape(term.lower()) + "(?![a-z0-9_])"
    return re.search(pattern, text) is not None


def active_exploit_closure(todo: TodoItem) -> bool:
    if todo.phase == TodoPhase.EXPLOIT:
        return True
    if todo_has_context_key(todo, WEB_CONTEXT_KEYS):
        text = todo_text(todo)
        return any((contains_term(text, term) for term in ACTIVE_EXPLOIT_TERMS))
    return False


__all__ = [
    "FILE_CONTEXT_KEYS",
    "WEB_CONTEXT_KEYS",
    "active_exploit_closure",
    "contains_term",
    "todo_has_context_key",
    "todo_has_file_signal",
    "todo_has_web_signal",
    "todo_text",
]
