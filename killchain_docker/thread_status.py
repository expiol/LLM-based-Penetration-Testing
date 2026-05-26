"""Helpers for publishing compact per-thread runtime status."""

from __future__ import annotations

import re
from typing import Any


TEXT_LIMIT = 220
CURRENT_TODO_STATUSES = {
    "pending",
    "running",
    "partial",
    "failed",
    "blocked",
    "interrupted",
}


def compact_status_text(value: object, *, limit: int = TEXT_LIMIT) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"


def thread_info(thread_id: object, thread_name: object) -> dict[str, object]:
    return {"id": thread_id, "name": thread_name}


def build_thread_registry(
    *,
    challenge: str | None,
    stage: str,
    status: str,
    pid: int,
    observed: dict[str, Any] | None = None,
    status_writer: dict[str, Any] | None = None,
    latest_event: dict[str, Any] | None = None,
    current_todo: dict[str, Any] | None = None,
    runtime_error: dict[str, Any] | None = None,
    message: object | None = None,
    extra_threads: dict[str, dict[str, Any]] | None = None,
    recent_events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return a role-aware thread registry for status and monitor payloads."""

    entries: dict[str, dict[str, Any]] = {}

    def add(role: str, info: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(info, dict):
            return None
        key = _thread_key(info.get("id"), info.get("name"))
        if key is None:
            return None
        entry = entries.setdefault(
            key,
            {
                "id": info.get("id"),
                "name": info.get("name"),
                "pid": pid,
                "challenge": challenge,
                "stage": stage,
                "status": status,
                "roles": [],
            },
        )
        if role not in entry["roles"]:
            entry["roles"].append(role)
        return entry

    observed_entry = add("observed", observed)
    writer_entry = add("status_writer", status_writer)
    event_entry = add("latest_event", _event_thread(latest_event))
    for event in recent_events or []:
        source_entry = add("event_source", _event_thread(event))
        _attach_latest_event(source_entry, event)
        _attach_event_work(source_entry, event)
    for role, info in sorted((extra_threads or {}).items()):
        add(role, info)

    _attach_current_todo(observed_entry or event_entry, current_todo)
    _attach_latest_event(event_entry or observed_entry, latest_event)
    _attach_runtime_error(observed_entry or event_entry or writer_entry, runtime_error)
    if message:
        target = observed_entry or event_entry or writer_entry
        if target is not None:
            target["message"] = compact_status_text(message)

    return sorted(
        entries.values(),
        key=lambda item: (str(item.get("name") or ""), str(item.get("id") or "")),
    )


def _thread_key(thread_id: object, thread_name: object) -> str | None:
    if thread_id is not None:
        return f"id:{thread_id}"
    if thread_name:
        return f"name:{thread_name}"
    return None


def _event_thread(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None
    return {"id": event.get("thread_id"), "name": event.get("thread_name")}


def _attach_current_todo(
    entry: dict[str, Any] | None, todo: dict[str, Any] | None
) -> None:
    if entry is None or not isinstance(todo, dict):
        return
    if str(todo.get("status") or "") not in CURRENT_TODO_STATUSES:
        return
    entry["current_todo"] = {
        key: compact_status_text(todo.get(key)) if key == "goal" else todo.get(key)
        for key in ("todo_id", "phase", "status", "worker", "attempts", "goal")
        if todo.get(key) is not None
    }


def _attach_latest_event(
    entry: dict[str, Any] | None, event: dict[str, Any] | None
) -> None:
    if entry is None or not isinstance(event, dict):
        return
    entry["latest_event"] = {
        key: compact_status_text(event.get(key)) if key == "message" else event.get(key)
        for key in ("sequence", "timestamp", "level", "event_type", "message")
        if event.get(key) is not None
    }


def _attach_event_work(entry: dict[str, Any] | None, event: dict[str, Any]) -> None:
    if entry is None:
        return
    context = event.get("context")
    if not isinstance(context, dict) or not context.get("todo_id"):
        return
    if str(context.get("todo_status") or "") not in CURRENT_TODO_STATUSES:
        entry.pop("current_todo", None)
        return
    _attach_current_todo(
        entry,
        {
            "todo_id": context.get("todo_id"),
            "phase": context.get("todo_phase"),
            "status": context.get("todo_status"),
            "worker": context.get("worker"),
        },
    )
    if context.get("worker"):
        entry["worker"] = compact_status_text(context.get("worker"))
    if context.get("cycle") is not None:
        entry["cycle"] = context.get("cycle")


def _attach_runtime_error(
    entry: dict[str, Any] | None, error: dict[str, Any] | None
) -> None:
    if entry is None or not isinstance(error, dict):
        return
    entry["error"] = {
        key: compact_status_text(error.get(key))
        for key in ("type", "message")
        if error.get(key)
    }
