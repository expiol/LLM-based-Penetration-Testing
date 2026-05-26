"""Structured runtime event recording."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from killchain_docker.logging_utils import (
    get_logger,
    json_sanitize,
    safe_extra,
)


LOGGER = get_logger(__name__)


class EventRecorder:
    """Collect structured runtime events and optionally stream them to logs."""

    MAX_MESSAGES = 2_000

    def __init__(self, *, quiet: bool = False) -> None:
        self.quiet = quiet
        self._messages: list[str] = []
        self._records: list[dict[str, Any]] = []
        self._context: dict[str, Any] = {}
        self._sequence = 0
        self._lock = threading.Lock()

    @property
    def messages(self) -> list[str]:
        with self._lock:
            return list(self._messages)

    @property
    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [json_sanitize(record) for record in self._records]

    def bind_context(self, **context: Any) -> None:
        with self._lock:
            self._context.update(
                {
                    key: json_sanitize(value)
                    for key, value in context.items()
                    if value is not None
                }
            )

    def emit(
        self,
        message: str,
        *,
        level: int = logging.INFO,
        event_type: str | None = None,
        **context: Any,
    ) -> None:
        record = self._record(
            message, level=level, event_type=event_type, context=context
        )
        if not self.quiet:
            LOGGER.log(level, message, extra=safe_extra(self._log_context(record)))

    def _record(
        self,
        message: str,
        *,
        level: int,
        event_type: str | None,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            self._sequence += 1
            merged_context = {
                **self._context,
                **{
                    key: json_sanitize(value)
                    for key, value in context.items()
                    if value is not None
                },
            }
            record = {
                "schema_version": 1,
                "sequence": self._sequence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": logging.getLevelName(level),
                "event_type": event_type or self._infer_event_type(message),
                "message": message,
                "pid": os.getpid(),
                "thread_id": threading.get_ident(),
                "thread_name": threading.current_thread().name,
                "context": merged_context,
            }
            self._messages.append(message)
            self._records.append(record)
            if len(self._messages) > self.MAX_MESSAGES:
                del self._messages[: len(self._messages) - self.MAX_MESSAGES]
            if len(self._records) > self.MAX_MESSAGES:
                del self._records[: len(self._records) - self.MAX_MESSAGES]
            return record

    @staticmethod
    def _infer_event_type(message: str) -> str:
        if message.startswith("[token usage]"):
            return "token_usage"
        if message.startswith("[interrupt]"):
            return "interrupt"
        if message.startswith("[persister]"):
            return "persistence"
        if "] plan:" in message:
            return "planner"
        if "] dispatch " in message:
            return "dispatch"
        if "] router summary:" in message:
            return "router_summary"
        if "] solved:" in message:
            return "solved"
        if "] transient LLM error" in message:
            return "llm_transient_error"
        if "LLM error" in message:
            return "llm_error"
        if "FAILED" in message or "UNHANDLED EXCEPTION" in message:
            return "failure"
        return "runtime"

    @staticmethod
    def _log_context(record: dict[str, Any]) -> dict[str, Any]:
        context = record.get("context")
        return {
            **(context if isinstance(context, dict) else {}),
            "event_type": record.get("event_type"),
            "event_sequence": record.get("sequence"),
            "event_pid": record.get("pid"),
            "event_thread_id": record.get("thread_id"),
            "event_thread_name": record.get("thread_name"),
        }
