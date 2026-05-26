"""Logging helpers for CLI entrypoints and runtime event streams."""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import traceback
from collections.abc import Iterable
from pathlib import Path
from typing import Any


DEFAULT_LOG_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s "
    "[pid=%(process)d thread=%(threadName)s thread_id=%(thread)d]: %(message)s"
)
_RESERVED_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
}


def _json_default(value: Any) -> str:
    return str(value)


def _is_safe_extra_key(key: Any) -> bool:
    return (
        isinstance(key, str)
        and key not in _RESERVED_RECORD_KEYS
        and not key.startswith("_")
    )


def _extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if not _is_safe_extra_key(key):
            continue
        fields[key] = json_sanitize(value)
    return fields


def safe_extra(fields: dict[str, Any] | None) -> dict[str, Any]:
    """Return logging ``extra`` fields that cannot overwrite LogRecord keys."""

    if not fields:
        return {}
    return {
        key: json_sanitize(value)
        for key, value in fields.items()
        if _is_safe_extra_key(key)
    }


class ContextFormatter(logging.Formatter):
    """Text formatter that keeps ``extra=`` context visible."""

    converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        fields = _extra_fields(record)
        if not fields:
            return message
        context = json.dumps(
            fields, ensure_ascii=True, sort_keys=True, default=_json_default
        )
        return f"{message} context={context}"


class JsonFormatter(logging.Formatter):
    """JSON-lines formatter for machine-readable process logs."""

    converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "pid": record.process,
            "thread_id": record.thread,
            "thread_name": record.threadName,
            "message": record.getMessage(),
        }
        fields = _extra_fields(record)
        if fields:
            payload["context"] = fields
        if record.exc_info:
            payload["traceback"] = "".join(
                traceback.format_exception(*record.exc_info)
            ).rstrip()
        return json.dumps(
            payload, ensure_ascii=True, sort_keys=True, default=_json_default
        )


def configure_logging(*, debug: bool = False, quiet: bool = False) -> None:
    """Configure process-wide standard logging once."""

    level_name = os.environ.get("AUTOPENTEST_LOG_LEVEL")
    level = logging.DEBUG if debug else logging.INFO
    if level_name:
        level = getattr(logging, level_name.strip().upper(), level)
    if quiet:
        level = logging.WARNING

    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        if (os.environ.get("AUTOPENTEST_LOG_JSON") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(ContextFormatter(DEFAULT_LOG_FORMAT))
        root.addHandler(handler)
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def json_dumps(payload: Any, *, indent: int | None = 2, sort_keys: bool = False) -> str:
    return json.dumps(
        json_sanitize(payload),
        indent=indent,
        ensure_ascii=True,
        sort_keys=sort_keys,
        default=_json_default,
    )


def json_sanitize(payload: Any) -> Any:
    """Return a JSON-compatible copy using the same fallback as log writers."""

    return _sanitize_json_value(payload, set())


def _sanitize_json_value(value: Any, seen: set[int]) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        marker = id(value)
        if marker in seen:
            return "[circular]"
        seen.add(marker)
        try:
            return {
                str(key): _sanitize_json_value(item, seen)
                for key, item in value.items()
            }
        finally:
            seen.remove(marker)
    if isinstance(value, (list, tuple, set)):
        marker = id(value)
        if marker in seen:
            return "[circular]"
        seen.add(marker)
        try:
            return [_sanitize_json_value(item, seen) for item in value]
        finally:
            seen.remove(marker)
    return _json_default(value)


def atomic_tmp_path(path: str | Path) -> Path:
    target = Path(path)
    suffix = f"{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp"
    return target.with_name(f".{target.name}.{suffix}")


def write_text_file(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = atomic_tmp_path(target)
    try:
        tmp_path.write_text(text, encoding="utf-8")
        tmp_path.replace(target)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def write_json_file(path: str | Path, payload: Any) -> None:
    write_text_file(path, json_dumps(payload) + "\n")


def write_jsonl_file(path: str | Path, rows: Iterable[Any]) -> None:
    content = "".join(
        json_dumps(row, indent=None, sort_keys=True) + "\n" for row in rows
    )
    write_text_file(path, content)


def write_stdout(text: str) -> None:
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def write_json_stdout(payload: Any) -> None:
    write_stdout(json_dumps(payload))
