"""Normalized batch Run Artifact readers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from killchain_docker.batch.monitor import STATUS_SUFFIX, relative_path


@dataclass(frozen=True)
class BatchResultReaders:
    """Adapters used to read raw batch result artifacts."""

    read_json: Callable[[str | Path | None], dict[str, Any] | None]
    token_usage: Callable[[Any], dict[str, int]]
    state_metrics: Callable[[dict[str, Any] | None], dict[str, Any]]
    rag_payload: Callable[[dict[str, Any] | None, dict[str, Any] | None], dict[str, Any] | None]
    failure_buckets: Callable[[dict[str, Any], dict[str, Any]], list[str]]


def build_challenge_entry(
    result: dict[str, Any],
    *,
    logdir: Path,
    readers: BatchResultReaders,
) -> dict[str, Any]:
    """Return the normalized summary/monitor entry for one challenge result."""

    log_payload = _result_log(result, readers)
    status_payload = _result_status_payload(result, log_payload, logdir, readers)
    summary = _result_summary(result, log_payload)
    metadata = _result_challenge_metadata(result, log_payload)
    state_metrics = _result_state_metrics(result, log_payload, readers)
    token_usage = _result_token_usage(result, log_payload, readers)
    artifacts = _result_artifacts(result, log_payload)
    rag = _result_rag(result, log_payload, readers)
    failure_buckets = readers.failure_buckets(log_payload, result)
    return {
        "challenge": result["challenge"],
        "monitor_challenge": result.get("monitor_challenge"),
        "run_id": result.get("run_id") or summary.get("run_id") or state_metrics.get("run_id"),
        "solved": result.get("solved", False),
        "status": result.get("status", "unknown"),
        "skip_reason": result.get("skip_reason") or log_payload.get("skip_reason"),
        "runtime_sec": result.get("runtime_sec"),
        "rag_mode": result.get("rag_mode") or (log_payload.get("args") or {}).get("rag_mode"),
        "category": metadata.get("category"),
        "files_count": len(metadata.get("files") or []),
        "has_server": bool(metadata.get("server_name") and metadata.get("port")),
        "server_type": metadata.get("server_type"),
        "authorized_scope_count": len(result.get("authorized_scope") or log_payload.get("authorized_scope") or []),
        "max_cycles": result.get("max_cycles") or log_payload.get("effective_max_cycles"),
        "token_usage": token_usage,
        "state_metrics": state_metrics,
        "artifacts": artifacts,
        "rag": rag,
        "threads": _result_threads(result, log_payload, status_payload),
        "runtime_error": _result_runtime_error(result, log_payload, summary, status_payload),
        "logfile": result.get("logfile"),
        "status_file": _result_status_file(result, log_payload, logdir),
        "error_type": result.get("error", {}).get("type") if result.get("error") else None,
        "failure_buckets": failure_buckets,
    }


def _result_log(result: dict[str, Any], readers: BatchResultReaders) -> dict[str, Any]:
    return readers.read_json(result.get("logfile")) or {}


def _result_summary(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("summary")
    if isinstance(summary, dict):
        return summary
    summary = log_payload.get("summary")
    return summary if isinstance(summary, dict) else {}


def _result_state_metrics(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    readers: BatchResultReaders,
) -> dict[str, Any]:
    metrics = result.get("state_metrics")
    if isinstance(metrics, dict) and metrics:
        return metrics
    metrics = log_payload.get("state_metrics")
    if isinstance(metrics, dict) and metrics:
        return metrics
    state_payload = log_payload.get("state")
    return readers.state_metrics(state_payload if isinstance(state_payload, dict) else None)


def _result_token_usage(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    readers: BatchResultReaders,
) -> dict[str, int]:
    if isinstance(result.get("token_usage"), dict):
        return readers.token_usage(result.get("token_usage"))
    if isinstance(log_payload.get("token_usage"), dict):
        return readers.token_usage(log_payload.get("token_usage"))
    summary = _result_summary(result, log_payload)
    return readers.token_usage(summary.get("token_usage"))


def _result_challenge_metadata(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
    meta = result.get("challenge_metadata")
    if isinstance(meta, dict) and meta:
        return meta
    meta = log_payload.get("challenge_metadata")
    return meta if isinstance(meta, dict) else {}


def _result_artifacts(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any] | None:
    artifacts = result.get("artifacts")
    if isinstance(artifacts, dict):
        return artifacts
    artifacts = log_payload.get("artifacts")
    return artifacts if isinstance(artifacts, dict) else None


def _result_rag(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    readers: BatchResultReaders,
) -> dict[str, Any] | None:
    rag = result.get("rag")
    if isinstance(rag, dict):
        return rag
    rag = log_payload.get("rag")
    if isinstance(rag, dict):
        return rag
    summary = _result_summary(result, log_payload)
    state_payload = log_payload.get("state")
    return readers.rag_payload(summary, state_payload if isinstance(state_payload, dict) else None)


def _result_status_file(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    logdir: Path,
) -> str | None:
    status_file = result.get("status_file") or log_payload.get("status_file")
    if status_file:
        return relative_path(Path(status_file), logdir)
    challenge_name = result.get("challenge")
    if not challenge_name:
        return None
    return f"{challenge_name}{STATUS_SUFFIX}"


def _result_status_payload(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    logdir: Path,
    readers: BatchResultReaders,
) -> dict[str, Any]:
    status_file = result.get("status_file") or log_payload.get("status_file")
    if status_file:
        path = Path(str(status_file))
        if not path.is_absolute():
            path = logdir / path
        return readers.read_json(path) or {}
    challenge_name = result.get("challenge")
    if not challenge_name:
        return {}
    return readers.read_json(logdir / f"{challenge_name}{STATUS_SUFFIX}") or {}


def _result_threads(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    status_payload: dict[str, Any],
) -> dict[str, Any] | None:
    for source in (result, log_payload, status_payload):
        threads = source.get("threads") if isinstance(source, dict) else None
        if isinstance(threads, dict) and threads:
            return threads
    return None


def _result_runtime_error(
    result: dict[str, Any],
    log_payload: dict[str, Any],
    summary: dict[str, Any],
    status_payload: dict[str, Any],
) -> dict[str, Any] | None:
    for source in (result, log_payload, summary, status_payload):
        runtime_error = source.get("runtime_error") if isinstance(source, dict) else None
        if isinstance(runtime_error, dict):
            return runtime_error
    return None
