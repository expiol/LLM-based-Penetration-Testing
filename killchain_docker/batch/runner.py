"""Batch execution: single-challenge runner and multi-challenge orchestration."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nyuctf.challenge import CTFChallenge

from killchain_docker.batch.dataset import (
    challenge_metadata,
    challenge_names_for_category,
    derive_authorized_scope,
    derive_objective,
    estimate_max_cycles,
    load_challenge,
    load_dataset,
    normalize_category,
    sample_challenge_names,
)
from killchain_docker.batch.docker import (
    compose_challenge_run_lock,
    start_challenge_with_retry,
)
from killchain_docker.controller import RunConfig, run_assessment
from killchain_docker.environment import CTFEnvironment
from killchain_docker.knowledge import oracle_context_status, public_rag_payload
from killchain_docker.logging_utils import configure_logging, get_logger, write_json_stdout
from killchain_docker.llm import LLMClientError, build_llm_client_from_env
from killchain_docker.thread_status import build_thread_registry, thread_info
from killchain_docker.batch.monitor import (
    STATUS_SUFFIX,
    relative_path,
    status_path_for_logfile,
    write_batch_monitor,
    write_batch_monitor_snapshot,
    write_json,
    write_run_status,
)
from killchain_docker.tools import build_execution_plane


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LOGGER = get_logger(__name__)

_SENSITIVE_KEYS = frozenset({"api_key", "authorization", "token", "secret", "password"})
_TOKEN_USAGE_KEYS = ("llm_calls", "prompt_tokens", "completion_tokens", "total_tokens")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LLM_GATEWAY_CONFIG = _PROJECT_ROOT / "configs" / "llm_gateway.json"
_BATCH_MONITOR_REFRESH_SEC = 3.0
_LEGACY_LLM_ENV_KEYS = (
    "AUTOPENTEST_LLM_MODE", "AUTOPENTEST_LLM_CONFIG_PATH", "AUTOPENTEST_LLM_PROVIDER",
    "AUTOPENTEST_LLM_BASE_URL", "AUTOPENTEST_LLM_MODEL", "AUTOPENTEST_LLM_API_KEY",
    "AUTOPENTEST_LLM_SCHEMA_MODELS", "AUTOPENTEST_LLM_TIMEOUT_S",
    "AUTOPENTEST_LLM_MAX_RETRIES", "AUTOPENTEST_LLM_MAX_COMPLETION_TOKENS",
)
_API_BALANCE_PATTERNS = [
    "insufficient_quota", "insufficient balance", "Arrearage", "billing",
    "exceeded your current quota", "account has been suspended", "rate_limit_exceeded",
    "You exceeded your current quota", "余额不足", "欠费", "账户余额",
]


def _mask_secret(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-4:]}"


def _sanitize_for_log(value: Any, *, key: str | None = None) -> Any:
    lowered_key = (key or "").lower()
    if lowered_key in _SENSITIVE_KEYS:
        return _mask_secret(value)
    if isinstance(value, dict):
        return {k: _sanitize_for_log(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_log(item, key=key) for item in value]
    return value


def _token_usage(value: Any) -> dict[str, int]:
    payload = value if isinstance(value, dict) else {}
    return {key: int(payload.get(key) or 0) for key in _TOKEN_USAGE_KEYS}


def _avg_token_usage(usages: list[dict[str, int]]) -> dict[str, float]:
    if not usages:
        return {key: 0.0 for key in _TOKEN_USAGE_KEYS}
    return {
        key: round(sum(int(item.get(key) or 0) for item in usages) / len(usages), 3)
        for key in _TOKEN_USAGE_KEYS
    }


def _sum_numeric_dicts(items: list[dict[str, int]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for item in items:
        for key, value in item.items():
            totals[key] = totals.get(key, 0) + int(value or 0)
    return totals


def _safe_read_json(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    candidate = Path(path)
    try:
        if not candidate.exists():
            return None
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("failed to read JSON payload", exc_info=True, extra={"path": str(candidate)})
        return None


def _utc_timestamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def _load_llm_experiment_config() -> dict[str, Any]:
    payload = _safe_read_json(_LLM_GATEWAY_CONFIG) or {}
    if not payload:
        return {"config_path": str(_LLM_GATEWAY_CONFIG), "available": False}
    sanitized = _sanitize_for_log(payload)
    sanitized["config_path"] = str(_LLM_GATEWAY_CONFIG)
    sanitized["available"] = True
    return sanitized


def _state_metrics(state_payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state_payload, dict):
        return {}

    todos = list(state_payload.get("todos") or [])
    todo_status_counts: dict[str, int] = {}
    worker_counts: dict[str, int] = {}
    for todo in todos:
        if not isinstance(todo, dict):
            continue
        status = str(todo.get("status") or "unknown")
        worker_name = str(todo.get("assigned_worker") or "unassigned")
        todo_status_counts[status] = todo_status_counts.get(status, 0) + 1
        worker_counts[worker_name] = worker_counts.get(worker_name, 0) + 1

    evidence = state_payload.get("evidence") or {}
    evidence_tool_counts: dict[str, int] = {}
    if isinstance(evidence, dict):
        for record in evidence.values():
            if not isinstance(record, dict):
                continue
            tool_name = str(record.get("tool_name") or "unknown")
            evidence_tool_counts[tool_name] = evidence_tool_counts.get(tool_name, 0) + 1

    return {
        "run_id": state_payload.get("run_id"),
        "run_status": state_payload.get("status"),
        "stop_reason": state_payload.get("stop_reason"),
        "todo_count": len(todos),
        "todo_status_counts": todo_status_counts,
        "worker_counts": worker_counts,
        "open_todo_count": sum(todo_status_counts.get(status, 0) for status in ("pending", "running")),
        "partial_todo_count": todo_status_counts.get("partial", 0),
        "interrupted_todo_count": todo_status_counts.get("interrupted", 0),
        "round_count": len(state_payload.get("rounds") or []),
        "evidence_count": len(evidence) if isinstance(evidence, dict) else 0,
        "evidence_tool_counts": evidence_tool_counts,
        "asset_count": len(state_payload.get("assets") or {}),
        "finding_count": len(state_payload.get("findings") or {}),
        "credential_count": len(state_payload.get("credentials") or {}),
        "execution_count": len(state_payload.get("execution_log") or []),
    }


def _is_api_balance_error(exc: Exception) -> bool:
    exc_str = str(exc).lower()
    exc_type = type(exc).__name__
    if "RateLimit" in exc_type or "AuthenticationError" in exc_type:
        return True
    return any(p.lower() in exc_str for p in _API_BALANCE_PATTERNS)


class _BatchMonitorHeartbeat:
    """Periodically refresh the JSON snapshot while runs are active."""

    def __init__(
        self,
        write_snapshot: Callable[[], None],
        *,
        interval_s: float = _BATCH_MONITOR_REFRESH_SEC,
    ) -> None:
        self.write_snapshot = write_snapshot
        self.interval_s = max(1.0, interval_s)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="batch-monitor-heartbeat",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self.interval_s + 1.0)

    def write_once(self) -> None:
        self.write_snapshot()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.write_once()
            except Exception:
                LOGGER.exception(
                    "batch monitor heartbeat failed",
                    extra={"interval_s": self.interval_s},
                )


class _MonitorRunState:
    """Thread-safe snapshot source shared by runner and monitor heartbeat."""

    def __init__(self, *, active_runs: list[dict[str, Any]] | None = None) -> None:
        self._lock = threading.RLock()
        self.results: list[dict[str, Any]] = []
        self.active_runs: list[dict[str, Any]] = list(active_runs or [])

    def results_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.results)

    def active_runs_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.active_runs)

    def append_result(self, result: dict[str, Any]) -> None:
        with self._lock:
            self.results.append(result)

    def set_active_runs(self, items: list[dict[str, Any]]) -> None:
        with self._lock:
            self.active_runs[:] = list(items)

    def add_active_run(self, item: dict[str, Any]) -> None:
        with self._lock:
            self.active_runs.append(item)

    def remove_active_run(self, key: str, value: str) -> None:
        with self._lock:
            self.active_runs[:] = [
                item
                for item in self.active_runs
                if item.get(key) != value
            ]


def _rag_payload(
    summary_payload: dict[str, Any] | None,
    state_payload: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if isinstance(summary_payload, dict) and isinstance(summary_payload.get("rag"), dict):
        return dict(summary_payload["rag"])
    metadata = state_payload.get("metadata") if isinstance(state_payload, dict) else None
    if isinstance(metadata, dict) and isinstance(metadata.get("rag"), dict):
        return dict(metadata["rag"])
    return None


def _is_unsolved_exhausted(log_payload: dict[str, Any], result: dict[str, Any]) -> bool:
    if result.get("solved") or log_payload.get("solved"):
        return False
    status_values = {
        str(value)
        for value in (
            result.get("status"),
            result.get("finish_reason"),
            log_payload.get("status"),
            log_payload.get("finish_reason"),
        )
        if value
    }
    if "unsolved_exhausted" in status_values:
        return True
    if "completed" not in status_values:
        return False
    metrics = result.get("state_metrics")
    if not isinstance(metrics, dict) or not metrics:
        metrics = log_payload.get("state_metrics")
    if not isinstance(metrics, dict) or not metrics:
        state_payload = log_payload.get("state")
        metrics = _state_metrics(state_payload if isinstance(state_payload, dict) else None)
    if metrics.get("open_todo_count") != 0:
        return False
    todo_counts = metrics.get("todo_status_counts") or {}
    return bool(todo_counts.get("completed") or metrics.get("todo_count"))


def _is_skipped_result(result: dict[str, Any]) -> bool:
    return str(result.get("status") or "") == "skipped"


def _is_interrupted_result(result: dict[str, Any]) -> bool:
    if result.get("solved"):
        return False
    return str(result.get("status") or "") == "interrupted" or bool(result.get("interrupted"))


def _is_failed_result(result: dict[str, Any]) -> bool:
    return not result.get("solved") and not _is_skipped_result(result) and not _is_interrupted_result(result)


def _is_evaluated_result(result: dict[str, Any]) -> bool:
    return not _is_skipped_result(result) and not _is_interrupted_result(result)


def _failure_buckets(log_payload: dict[str, Any], result: dict[str, Any]) -> list[str]:
    buckets: set[str] = set()
    if result.get("solved"):
        return []

    haystack_parts: list[str] = []
    for source in (result, log_payload):
        for key in ("status", "finish_reason", "traceback"):
            value = source.get(key) if isinstance(source, dict) else None
            if value:
                haystack_parts.append(str(value))
        error = source.get("error") if isinstance(source, dict) else None
        if isinstance(error, dict):
            haystack_parts.extend(str(value) for value in error.values() if value)
        elif error:
            haystack_parts.append(str(error))
        runtime_error = source.get("runtime_error") if isinstance(source, dict) else None
        if isinstance(runtime_error, dict):
            buckets.add("runtime_error")
            haystack_parts.extend(str(value) for value in runtime_error.values() if value)

    state_payload = log_payload.get("state") if isinstance(log_payload, dict) else None
    if isinstance(state_payload, dict):
        metadata = state_payload.get("metadata")
        runtime_error = metadata.get("runtime_error") if isinstance(metadata, dict) else None
        if isinstance(runtime_error, dict):
            buckets.add("runtime_error")
            haystack_parts.extend(str(value) for value in runtime_error.values() if value)
        last_llm_error = metadata.get("last_llm_error") if isinstance(metadata, dict) else None
        if isinstance(last_llm_error, dict):
            kind = str(last_llm_error.get("kind") or "").strip()
            if kind:
                buckets.add(f"llm_{kind}")
        haystack_parts.extend(str(note) for note in state_payload.get("orchestration_notes") or [])
        for todo in state_payload.get("todos") or []:
            if isinstance(todo, dict):
                haystack_parts.extend(str(todo.get(key) or "") for key in ("goal", "result_summary", "error"))
        for record in (state_payload.get("evidence") or {}).values():
            if isinstance(record, dict):
                haystack_parts.append(str(record.get("summary") or ""))
                extracted = record.get("extracted")
                if isinstance(extracted, dict):
                    output_context = extracted.get("output_context")
                    if isinstance(output_context, dict):
                        haystack_parts.extend(
                            str(output_context.get(key) or "")
                            for key in (
                                "failure_kind",
                                "failure_detail",
                                "result_quality",
                                "partial_reason",
                                "stderr",
                                "stdout",
                            )
                        )
        for record in state_payload.get("execution_log") or []:
            if isinstance(record, dict):
                haystack_parts.extend(str(record.get(key) or "") for key in ("summary", "error"))

    haystack = "\n".join(haystack_parts).lower()

    if (
        "missing required metadata.script_code" in haystack
        or "no script code provided" in haystack
        or "script execution skipped" in haystack
    ):
        buckets.add("script_missing_code")
    if "script execution failed (exit" in haystack:
        buckets.add("script_nonzero_exit")
    if (
        "script exceeded its execution or socket timeout" in haystack
        or "[timeout after" in haystack
        or "\ntimeout\n" in f"\n{haystack}\n"
    ):
        buckets.add("script_timeout")
    if (
        "scratch_space_exhausted" in haystack
        or "no space left on device" in haystack
        or "mktemp: failed to create directory" in haystack
    ):
        buckets.add("scratch_space_exhausted")
    if (
        "network_pipe_closed" in haystack
        or "connection_refused" in haystack
        or "connection_reset" in haystack
        or "connection refused" in haystack
        or "connection reset" in haystack
        or "broken pipe" in haystack
        or "remote endpoint refused" in haystack
        or "remote endpoint reset" in haystack
        or "only completed 0 rounds" in haystack
    ):
        buckets.add("network_interaction_failed")
    if (
        "package_install_blocked" in haystack
        or "package installation is not permitted" in haystack
        or "package-manager updates/installs" in haystack
    ):
        buckets.add("package_install_blocked")
    if (
        "scope_violation_blocked" in haystack
        or "outside authorized_scope" in haystack
        or "outside the challenge scope" in haystack
        or "ambient flag/secret search outside files_root" in haystack
    ):
        buckets.add("scope_violation_blocked")
    if (
        "missing required metadata.source_files" in haystack
        or "missing required metadata.pcap_files" in haystack
        or "missing required metadata.binary_files" in haystack
        or "missing required metadata.archive_files" in haystack
        or "missing required metadata.database_files" in haystack
        or "missing required metadata.repo_paths" in haystack
        or "no requested source files could be read" in haystack
        or "no requested pcap files could be read" in haystack
        or "no requested binary files could be read" in haystack
        or "completed for 0 file(s)" in haystack
        or "completed for 0 binary(ies)" in haystack
    ):
        buckets.add("tool_missing_target_files")
    if (
        "no requested source files could be read" in haystack
        or "missing required metadata.source_files" in haystack
        or "source review failed" in haystack
    ):
        buckets.add("source_target_unresolved")
    if "candidate mismatch" in haystack:
        buckets.add("candidate_mismatch")
    if "rejected flag candidate" in haystack or "escaped_byte_candidate" in haystack:
        buckets.add("candidate_rejected")
    if "empty_result" in haystack or "0 packet(s)" in haystack:
        buckets.add("empty_tool_result")
    if "family" in haystack and "cooldown" in haystack:
        buckets.add("stagnated")
    if "max_cycles_exhausted" in haystack:
        buckets.add("max_cycles_exhausted")
    if "router_no_assignments" in haystack:
        buckets.add("router_no_assignments")
    if "runtime_error" in haystack:
        buckets.add("runtime_error")
    if result.get("llm_error") or log_payload.get("llm_error") or "llm_error" in haystack:
        buckets.add("llm_error")
    if (
        "docker compose" in haystack
        or "ports are not available" in haystack
        or "bind: address already in use" in haystack
        or "port is already allocated" in haystack
        or "start_challenge_container" in haystack
    ):
        buckets.add("docker_start_error")

    status_values = {
        str(value)
        for value in (
            result.get("status"),
            result.get("finish_reason"),
            log_payload.get("status"),
            log_payload.get("finish_reason"),
        )
        if value
    }
    if "interrupted" in status_values or "keyboardinterrupt" in haystack:
        buckets.add("interrupted")

    state_metrics = result.get("state_metrics")
    if not isinstance(state_metrics, dict) or not state_metrics:
        state_metrics = log_payload.get("state_metrics")
    if not isinstance(state_metrics, dict) or not state_metrics:
        state_payload = log_payload.get("state")
        state_metrics = _state_metrics(state_payload if isinstance(state_payload, dict) else None)
    if isinstance(state_metrics, dict) and int(state_metrics.get("partial_todo_count") or 0) > 0:
        buckets.add("partial_no_candidate")
    if isinstance(state_metrics, dict) and state_metrics.get("stop_reason") == "router_no_assignments":
        buckets.add("router_no_assignments")
    if "partial_todos_unsolved" in haystack or "partial: no flag candidate" in haystack:
        buckets.add("partial_no_candidate")
    if _is_unsolved_exhausted(log_payload, result):
        buckets.add("unsolved_exhausted")

    return sorted(buckets)


def _active_run_entry(name: str, index: int) -> dict[str, Any]:
    thread_id = threading.get_ident()
    thread_name = threading.current_thread().name
    scheduler = thread_info(thread_id, thread_name)
    threads = {
        "scheduler": scheduler,
        "registry": build_thread_registry(
            challenge=name,
            stage="scheduled",
            status="active",
            pid=os.getpid(),
            message="challenge scheduled",
            extra_threads={"scheduler": scheduler},
        ),
    }
    return {
        "challenge": name,
        "status_file": f"{name}{STATUS_SUFFIX}",
        "index": index,
        "scheduler_pid": os.getpid(),
        "scheduler_thread_id": thread_id,
        "scheduler_thread_name": thread_name,
        "threads": threads,
        "stage": "scheduled",
        "status": "active",
        "message": "challenge scheduled",
    }


def _selected_challenge_names(dataset: Any, args: argparse.Namespace) -> tuple[list[str], str | None]:
    category_filter = normalize_category(getattr(args, "category", None))
    names = challenge_names_for_category(dataset, category_filter)
    requested = list(getattr(args, "challenges", None) or [])
    if not requested:
        return sample_challenge_names(dataset, args, names), category_filter

    allowed = set(names)
    selected: list[str] = []
    seen: set[str] = set()
    missing: list[str] = []
    for name in requested:
        challenge_name = str(name).strip()
        if not challenge_name or challenge_name in seen:
            continue
        if challenge_name not in allowed:
            missing.append(challenge_name)
            continue
        seen.add(challenge_name)
        selected.append(challenge_name)

    if missing:
        scope = f" in category '{category_filter}'" if category_filter else ""
        raise ValueError(f"Unknown challenge(s){scope}: {', '.join(missing)}")
    return sample_challenge_names(dataset, args, selected), category_filter


def _interrupted_batch_result(
    args: argparse.Namespace,
    name: str,
    exc: BaseException,
    message: str,
    *,
    monitor_challenge: str | None = None,
) -> dict[str, Any]:
    status_file = resolve_status_file(args, name)
    error = {"type": type(exc).__name__, "message": message}
    write_run_status(
        status_file,
        challenge=name,
        stage="batch_interrupted",
        status="interrupted",
        error=error,
        message=message,
    )
    result: dict[str, Any] = {
        "challenge": name,
        "solved": False,
        "status": "interrupted",
        "error": error,
        "api_error": False,
        "llm_error": False,
        "interrupted": True,
        "status_file": str(status_file),
    }
    if monitor_challenge:
        result["monitor_challenge"] = monitor_challenge
    return result


def _interrupted_active_results(
    args: argparse.Namespace,
    *,
    active_runs: list[dict[str, Any]],
    current_name: str | None,
    results: list[dict[str, Any]],
    exc: BaseException,
    message: str,
) -> list[dict[str, Any]]:
    completed = {str(result.get("challenge")) for result in results if result.get("challenge")}
    pending: list[tuple[str, str | None]] = []

    def add_pending(challenge: str, monitor_challenge: Any = None) -> None:
        if not challenge or challenge in completed:
            return
        if any(name == challenge for name, _monitor in pending):
            return
        monitor_name = str(monitor_challenge) if monitor_challenge else None
        pending.append((challenge, monitor_name))

    for item in active_runs:
        add_pending(str(item.get("challenge") or ""), item.get("monitor_challenge"))
    if current_name:
        add_pending(current_name)

    return [
        _interrupted_batch_result(
            args,
            name,
            exc,
            message,
            monitor_challenge=monitor_challenge,
        )
        for name, monitor_challenge in pending
    ]


def _worker_failure_result(args: argparse.Namespace, name: str, exc: Exception) -> dict[str, Any]:
    LOGGER.exception("challenge worker failed", extra={"challenge": name})
    status_file = resolve_status_file(args, name)
    write_run_status(
        status_file,
        challenge=name,
        stage="worker",
        status="worker_error",
        error={"type": type(exc).__name__, "message": str(exc)},
    )
    return {
        "challenge": name,
        "solved": False,
        "status": "worker_error",
        "error": {"type": type(exc).__name__, "message": str(exc)},
        "api_error": isinstance(exc, LLMClientError),
        "llm_error": isinstance(exc, LLMClientError),
        "traceback": traceback.format_exc(),
        "status_file": str(status_file),
    }


def _parallel_result(
    args: argparse.Namespace,
    future: concurrent.futures.Future[dict[str, Any]],
    name: str,
) -> dict[str, Any]:
    try:
        return future.result()
    except Exception as exc:
        return _worker_failure_result(args, name, exc)


def _log_challenge_result(name: str, result: dict[str, Any]) -> None:
    err = result.get("error")
    if _is_skipped_result(result):
        LOGGER.info("challenge skipped", extra={"challenge": name})
        return
    if _is_interrupted_result(result):
        LOGGER.warning("challenge interrupted", extra={"challenge": name})
        return
    if result.get("solved"):
        LOGGER.info("challenge solved", extra={"challenge": name})
        return
    if err:
        LOGGER.error(
            "challenge failed",
            extra={
                "challenge": name,
                "error_type": err.get("type", "?"),
                "error_message": str(err.get("message", ""))[:240],
            },
        )
        return
    LOGGER.error("challenge failed", extra={"challenge": name, "status": result.get("status")})


def _configure_llm_environment() -> None:
    import os
    for key in _LEGACY_LLM_ENV_KEYS:
        os.environ.pop(key, None)


def _subprocess_stream_text(chunk: str | bytes | None) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace").strip()
    return str(chunk).strip()


def _called_process_message(exc: subprocess.CalledProcessError) -> str:
    message = str(exc)
    err_out = _subprocess_stream_text(exc.stderr)
    std_out = _subprocess_stream_text(exc.stdout)
    if err_out:
        return f"{message}\nstderr:\n{err_out}"
    if std_out:
        return f"{message}\nstdout:\n{std_out}"
    return message


def write_log(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)


def _artifact_solved(
    summary_payload: dict[str, Any] | None,
    state_payload: dict[str, Any] | None,
    *,
    expected_flag: str,
) -> bool:
    """Return true only for explicit solve signals, never raw artifact text."""

    for payload in (summary_payload, state_payload):
        if not isinstance(payload, dict):
            continue
        if bool(payload.get("solved")):
            return True
        if expected_flag and payload.get("validated_flag") == expected_flag:
            return True
    return False


def resolve_experiment_logdir(args: argparse.Namespace) -> Path:
    logdir = Path(args.logdir).expanduser().resolve()
    suffix = "_".join(
        part for part in (
            getattr(args, "name", None),
            f"round{args.index}" if getattr(args, "index", None) else None,
        ) if part
    )
    logdir = logdir / suffix if suffix else logdir
    logdir.mkdir(parents=True, exist_ok=True)
    return logdir


def resolve_logfile(args: argparse.Namespace, challenge: CTFChallenge) -> Path:
    return resolve_experiment_logdir(args) / f"{challenge.canonical_name}.json"


def resolve_status_file(args: argparse.Namespace, challenge_name: str) -> Path:
    return resolve_experiment_logdir(args) / f"{challenge_name}{STATUS_SUFFIX}"


def resolve_output_root(args: argparse.Namespace, challenge: CTFChallenge, logfile: Path) -> Path:
    if args.output_root:
        return Path(args.output_root).expanduser().resolve()
    return logfile.parent / "artifacts" / challenge.canonical_name


def _oracle_preflight_skip_result(
    args: argparse.Namespace,
    challenge: CTFChallenge,
    *,
    logfile: Path,
    status_file: Path,
    metadata: dict[str, Any],
    authorized_scope: list[str],
    objective: str,
    effective_max_cycles: int,
    started_at: float,
) -> dict[str, Any] | None:
    if getattr(args, "rag_mode", None) != "oracle":
        return None

    rag_payload = oracle_context_status(metadata.get("canonical_name") or challenge.canonical_name)
    public_rag = public_rag_payload(rag_payload) or {}
    if public_rag.get("status") == "hit" and int(public_rag.get("hint_count") or 0) > 0:
        return None

    status = str(public_rag.get("status") or "unavailable")
    message = f"oracle RAG has no actionable solution sketch ({status})"
    runtime_sec = round(time.time() - started_at, 3)
    token_usage = _token_usage(None)
    result = {
        "challenge": challenge.canonical_name,
        "solved": False,
        "status": "skipped",
        "skip_reason": "rag_oracle_unavailable",
        "logfile": str(logfile),
        "status_file": str(status_file),
        "runtime_sec": runtime_sec,
        "rag_mode": "oracle",
        "run_id": None,
        "artifacts": None,
        "rag": public_rag,
        "challenge_metadata": metadata,
        "authorized_scope": authorized_scope,
        "max_cycles": effective_max_cycles,
        "token_usage": token_usage,
        "state_metrics": {},
        "error": None,
        "api_error": False,
        "llm_error": False,
        "interrupted": False,
    }
    write_log(
        logfile,
        {
            "args": _sanitize_for_log(vars(args)),
            "challenge": challenge.challenge_info,
            "challenge_metadata": metadata,
            "objective": objective,
            "authorized_scope": authorized_scope,
            "effective_max_cycles": effective_max_cycles,
            "success": False,
            "solved": False,
            "status": "skipped",
            "finish_reason": "skipped",
            "skip_reason": "rag_oracle_unavailable",
            "artifacts": None,
            "summary": None,
            "token_usage": token_usage,
            "rag": rag_payload,
            "state_metrics": {},
            "error": None,
            "llm_error": False,
            "start_time": started_at,
            "end_time": time.time(),
            "runtime_sec": runtime_sec,
            "status_file": str(status_file),
            "rag_mode": "oracle",
        },
    )
    write_run_status(
        status_file,
        challenge=challenge.canonical_name,
        stage="rag_preflight",
        status="skipped",
        solved=False,
        logfile=str(logfile),
        rag=public_rag,
        token_usage=token_usage,
        runtime_sec=runtime_sec,
        message=message,
    )
    LOGGER.warning(
        "oracle RAG context unavailable; skipping execution benchmark sample",
        extra={
            "challenge": challenge.canonical_name,
            "rag_status": status,
            "hint_count": int(public_rag.get("hint_count") or 0),
        },
    )
    return result


# ---------------------------------------------------------------------------
# Single challenge execution
# ---------------------------------------------------------------------------

def run_single_challenge(args: argparse.Namespace, challenge: CTFChallenge) -> dict[str, Any]:
    """Run a single challenge and return the result dict."""
    logfile = resolve_logfile(args, challenge)
    status_file = status_path_for_logfile(logfile)

    if logfile.exists() and args.skip_exist:
        LOGGER.info("skipping existing challenge log", extra={"challenge": challenge.canonical_name, "logfile": str(logfile)})
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="skipped",
            status="skipped",
            logfile=str(logfile),
        )
        return {
            "challenge": challenge.canonical_name, "status": "skipped",
            "solved": False, "api_error": False, "llm_error": False,
            "logfile": str(logfile), "status_file": str(status_file),
        }

    with compose_challenge_run_lock(challenge):
        return _run_single_challenge_inner(args, challenge, logfile)


def _effective_max_cycles(
    args: argparse.Namespace,
    challenge: CTFChallenge,
    authorized_scope: list[str],
) -> int:
    base_cycles = int(getattr(args, "max_cycles", 8) or 8)
    if not bool(getattr(args, "auto_max_cycles", False)):
        return base_cycles
    return estimate_max_cycles(challenge, authorized_scope, base_cycles=base_cycles)


def _llm_token_usage(llm_client: Any) -> dict[str, int]:
    ledger = getattr(llm_client, "token_ledger", None)
    if ledger is None:
        return _token_usage(None)
    to_dict = getattr(ledger, "to_dict", None)
    if not callable(to_dict):
        return _token_usage(None)
    return _token_usage(to_dict())


def _run_single_challenge_inner(
    args: argparse.Namespace, challenge: CTFChallenge, logfile: Path,
) -> dict[str, Any]:
    status_file = status_path_for_logfile(logfile)
    authorized_scope = args.scope or derive_authorized_scope(challenge)
    objective = args.objective or derive_objective(challenge, authorized_scope)
    output_root = resolve_output_root(args, challenge, logfile)
    metadata = challenge_metadata(challenge)
    effective_max_cycles = _effective_max_cycles(args, challenge, authorized_scope)

    config = RunConfig(
        objective=objective,
        authorized_scope=authorized_scope,
        output_root=str(output_root),
        max_cycles=effective_max_cycles,
        quiet=args.quiet,
        status_path=str(status_file),
        rag_mode=getattr(args, "rag_mode", None),
        metadata={"challenge": metadata},
    )

    started_at = time.time()
    preflight_skip = _oracle_preflight_skip_result(
        args,
        challenge,
        logfile=logfile,
        status_file=status_file,
        metadata=metadata,
        authorized_scope=authorized_scope,
        objective=objective,
        effective_max_cycles=effective_max_cycles,
        started_at=started_at,
    )
    if preflight_skip is not None:
        return preflight_skip

    environment = CTFEnvironment(challenge, args.container_image, args.container_network)
    artifacts = None
    error_payload = None
    traceback_text = None
    llm_client = None
    solved = False
    is_api_error = False
    is_llm_error = False
    interrupted = False

    try:
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="llm_preflight",
            status="starting",
            logfile=str(logfile),
            rag_mode=getattr(args, "rag_mode", None),
            message="building LLM client",
        )
        _configure_llm_environment()
        llm_client = build_llm_client_from_env(preflight=True)
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="container_start",
            status="starting",
            logfile=str(logfile),
            message="starting challenge container",
        )
        start_challenge_with_retry(challenge, debug=args.debug)
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="environment_setup",
            status="starting",
            logfile=str(logfile),
            message="setting up execution environment",
        )
        environment.setup()
        if not environment.container:
            raise RuntimeError("environment container did not start")

        execution_plane = build_execution_plane(
            argv_prefix=["docker", "exec", "-i", environment.container],
            python_executable="python3",
        )
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="assessment",
            status="running",
            logfile=str(logfile),
            message="orchestrator running",
        )
        artifacts = run_assessment(
            config, execution_plane=execution_plane,
            expected_flag=challenge.flag, llm_client=llm_client,
        )
    except (KeyboardInterrupt, SystemExit) as exc:
        recovered_artifacts = getattr(exc, "run_artifacts", None)
        if recovered_artifacts is not None:
            artifacts = recovered_artifacts
        interrupted = True
        error_payload = {"type": type(exc).__name__, "message": f"Run interrupted by {type(exc).__name__}"}
        LOGGER.warning(
            "single challenge run interrupted",
            exc_info=True,
            extra={"challenge": challenge.canonical_name, "logfile": str(logfile)},
        )
        traceback_text = traceback.format_exc() or error_payload["message"]
    except Exception as exc:
        recovered_artifacts = getattr(exc, "run_artifacts", None)
        if recovered_artifacts is not None:
            artifacts = recovered_artifacts
        message = _called_process_message(exc) if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        error_payload = {"type": type(exc).__name__, "message": message}
        if isinstance(exc, LLMClientError):
            error_payload.update({
                "kind": str(exc.kind),
                "transient": exc.transient,
                "schema_name": exc.schema_name,
                "model": exc.model,
                "attempts": exc.attempts,
            })
        traceback_text = traceback.format_exc() or f"{type(exc).__name__}: {exc}"
        is_llm_error = isinstance(exc, LLMClientError)
        is_api_error = is_llm_error or _is_api_balance_error(exc)
        LOGGER.exception(
            "single challenge run failed",
            extra={
                "challenge": challenge.canonical_name,
                "logfile": str(logfile),
                "error_type": type(exc).__name__,
                "llm_error": is_llm_error,
            },
        )
    finally:
        teardown_error: Exception | None = None
        write_run_status(
            status_file,
            challenge=challenge.canonical_name,
            stage="teardown",
            status="running",
            logfile=str(logfile),
            message="tearing down environment",
        )
        try:
            environment.teardown()
        except Exception as exc:
            teardown_error = exc
            LOGGER.warning(
                "environment teardown failed",
                exc_info=True,
                extra={"challenge": challenge.canonical_name},
            )
        try:
            challenge.stop_challenge_container()
        except Exception as exc:
            if teardown_error is None:
                teardown_error = exc
            LOGGER.warning(
                "challenge container stop failed",
                exc_info=True,
                extra={"challenge": challenge.canonical_name},
            )
        if teardown_error is not None and error_payload is None:
            message = (
                _called_process_message(teardown_error)
                if isinstance(teardown_error, subprocess.CalledProcessError)
                else str(teardown_error)
            )
            error_payload = {"type": type(teardown_error).__name__, "message": message}

    ended_at = time.time()
    summary_payload = None
    state_payload = None
    if artifacts is not None:
        summary_path = Path(artifacts.summary_path)
        if summary_path.exists():
            summary_payload = _safe_read_json(summary_path)
        state_path = Path(artifacts.state_path)
        if state_path.exists():
            state_payload = _safe_read_json(state_path)

    if artifacts is not None:
        solved = _artifact_solved(
            summary_payload,
            state_payload,
            expected_flag=challenge.flag,
        )

    state_metrics = _state_metrics(state_payload)
    artifact_status = artifacts.status if artifacts is not None else "failed"
    if interrupted:
        artifact_status = "interrupted"
    interrupted = interrupted or artifact_status == "interrupted"
    unsolved_exhausted = (
        not solved
        and artifact_status == "completed"
        and state_metrics.get("open_todo_count") == 0
        and bool(state_metrics.get("todo_count"))
    )
    finish_reason = "solved" if solved else (
        "interrupted" if interrupted else (
            "unsolved_exhausted" if unsolved_exhausted else artifact_status
        )
    )
    if summary_payload is not None:
        token_usage = _token_usage(summary_payload.get("token_usage"))
    else:
        token_usage = _llm_token_usage(llm_client)
    rag_payload = _rag_payload(summary_payload, state_payload)
    metadata = challenge_metadata(challenge)
    log_payload = {
        "args": _sanitize_for_log(vars(args)),
        "challenge": challenge.challenge_info,
        "challenge_metadata": metadata,
        "objective": objective,
        "authorized_scope": authorized_scope,
        "effective_max_cycles": effective_max_cycles,
        "success": solved, "solved": solved,
        "status": finish_reason,
        "finish_reason": finish_reason,
        "interrupted": interrupted,
        "artifacts": None if artifacts is None else artifacts.model_dump(mode="json"),
        "summary": summary_payload,
        "token_usage": token_usage,
        "rag": rag_payload,
        "state_metrics": state_metrics,
        "state": state_payload,
        "error": error_payload,
        "llm_error": is_llm_error,
        "traceback": traceback_text,
        "start_time": started_at, "end_time": ended_at,
        "runtime_sec": round(ended_at - started_at, 3),
        "status_file": str(status_file),
        "rag_mode": getattr(args, "rag_mode", None),
    }
    write_log(logfile, log_payload)
    write_run_status(
        status_file,
        challenge=challenge.canonical_name,
        stage="complete",
        status=finish_reason,
        solved=solved,
        run_id=None if artifacts is None else artifacts.run_id,
        logfile=str(logfile),
        artifacts=None if artifacts is None else artifacts.model_dump(mode="json"),
        state_metrics=state_metrics,
        rag=public_rag_payload(rag_payload),
        token_usage=token_usage,
        runtime_sec=round(ended_at - started_at, 3),
        error=error_payload,
        api_error=is_api_error,
        llm_error=is_llm_error,
        message=finish_reason,
    )

    return {
        "challenge": challenge.canonical_name,
        "solved": solved,
        "status": finish_reason,
        "logfile": str(logfile),
        "status_file": str(status_file),
        "runtime_sec": round(ended_at - started_at, 3),
        "rag_mode": getattr(args, "rag_mode", None),
        "run_id": None if artifacts is None else artifacts.run_id,
        "artifacts": None if artifacts is None else artifacts.model_dump(mode="json"),
        "rag": public_rag_payload(rag_payload),
        "challenge_metadata": metadata,
        "authorized_scope": authorized_scope,
        "max_cycles": effective_max_cycles,
        "token_usage": token_usage,
        "state_metrics": state_metrics,
        "error": error_payload,
        "api_error": is_api_error,
        "llm_error": is_llm_error,
        "interrupted": interrupted,
    }


# ---------------------------------------------------------------------------
# Batch execution
# ---------------------------------------------------------------------------

def run_all_challenges(args: argparse.Namespace) -> int:
    """Run every challenge in the split. Returns exit code."""
    configure_logging(
        debug=bool(getattr(args, "debug", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )
    dataset = load_dataset(args)
    try:
        all_names, category_filter = _selected_challenge_names(dataset, args)
    except ValueError as exc:
        LOGGER.error("invalid challenge selection", extra={"error": str(exc)})
        return 1
    logdir = resolve_experiment_logdir(args)

    if category_filter:
        LOGGER.info(
            "filtered challenges by category",
            extra={"category": category_filter, "challenge_count": len(all_names)},
        )
    if getattr(args, "challenges", None):
        LOGGER.info("selected explicit challenge subset", extra={"challenge_count": len(all_names)})

    total = len(all_names)
    if total == 0:
        LOGGER.error("no challenges found in the specified split/category")
        return 1

    LOGGER.info("batch run starting", extra={"total": total, "split": args.split})

    monitor_state = _MonitorRunState()
    results = monitor_state.results
    solved_count = 0
    failed_count = 0
    skipped_count = 0
    batch_start = time.time()
    batch_interrupted = False
    current_name: str | None = None

    workers = max(1, int(getattr(args, "parallel_workers", 1) or 1))
    monitor_path = write_batch_monitor(
        logdir=logdir,
        challenge_names=all_names,
        results=results,
        batch_start=batch_start,
    )
    LOGGER.info("batch monitor ready", extra={"monitor_path": str(monitor_path)})
    heartbeat = _BatchMonitorHeartbeat(
        lambda: write_batch_monitor_snapshot(
            logdir=logdir,
            challenge_names=all_names,
            results=monitor_state.results_snapshot(),
            batch_start=batch_start,
            active_runs=monitor_state.active_runs_snapshot(),
        )
    )
    heartbeat.start()
    try:
        if workers == 1:
            for idx, name in enumerate(all_names, 1):
                current_name = name
                monitor_state.set_active_runs([_active_run_entry(name, idx)])
                write_batch_monitor(
                    logdir=logdir,
                    challenge_names=all_names,
                    results=monitor_state.results_snapshot(),
                    batch_start=batch_start,
                    active_runs=monitor_state.active_runs_snapshot(),
                )
                LOGGER.info("challenge run starting", extra={"challenge": name, "index": idx, "total": total})

                try:
                    args.challenge = name
                    challenge = CTFChallenge(dataset.get(name), dataset.basedir)
                except Exception as exc:
                    LOGGER.exception("failed to load challenge", extra={"challenge": name})
                    status_file = resolve_status_file(args, name)
                    write_run_status(
                        status_file,
                        challenge=name,
                        stage="load_challenge",
                        status="load_error",
                        error={"type": type(exc).__name__, "message": str(exc)},
                    )
                    result = {
                        "challenge": name, "solved": False, "status": "load_error",
                        "error": {"type": type(exc).__name__, "message": str(exc)},
                        "api_error": False, "llm_error": False,
                        "status_file": str(status_file),
                    }
                    monitor_state.append_result(result)
                    monitor_state.set_active_runs([])
                    solved_count, failed_count, skipped_count = _update_result_counters(
                        result, solved_count, failed_count, skipped_count
                    )
                    _save_batch_progress(
                        args,
                        monitor_state.results_snapshot(),
                        batch_start,
                        challenge_names=all_names,
                    )
                    continue

                result = run_single_challenge(args, challenge)
                monitor_state.append_result(result)
                monitor_state.set_active_runs([])
                solved_count, failed_count, skipped_count = _update_result_counters(
                    result, solved_count, failed_count, skipped_count
                )
                _save_batch_progress(
                    args,
                    monitor_state.results_snapshot(),
                    batch_start,
                    challenge_names=all_names,
                )

                if result.get("api_error"):
                    LOGGER.error(
                        "LLM/API error detected; aborting batch run",
                        extra={"completed": idx, "total": total},
                    )
                    break
                if result.get("status") == "interrupted":
                    LOGGER.warning(
                        "run interrupted; stopping batch run",
                        extra={"completed": idx, "total": total},
                    )
                    break
        else:
            LOGGER.info("parallel mode enabled", extra={"workers": workers})
            base_args = vars(args).copy()
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                pending_names = iter(enumerate(all_names, 1))
                future_map: dict[concurrent.futures.Future[dict[str, Any]], str] = {}

                def submit_next() -> bool:
                    try:
                        challenge_index, challenge_name = next(pending_names)
                    except StopIteration:
                        return False
                    future = executor.submit(_run_named_challenge_worker, base_args, challenge_name)
                    future_map[future] = challenge_name
                    monitor_state.add_active_run(_active_run_entry(challenge_name, challenge_index))
                    return True

                for _ in range(min(workers, total)):
                    submit_next()

                write_batch_monitor(
                    logdir=logdir,
                    challenge_names=all_names,
                    results=monitor_state.results_snapshot(),
                    batch_start=batch_start,
                    active_runs=monitor_state.active_runs_snapshot(),
                )

                try:
                    stop_batch = False
                    while future_map and not stop_batch:
                        done, _pending = concurrent.futures.wait(
                            future_map,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )
                        for future in done:
                            name = future_map.pop(future)
                            current_name = name
                            result = _parallel_result(args, future, name)
                            monitor_state.append_result(result)
                            monitor_state.remove_active_run("challenge", name)
                            solved_count, failed_count, skipped_count = _update_result_counters(
                                result, solved_count, failed_count, skipped_count
                            )
                            _log_challenge_result(name, result)

                            if result.get("status") == "interrupted":
                                for pending in future_map:
                                    pending.cancel()
                                LOGGER.warning("run interrupted; stopping parallel batch")
                                monitor_state.set_active_runs([])
                                stop_batch = True
                            elif result.get("api_error"):
                                for pending in future_map:
                                    pending.cancel()
                                LOGGER.error("LLM/API error detected; stopping parallel batch")
                                monitor_state.set_active_runs([])
                                stop_batch = True
                            else:
                                submit_next()

                            _save_batch_progress(
                                args,
                                monitor_state.results_snapshot(),
                                batch_start,
                                challenge_names=all_names,
                                active_runs=monitor_state.active_runs_snapshot(),
                            )
                            if stop_batch:
                                break
                except (KeyboardInterrupt, SystemExit):
                    for pending in future_map:
                        pending.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
    except (KeyboardInterrupt, SystemExit) as exc:
        batch_interrupted = True
        code = getattr(exc, "code", None)
        message = f"Batch interrupted by {type(exc).__name__}"
        if code not in (None, ""):
            message += f" (code={code})"
        for result in _interrupted_active_results(
            args,
            active_runs=monitor_state.active_runs_snapshot(),
            current_name=current_name,
            results=monitor_state.results_snapshot(),
            exc=exc,
            message=message,
        ):
            monitor_state.append_result(result)
            solved_count, failed_count, skipped_count = _update_result_counters(
                result, solved_count, failed_count, skipped_count
            )
        monitor_state.set_active_runs([])
        LOGGER.warning(
            "batch interrupted; saving progress",
            exc_info=True,
            extra={"interrupt_reason": message},
        )
    finally:
        heartbeat.stop()

    batch_end = time.time()
    summary_path = _save_batch_progress(
        args,
        results,
        batch_start,
        finished=True,
        challenge_names=all_names,
    )
    solved_names = [r["challenge"] for r in results if r.get("solved")]
    failed_names = [r["challenge"] for r in results if _is_failed_result(r)]
    skipped_names = [r["challenge"] for r in results if _is_skipped_result(r)]
    interrupted_names = [r["challenge"] for r in results if _is_interrupted_result(r)]

    LOGGER.info(
        "batch complete",
        extra={
            "attempted": len(results),
            "total": total,
            "solved": solved_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "interrupted": len(interrupted_names),
            "runtime_sec": round(batch_end - batch_start, 3),
            "summary_path": str(summary_path),
            "monitor_path": str(logdir / "_batch_monitor.html"),
        },
    )
    if solved_names:
        for name in solved_names:
            LOGGER.info("solved challenge", extra={"challenge": name})
    if failed_names:
        for name in failed_names:
            LOGGER.info("failed challenge", extra={"challenge": name})
    if skipped_names:
        for name in skipped_names:
            LOGGER.info("skipped challenge", extra={"challenge": name})
    if interrupted_names:
        for name in interrupted_names:
            LOGGER.info("interrupted challenge", extra={"challenge": name})

    if batch_interrupted or interrupted_names:
        return 130
    return 0 if solved_count > 0 or failed_count == 0 else 1


def _save_batch_progress(
    args: argparse.Namespace,
    results: list[dict[str, Any]],
    batch_start: float,
    *,
    finished: bool = False,
    challenge_names: list[str] | None = None,
    active_runs: list[dict[str, Any]] | None = None,
) -> Path:
    """Persist a JSON summary of batch progress after each challenge."""
    logdir = resolve_experiment_logdir(args)
    summary_path = logdir / "_batch_summary.json"

    solved_list = [r for r in results if r.get("solved")]
    failed_list = [r for r in results if _is_failed_result(r)]
    skipped_list = [r for r in results if _is_skipped_result(r)]
    interrupted_list = [r for r in results if _is_interrupted_result(r)]

    def _result_log(result: dict[str, Any]) -> dict[str, Any]:
        return _safe_read_json(result.get("logfile")) or {}

    def _result_summary(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        summary = result.get("summary")
        if isinstance(summary, dict):
            return summary
        summary = log_payload.get("summary")
        return summary if isinstance(summary, dict) else {}

    def _result_state_metrics(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        metrics = result.get("state_metrics")
        if isinstance(metrics, dict) and metrics:
            return metrics
        metrics = log_payload.get("state_metrics")
        if isinstance(metrics, dict) and metrics:
            return metrics
        state_payload = log_payload.get("state")
        return _state_metrics(state_payload if isinstance(state_payload, dict) else None)

    def _result_token_usage(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, int]:
        if isinstance(result.get("token_usage"), dict):
            return _token_usage(result.get("token_usage"))
        if isinstance(log_payload.get("token_usage"), dict):
            return _token_usage(log_payload.get("token_usage"))
        summary = _result_summary(result, log_payload)
        return _token_usage(summary.get("token_usage"))

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

    def _result_rag(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any] | None:
        rag = result.get("rag")
        if isinstance(rag, dict):
            return rag
        rag = log_payload.get("rag")
        if isinstance(rag, dict):
            return rag
        summary = _result_summary(result, log_payload)
        state_payload = log_payload.get("state")
        return _rag_payload(summary, state_payload if isinstance(state_payload, dict) else None)

    def _result_status_file(result: dict[str, Any], log_payload: dict[str, Any]) -> str | None:
        status_file = result.get("status_file") or log_payload.get("status_file")
        if status_file:
            return relative_path(Path(status_file), logdir)
        challenge_name = result.get("challenge")
        if not challenge_name:
            return None
        return f"{challenge_name}{STATUS_SUFFIX}"

    def _result_status_payload(result: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        status_file = result.get("status_file") or log_payload.get("status_file")
        if status_file:
            path = Path(str(status_file))
            if not path.is_absolute():
                path = logdir / path
            return _safe_read_json(path) or {}
        challenge_name = result.get("challenge")
        if not challenge_name:
            return {}
        return _safe_read_json(logdir / f"{challenge_name}{STATUS_SUFFIX}") or {}

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

    def _challenge_entry(result: dict[str, Any]) -> dict[str, Any]:
        log_payload = _result_log(result)
        status_payload = _result_status_payload(result, log_payload)
        summary = _result_summary(result, log_payload)
        metadata = _result_challenge_metadata(result, log_payload)
        state_metrics = _result_state_metrics(result, log_payload)
        token_usage = _result_token_usage(result, log_payload)
        artifacts = _result_artifacts(result, log_payload)
        rag = _result_rag(result, log_payload)
        failure_buckets = _failure_buckets(log_payload, result)
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
            "status_file": _result_status_file(result, log_payload),
            "error_type": result.get("error", {}).get("type") if result.get("error") else None,
            "failure_buckets": failure_buckets,
        }

    details = [_challenge_entry(result) for result in results]
    evaluated_details = [entry for entry in details if _is_evaluated_result(entry)]
    token_usages = [entry["token_usage"] for entry in evaluated_details]
    total_token_usage = _sum_numeric_dicts(token_usages)
    solved_token_usages = [entry["token_usage"] for entry in details if entry.get("solved")]
    failed_token_usages = [
        entry["token_usage"]
        for entry in details
        if _is_failed_result(entry)
    ]
    runtime_values = [
        float(entry["runtime_sec"])
        for entry in details
        if isinstance(entry.get("runtime_sec"), (int, float))
    ]
    todo_counts = [int((entry.get("state_metrics") or {}).get("todo_count") or 0) for entry in details]
    open_todo_counts = [int((entry.get("state_metrics") or {}).get("open_todo_count") or 0) for entry in details]
    partial_todo_counts = [int((entry.get("state_metrics") or {}).get("partial_todo_count") or 0) for entry in details]
    interrupted_todo_counts = [
        int((entry.get("state_metrics") or {}).get("interrupted_todo_count") or 0)
        for entry in details
    ]
    worker_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("worker_counts") or {}
        for entry in details
    ])
    todo_status_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("todo_status_counts") or {}
        for entry in details
    ])
    evidence_tool_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("evidence_tool_counts") or {}
        for entry in details
    ])
    category_counts: dict[str, int] = {}
    failure_bucket_counts: dict[str, int] = {}
    for entry in details:
        category = str(entry.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
        for bucket in entry.get("failure_buckets") or []:
            failure_bucket_counts[str(bucket)] = failure_bucket_counts.get(str(bucket), 0) + 1

    total_attempted = len(results)
    evaluated_count = len(evaluated_details)
    success_rate = round(len(solved_list) / evaluated_count, 4) if evaluated_count else 0.0
    elapsed = round(time.time() - batch_start, 3)
    payload = {
        "schema_version": 2,
        "split": args.split,
        "category_filter": getattr(args, "category", None),
        "finished": finished,
        "started_at": _utc_timestamp(batch_start),
        "updated_at": _utc_timestamp(),
        "total_attempted": total_attempted,
        "evaluated_count": evaluated_count,
        "solved_count": len(solved_list),
        "failed_count": len(failed_list),
        "skipped_count": len(skipped_list),
        "interrupted_count": len(interrupted_list),
        "success_rate": success_rate,
        "elapsed_sec": elapsed,
        "experiment_config": {
            "name": getattr(args, "name", None),
            "index": getattr(args, "index", None),
            "dataset": getattr(args, "dataset", None),
            "split": args.split,
            "category_filter": getattr(args, "category", None),
            "challenge": getattr(args, "challenge", None),
            "run_all": bool(getattr(args, "run_all", False)),
            "max_cycles_arg": getattr(args, "max_cycles", None),
            "auto_max_cycles": bool(getattr(args, "auto_max_cycles", False)),
            "container_image": getattr(args, "container_image", None),
            "container_network": getattr(args, "container_network", None),
            "parallel_workers": int(getattr(args, "parallel_workers", 1) or 1),
            "replicas": int(getattr(args, "replicas", 1) or 1),
            "skip_exist": bool(getattr(args, "skip_exist", False)),
            "quiet": bool(getattr(args, "quiet", False)),
            "debug": bool(getattr(args, "debug", False)),
            "logdir": str(logdir),
            "output_root": getattr(args, "output_root", None),
            "objective_overridden": bool(getattr(args, "objective", None)),
            "scope_overridden": bool(getattr(args, "scope", None)),
            "rag_mode": getattr(args, "rag_mode", None),
            "llm_gateway": _load_llm_experiment_config(),
        },
        "paper_metrics": {
            "success_rate": success_rate,
            "attempted": evaluated_count,
            "total_attempted": total_attempted,
            "solved": len(solved_list),
            "failed": len(failed_list),
            "skipped": len(skipped_list),
            "interrupted": len(interrupted_list),
            "elapsed_sec": elapsed,
            "runtime_sec_total": round(sum(runtime_values), 3),
            "runtime_sec_mean": round(sum(runtime_values) / len(runtime_values), 3) if runtime_values else 0.0,
            "token_usage_total": total_token_usage,
            "token_usage_mean_per_attempt": _avg_token_usage(token_usages),
            "token_usage_mean_solved": _avg_token_usage(solved_token_usages),
            "token_usage_mean_failed": _avg_token_usage(failed_token_usages),
            "todo_count_total": sum(todo_counts),
            "todo_count_mean": round(sum(todo_counts) / len(todo_counts), 3) if todo_counts else 0.0,
            "open_todo_count_total": sum(open_todo_counts),
            "partial_todo_count_total": sum(partial_todo_counts),
            "interrupted_todo_count_total": sum(interrupted_todo_counts),
            "todo_status_totals": todo_status_totals,
            "worker_totals": worker_totals,
            "evidence_tool_totals": evidence_tool_totals,
            "category_counts": category_counts,
            "failure_bucket_counts": failure_bucket_counts,
        },
        "failure_buckets": failure_bucket_counts,
        "token_usage": {
            "total": total_token_usage,
            "mean_per_attempt": _avg_token_usage(token_usages),
            "mean_solved": _avg_token_usage(solved_token_usages),
            "mean_failed": _avg_token_usage(failed_token_usages),
        },
        "solved_challenges": [r["challenge"] for r in solved_list],
        "failed_challenges": [r["challenge"] for r in failed_list],
        "skipped_challenges": [r["challenge"] for r in skipped_list],
        "interrupted_challenges": [r["challenge"] for r in interrupted_list],
        "details": details,
    }
    write_log(summary_path, payload)
    write_batch_monitor(
        logdir=logdir,
        challenge_names=challenge_names or [str(result["challenge"]) for result in results],
        results=details,
        batch_start=batch_start,
        active_runs=active_runs,
        finished=finished,
    )
    if not finished:
        LOGGER.info("batch progress saved", extra={"summary_path": str(summary_path)})
    return summary_path


def _update_result_counters(
    result: dict[str, Any],
    solved_count: int,
    failed_count: int,
    skipped_count: int,
) -> tuple[int, int, int]:
    if _is_skipped_result(result):
        skipped_count += 1
    elif result.get("solved"):
        solved_count += 1
    elif _is_failed_result(result):
        failed_count += 1
    return solved_count, failed_count, skipped_count


def _run_named_challenge_worker(args_dict: dict[str, Any], challenge_name: str) -> dict[str, Any]:
    worker_args = argparse.Namespace(**args_dict)
    worker_args.challenge = challenge_name
    configure_logging(
        debug=bool(getattr(worker_args, "debug", False)),
        quiet=bool(getattr(worker_args, "quiet", False)),
    )
    try:
        challenge = load_challenge(worker_args)
    except Exception as exc:
        LOGGER.exception(
            "failed to load challenge in worker",
            extra={"challenge": challenge_name},
        )
        status_file = resolve_status_file(worker_args, challenge_name)
        write_run_status(
            status_file,
            challenge=challenge_name,
            stage="load_challenge",
            status="load_error",
            error={"type": type(exc).__name__, "message": str(exc)},
        )
        return {
            "challenge": challenge_name,
            "solved": False,
            "status": "load_error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "api_error": False,
            "llm_error": False,
            "status_file": str(status_file),
        }
    return run_single_challenge(worker_args, challenge)


def run_single_challenge_replicas(args: argparse.Namespace) -> int:
    configure_logging(
        debug=bool(getattr(args, "debug", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )
    replicas = max(1, int(getattr(args, "replicas", 1) or 1))
    if replicas == 1:
        challenge = load_challenge(args)
        logdir = resolve_experiment_logdir(args)
        batch_start = time.time()
        active_runs = [
            {
                "challenge": challenge.canonical_name,
                "status_file": f"{challenge.canonical_name}{STATUS_SUFFIX}",
            }
        ]
        write_batch_monitor(
            logdir=logdir,
            challenge_names=[challenge.canonical_name],
            results=[],
            batch_start=batch_start,
            active_runs=active_runs,
        )
        heartbeat = _BatchMonitorHeartbeat(
            lambda: write_batch_monitor_snapshot(
                logdir=logdir,
                challenge_names=[challenge.canonical_name],
                results=[],
                batch_start=batch_start,
                active_runs=list(active_runs),
            )
        )
        heartbeat.start()
        try:
            result = run_single_challenge(args, challenge)
        finally:
            heartbeat.stop()
        _save_batch_progress(
            args,
            [result],
            batch_start,
            finished=True,
            challenge_names=[challenge.canonical_name],
        )
        if result.get("status") == "interrupted":
            LOGGER.warning("run interrupted", extra={"logfile": result.get("logfile")})
            return 130
        if result.get("error"):
            error = result["error"]
            LOGGER.error(
                "run failed",
                extra={
                    "error_type": error["type"],
                    "error_message": error["message"],
                    "logfile": result.get("logfile"),
                },
            )
            return 1
        write_json_stdout(result)
        if result.get("solved") or result.get("status") == "skipped":
            return 0
        return 1

    workers = max(1, int(getattr(args, "parallel_workers", replicas) or replicas))
    workers = min(workers, replicas)
    LOGGER.info("launching isolated replicas", extra={"replicas": replicas, "workers": workers})

    base_args = vars(args).copy()
    run_label_prefix = str(int(time.time()))
    parent_logdir = resolve_experiment_logdir(args)
    batch_start = time.time()
    base_name = str(getattr(args, "name", None) or "replica")
    replica_names = [
        f"{getattr(args, 'challenge', 'challenge')}#replica-{idx}"
        for idx in range(1, replicas + 1)
    ]
    replica_status_base = Path() if getattr(args, "name", None) else Path(base_name)
    active_runs = [
        {
            "challenge": name,
            "monitor_challenge": name,
            "replica": idx,
            "status_file": str(
                parent_logdir
                / replica_status_base
                / f"rep{idx}_{run_label_prefix}"
                / f"{getattr(args, 'challenge', 'challenge')}{STATUS_SUFFIX}"
            ),
        }
        for idx, name in enumerate(replica_names, 1)
    ]
    replica_status_files = {
        str(item["monitor_challenge"]): item.get("status_file")
        for item in active_runs
    }
    write_batch_monitor(
        logdir=parent_logdir,
        challenge_names=replica_names,
        results=[],
        batch_start=batch_start,
        active_runs=active_runs,
    )
    monitor_state = _MonitorRunState(active_runs=active_runs)
    results = monitor_state.results

    heartbeat = _BatchMonitorHeartbeat(
        lambda: write_batch_monitor_snapshot(
            logdir=parent_logdir,
            challenge_names=replica_names,
            results=monitor_state.results_snapshot(),
            batch_start=batch_start,
            active_runs=monitor_state.active_runs_snapshot(),
        )
    )
    heartbeat.start()
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(_run_single_replica_worker, base_args, idx + 1, run_label_prefix): idx + 1
                for idx in range(replicas)
            }
            for future in concurrent.futures.as_completed(future_map):
                replica_idx = future_map[future]
                monitor_challenge = replica_names[replica_idx - 1]
                try:
                    result = future.result()
                except Exception as exc:
                    LOGGER.exception(
                        "replica worker failed",
                        extra={"challenge": args.challenge, "replica": replica_idx},
                    )
                    result = {
                        "challenge": args.challenge,
                        "replica": replica_idx,
                        "solved": False,
                        "status": "worker_error",
                        "error": {"type": type(exc).__name__, "message": str(exc)},
                        "api_error": isinstance(exc, LLMClientError),
                        "llm_error": isinstance(exc, LLMClientError),
                        "traceback": traceback.format_exc(),
                        "status_file": replica_status_files.get(monitor_challenge),
                    }
                result["monitor_challenge"] = monitor_challenge
                monitor_state.append_result(result)
                monitor_state.remove_active_run("monitor_challenge", monitor_challenge)
                marker = "SOLVED" if result.get("solved") else "FAILED"
                LOGGER.info(
                    "replica completed",
                    extra={
                        "replica": replica_idx,
                        "result": marker,
                        "status": result.get("status"),
                        "logfile": result.get("logfile"),
                    },
                )
                if result.get("api_error"):
                    for pending in future_map:
                        pending.cancel()
                    monitor_state.set_active_runs([])
                    break
                _save_batch_progress(
                    args,
                    monitor_state.results_snapshot(),
                    batch_start,
                    challenge_names=replica_names,
                    active_runs=monitor_state.active_runs_snapshot(),
                )
    finally:
        heartbeat.stop()

    _save_batch_progress(
        args,
        monitor_state.results_snapshot(),
        batch_start,
        finished=True,
        challenge_names=replica_names,
    )
    write_json_stdout({"replicas": replicas, "results": results})
    if any(result.get("status") == "interrupted" for result in results):
        return 130
    if any(result.get("api_error") for result in results):
        return 2
    return 0 if any(result.get("solved") for result in results) else 1


def _run_single_replica_worker(
    args_dict: dict[str, Any],
    replica_idx: int,
    label_prefix: str,
) -> dict[str, Any]:
    worker_args = argparse.Namespace(**args_dict)
    configure_logging(
        debug=bool(getattr(worker_args, "debug", False)),
        quiet=bool(getattr(worker_args, "quiet", False)),
    )
    base_name = worker_args.name or "replica"
    worker_args.name = str(Path(base_name) / f"rep{replica_idx}_{label_prefix}")
    if worker_args.output_root:
        worker_args.output_root = str(Path(worker_args.output_root).expanduser().resolve() / worker_args.name)
    challenge = load_challenge(worker_args)
    result = run_single_challenge(worker_args, challenge)
    result["replica"] = replica_idx
    return result
