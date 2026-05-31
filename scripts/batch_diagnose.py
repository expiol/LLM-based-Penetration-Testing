from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from tabulate import tabulate

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.batch.result_logs import iter_result_logs
from killchain_docker.logging_utils import configure_logging, get_logger, write_stdout


LOGGER = get_logger(__name__)


FRAMEWORK_BUCKETS = {
    "challenge_timeout",
    "docker_start_error",
    "runtime_error",
    "script_missing_code",
    "tool_missing_target_files",
    "source_target_unresolved",
    "scope_violation_blocked",
}
LLM_LIMIT_BUCKETS = {
    "candidate_mismatch",
    "candidate_rejected",
    "max_cycles_exhausted",
    "partial_todos_unsolved",
    "partial_no_candidate",
    "stagnated",
    "unsolved_exhausted",
}
PROVIDER_LIMIT_BUCKETS = {
    "llm_connection",
    "llm_timeout",
    "llm_transient_error",
}
STATE_FRAMEWORK_FAILURES = {
    "docker_start_error",
    "runtime_error",
    "script_missing_code",
    "tool_missing_target_files",
    "source_target_unresolved",
}
STATE_LLM_LIMIT_SIGNALS = {
    "candidate_mismatch",
    "candidate_rejected",
    "network_incomplete_read",
    "no_candidate",
    "near_miss",
    "partial_probe_miss",
    "partial_probe_output",
    "partial_no_candidate",
}
STATE_MODEL_OUTPUT_SIGNALS = {
    "diagnostic_evidence",
    "masked_shell_error",
    "nonzero_exit",
    "scope_violation_blocked",
}


def read_json(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    candidate = Path(path)
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("failed to read json", exc_info=True, extra={"path": str(path)})
        return {}
    return payload if isinstance(payload, dict) else {}


def _nested_dict(source: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = source
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _list_text(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]


def _events_tail(artifacts: dict[str, Any], *, limit: int = 80) -> list[str]:
    events_path = artifacts.get("events_path")
    if not events_path:
        return []
    path = Path(str(events_path))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    messages: list[str] = []
    for line in lines[-limit:]:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            messages.append(str(payload.get("message") or ""))
    return messages


def _failure_buckets(result: dict[str, Any]) -> list[str]:
    buckets = result.get("failure_buckets")
    if isinstance(buckets, list):
        return sorted(str(item) for item in buckets if item)
    return []


def _status_counts(metrics: dict[str, Any]) -> dict[str, int]:
    raw = metrics.get("todo_status_counts")
    if not isinstance(raw, dict):
        return {}
    counts: dict[str, int] = {}
    for key, value in raw.items():
        try:
            counts[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return counts


def _state_result_signals(state: dict[str, Any]) -> set[str]:
    rounds = state.get("rounds")
    if not isinstance(rounds, list):
        return set()
    signals: set[str] = set()
    for round_entry in rounds:
        if not isinstance(round_entry, dict):
            continue
        results = round_entry.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            for key in ("result_quality", "partial_reason", "summary", "error"):
                value = result.get(key)
                if isinstance(value, str) and value:
                    signals.add(value)
            context = result.get("output_context")
            if isinstance(context, dict):
                for key in ("failure_kind", "partial_reason", "result_quality"):
                    value = context.get(key)
                    if isinstance(value, str) and value:
                        signals.add(value)
    return signals


def _signal_reason(signals: set[str], allowed: set[str]) -> str:
    matched = sorted(signal for signal in signals if signal in allowed)
    return ", ".join(matched)


def _stop_reason(
    result: dict[str, Any], summary: dict[str, Any], state: dict[str, Any]
) -> str:
    metrics = result.get("state_metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    return str(
        metrics.get("stop_reason")
        or summary.get("stop_reason")
        or state.get("stop_reason")
        or result.get("status")
        or ""
    )


def _is_transient_llm_error(
    result: dict[str, Any],
    summary: dict[str, Any],
    state: dict[str, Any],
    buckets: set[str],
) -> bool:
    if _stop_reason(result, summary, state) == "llm_transient_error":
        return True
    last_llm_error = _nested_dict(state, "metadata", "last_llm_error")
    if last_llm_error and bool(last_llm_error.get("transient")):
        return True
    return bool(buckets & PROVIDER_LIMIT_BUCKETS)


def classify_result(
    result: dict[str, Any],
    summary: dict[str, Any],
    state: dict[str, Any],
    events_tail: list[str],
) -> tuple[str, str]:
    if bool(result.get("solved") or summary.get("solved") or state.get("solved")):
        return "solved", "validated or solved signal present"
    buckets = set(_failure_buckets(result))
    stop_reason = _stop_reason(result, summary, state)
    if _is_transient_llm_error(result, summary, state, buckets):
        return "needs_retry", "transient LLM provider error; rerun required"
    if stop_reason == "challenge_timeout":
        return "framework_signal", "challenge_timeout"
    error_payload = result.get("error")
    if isinstance(error_payload, dict):
        error_text = " ".join(str(value) for value in error_payload.values()).lower()
        if "docker compose" in error_text or "dockerfile:" in error_text:
            return "framework_signal", "docker_start_error"
    if result.get("llm_error") or _nested_dict(state, "metadata", "last_llm_error"):
        return "framework_or_api", "non-transient LLM client error recorded"
    if result.get("api_error"):
        return "framework_or_api", "fatal API error recorded"
    if result.get("interrupted"):
        return "interrupted", "run interrupted"
    runtime_error = (
        result.get("runtime_error")
        or summary.get("runtime_error")
        or _nested_dict(state, "metadata", "runtime_error")
    )
    if isinstance(runtime_error, dict) and runtime_error:
        return "framework_or_api", "runtime_error recorded"

    if buckets & FRAMEWORK_BUCKETS:
        return "framework_signal", ", ".join(sorted(buckets & FRAMEWORK_BUCKETS))
    if buckets & LLM_LIMIT_BUCKETS:
        return "likely_llm_limit", ", ".join(sorted(buckets & LLM_LIMIT_BUCKETS))

    metrics = result.get("state_metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    status_counts = _status_counts(metrics)
    if stop_reason == "max_cycles_exhausted":
        return "likely_llm_limit", "max_cycles_exhausted"
    state_signals = _state_result_signals(state)
    if state_signals & STATE_FRAMEWORK_FAILURES:
        return "framework_signal", _signal_reason(
            state_signals, STATE_FRAMEWORK_FAILURES
        )
    max_cycles_raw = result.get("effective_max_cycles") or result.get("max_cycles")
    try:
        max_cycles = int(max_cycles_raw) if max_cycles_raw is not None else 0
    except (TypeError, ValueError):
        max_cycles = 0
    round_count = int(metrics.get("round_count") or 0)
    if stop_reason == "partial_todos_unsolved":
        reason = _signal_reason(state_signals, STATE_LLM_LIMIT_SIGNALS)
        if reason:
            return "likely_llm_limit", reason
        reason = _signal_reason(state_signals, STATE_MODEL_OUTPUT_SIGNALS)
        if reason:
            return "model_output_quality", reason
        if max_cycles and round_count >= max_cycles:
            return "likely_llm_limit", "bounded run exhausted without framework signal"
        return "likely_llm_limit", "partial_todos_unsolved"
    if stop_reason == "unsolved_no_work_remaining":
        reason = _signal_reason(state_signals, STATE_LLM_LIMIT_SIGNALS)
        if reason:
            return "likely_llm_limit", reason
        return "likely_llm_limit", "no remaining actionable work after bounded run"
    if stop_reason == "todo_failed":
        reason = _signal_reason(state_signals, STATE_LLM_LIMIT_SIGNALS)
        if reason:
            return "likely_llm_limit", reason
        reason = _signal_reason(state_signals, STATE_MODEL_OUTPUT_SIGNALS)
        if reason:
            return "model_output_quality", reason
    if status_counts.get("blocked") and not result.get("error"):
        return "likely_llm_limit", "blocked after bounded attempts"
    if any("schema" in text.lower() and "validation" in text.lower() for text in events_tail):
        return "model_output_quality", "structured-output correction was needed"
    if result.get("error"):
        return "framework_signal", "unclassified error payload"
    return "needs_review", stop_reason or "no clear failure signal"


def summarize_log(path: Path) -> dict[str, Any]:
    result = read_json(path)
    artifacts = result.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    summary = read_json(artifacts.get("summary_path"))
    state = read_json(artifacts.get("state_path"))
    events_tail = _events_tail(artifacts)
    classification, reason = classify_result(result, summary, state, events_tail)
    metrics = result.get("state_metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    token_usage = result.get("token_usage")
    token_usage = token_usage if isinstance(token_usage, dict) else {}
    return {
        "challenge": str(result.get("challenge") or path.stem),
        "status": str(result.get("status") or summary.get("status") or "unknown"),
        "solved": bool(result.get("solved") or summary.get("solved")),
        "stop_reason": str(metrics.get("stop_reason") or summary.get("stop_reason") or ""),
        "classification": classification,
        "reason": reason,
        "rounds": int(metrics.get("round_count") or summary.get("rounds") or 0),
        "executions": int(metrics.get("execution_count") or summary.get("executions") or 0),
        "evidence": int(metrics.get("evidence_count") or summary.get("evidence") or 0),
        "llm_calls": int(token_usage.get("llm_calls") or 0),
        "tokens": int(token_usage.get("total_tokens") or 0),
        "runtime_sec": round(float(result.get("runtime_sec") or 0.0), 3),
        "failure_buckets": ", ".join(_failure_buckets(result)),
        "logfile": str(path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("Diagnose structured AutoPentest batch logs")
    parser.add_argument("logdir")
    parser.add_argument("--json", action="store_true", help="emit JSON rows")
    parser.add_argument("--include-solved", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    logdir = Path(args.logdir).expanduser().resolve()
    if not logdir.is_dir():
        LOGGER.error("log directory does not exist", extra={"logdir": str(logdir)})
        return 1
    rows = [summarize_log(path) for path in iter_result_logs(logdir)]
    if not args.include_solved:
        rows = [row for row in rows if not row["solved"]]
    if args.json:
        write_stdout(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    table = [
        [
            row["challenge"],
            row["status"],
            "yes" if row["solved"] else "no",
            row["stop_reason"],
            row["classification"],
            row["reason"],
            row["rounds"],
            row["executions"],
            row["llm_calls"],
            row["runtime_sec"],
        ]
        for row in rows
    ]
    write_stdout(
        tabulate(
            table,
            headers=[
                "Challenge",
                "Status",
                "Solved",
                "Stop",
                "Class",
                "Reason",
                "Rounds",
                "Execs",
                "LLM",
                "Runtime",
            ],
            tablefmt="tsv",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
