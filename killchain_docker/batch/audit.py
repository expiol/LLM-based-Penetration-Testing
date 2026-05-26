"""Artifact audit helpers for RAG ablation runs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from killchain_docker.rag.hit import (
    redact_file_path_literals,
    redact_flag_literals,
)
from killchain_docker.logging_utils import (
    configure_logging,
    get_logger,
    write_json_file,
    write_json_stdout,
)


LOGGER = get_logger(__name__)
DEFAULT_EXPECTED_MODES = ("enabled", "strict")
ALLOWED_MODE_RETURNCODES = {0, 1}
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_FRONTEND_PATH_KEYS = frozenset(
    {"logdir", "summary_file", "logfile", "status_file", "run_dir"}
)


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning(
            "failed to read JSON payload",
            exc_info=True,
            extra={"path": str(path)},
        )
        return {}
    return payload if isinstance(payload, dict) else {}


def read_json_lines(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        LOGGER.warning(
            "failed to read JSONL payload",
            exc_info=True,
            extra={"path": str(path)},
        )
        return records
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            LOGGER.warning(
                "failed to decode JSONL record",
                exc_info=True,
                extra={"path": str(path), "line_number": line_number},
            )
            return []
        if not isinstance(payload, dict):
            LOGGER.warning(
                "JSONL record is not an object",
                extra={
                    "path": str(path),
                    "line_number": line_number,
                    "payload_type": type(payload).__name__,
                },
            )
            return []
        records.append(payload)
    return records


def read_text_payload(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        LOGGER.warning(
            "failed to read text payload",
            exc_info=True,
            extra={"path": str(path)},
        )
        return ""


def issue(code: str, message: str, **context: Any) -> dict[str, Any]:
    payload = {"code": code, "message": message}
    payload.update({key: value for key, value in context.items() if value is not None})
    return payload


def count_value(value: Any) -> int | None:
    """Return a non-negative integer count, or ``None`` for invalid values."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        return int(value.strip())
    return None


def is_dry_run_manifest(manifest: dict[str, Any]) -> bool:
    """Return True when an ablation manifest only records planned commands."""

    modes = manifest.get("modes")
    if not isinstance(modes, dict):
        return False
    return any(
        isinstance(payload, dict) and bool(payload.get("dry_run"))
        for payload in modes.values()
    )


def audit_dry_run_manifest(
    report_path: Path,
    *,
    expected_modes: tuple[str, ...] = DEFAULT_EXPECTED_MODES,
    require_finished: bool = True,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a dry-run ablation manifest without requiring runtime artifacts."""

    manifest = manifest if manifest is not None else read_json_object(report_path)
    issues: list[dict[str, Any]] = []
    mode_checks: dict[str, Any] = {}

    if not manifest:
        issues.append(
            issue(
                "manifest_unreadable",
                "manifest is missing or not a JSON object",
                path=str(report_path),
            )
        )
        return {
            "schema_version": 1,
            "ok": False,
            "dry_run": True,
            "report_path": str(report_path.resolve()),
            "issue_count": len(issues),
            "issues": issues,
            "modes": mode_checks,
        }

    if require_finished and not manifest.get("finished"):
        issues.append(
            issue(
                "manifest_unfinished",
                "dry-run manifest is not marked finished",
                path=str(report_path),
            )
        )

    modes = manifest.get("modes")
    if not isinstance(modes, dict):
        issues.append(
            issue(
                "manifest_modes_missing",
                "manifest modes is missing or invalid",
                path=str(report_path),
            )
        )
        modes = {}

    for mode in expected_modes:
        payload = modes.get(mode)
        if not isinstance(payload, dict):
            issues.append(
                issue("mode_missing", "expected RAG mode is missing", mode=mode)
            )
            continue
        command = payload.get("command")
        returncode = count_value(payload.get("returncode"))
        dry_run = bool(payload.get("dry_run"))
        mode_checks[mode] = {
            "dry_run": dry_run,
            "returncode": returncode,
            "command": command if isinstance(command, list) else None,
            "logdir": payload.get("logdir"),
        }
        if not dry_run:
            issues.append(
                issue("mode_not_dry_run", "mode is not marked dry_run", mode=mode)
            )
        if not isinstance(command, list) or not command:
            issues.append(
                issue(
                    "mode_command_missing", "dry-run mode command is missing", mode=mode
                )
            )
        if returncode is None:
            issues.append(
                issue(
                    "mode_returncode_invalid",
                    "mode returncode is not a non-negative integer",
                    mode=mode,
                    returncode=payload.get("returncode"),
                )
            )
        elif returncode != 0:
            issues.append(
                issue(
                    "mode_returncode",
                    "dry-run mode returncode should be zero",
                    mode=mode,
                    returncode=returncode,
                )
            )

    return {
        "schema_version": 1,
        "ok": not issues,
        "dry_run": True,
        "report_path": str(report_path.resolve()),
        "issue_count": len(issues),
        "issues": issues,
        "modes": mode_checks,
    }


def audit_ablation_manifest(
    report_path: Path,
    *,
    expected_modes: tuple[str, ...] = DEFAULT_EXPECTED_MODES,
    require_finished: bool = True,
    require_attempts: bool = True,
    require_rag: bool = True,
) -> dict[str, Any]:
    manifest = read_json_object(report_path)
    issues: list[dict[str, Any]] = []
    mode_checks: dict[str, Any] = {}

    if not manifest:
        issues.append(
            issue(
                "manifest_unreadable",
                "manifest is missing or not a JSON object",
                path=str(report_path),
            )
        )
        return _audit_payload(report_path, issues, mode_checks)

    if is_dry_run_manifest(manifest):
        return audit_dry_run_manifest(
            report_path,
            expected_modes=expected_modes,
            require_finished=require_finished,
            manifest=manifest,
        )

    if require_finished and not manifest.get("finished"):
        issues.append(
            issue(
                "manifest_unfinished",
                "ablation manifest is not marked finished",
                path=str(report_path),
            )
        )

    modes = manifest.get("modes")
    if not isinstance(modes, dict):
        issues.append(
            issue(
                "manifest_modes_missing",
                "manifest modes is missing or invalid",
                path=str(report_path),
            )
        )
        return _audit_payload(report_path, issues, mode_checks)

    for mode in expected_modes:
        mode_payload = modes.get(mode)
        if not isinstance(mode_payload, dict):
            issues.append(
                issue("mode_missing", "expected RAG mode is missing", mode=mode)
            )
            continue
        mode_issues, checks = audit_mode(
            mode,
            mode_payload,
            require_attempts=require_attempts,
            require_rag=require_rag,
        )
        issues.extend(mode_issues)
        mode_checks[mode] = checks

    if len(set(expected_modes)) >= 2:
        comparison = manifest.get("comparison")
        if not isinstance(comparison, dict) or not comparison.get("available"):
            issues.append(
                issue(
                    "comparison_missing",
                    "mode comparison is missing or unavailable",
                )
            )
        elif (
            not isinstance(comparison.get("baseline_mode"), str)
            or not isinstance(comparison.get("deltas_from_baseline"), dict)
        ):
            issues.append(
                issue(
                    "comparison_delta_missing",
                    "mode comparison delta is missing",
                )
            )

    return _audit_payload(report_path, issues, mode_checks)


def audit_mode(
    mode: str,
    mode_payload: dict[str, Any],
    *,
    require_attempts: bool,
    require_rag: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    returncode = count_value(mode_payload.get("returncode"))
    if returncode is None:
        issues.append(
            issue(
                "mode_returncode_invalid",
                "mode returncode is not a non-negative integer",
                mode=mode,
                returncode=mode_payload.get("returncode"),
            )
        )
    elif returncode not in ALLOWED_MODE_RETURNCODES:
        issues.append(
            issue(
                "mode_returncode",
                "mode returncode indicates infrastructure failure",
                mode=mode,
                returncode=returncode,
            )
        )

    logdir = Path(str(mode_payload.get("logdir") or "")).expanduser()
    summary_path = _path_from_payload(
        mode_payload, "summary_path", logdir / "_batch_summary.json"
    )
    monitor_path = _path_from_payload(
        mode_payload, "monitor_json_path", logdir / "_batch_monitor.json"
    )
    html_path = _path_from_payload(
        mode_payload, "monitor_path", logdir / "_batch_monitor.html"
    )
    summary = read_json_object(summary_path)
    monitor = read_json_object(monitor_path)

    checks = {
        "returncode": returncode,
        "logdir": str(logdir),
        "summary_path": str(summary_path),
        "monitor_json_path": str(monitor_path),
        "monitor_path": str(html_path),
        "attempted": 0,
        "details_checked": 0,
        "status_files_checked": 0,
        "artifact_runs_checked": 0,
        "events_checked": 0,
    }

    if not summary:
        issues.append(
            issue(
                "summary_missing",
                "batch summary is missing or unreadable",
                mode=mode,
                path=str(summary_path),
            )
        )
        return issues, checks
    if not monitor:
        issues.append(
            issue(
                "monitor_missing",
                "batch monitor JSON is missing or unreadable",
                mode=mode,
                path=str(monitor_path),
            )
        )
    if not html_path.exists():
        issues.append(
            issue(
                "monitor_html_missing",
                "batch monitor HTML is missing",
                mode=mode,
                path=str(html_path),
            )
        )
    else:
        issues.extend(_audit_monitor_html(mode, html_path))

    attempted = count_value(summary.get("total_attempted"))
    if attempted is None:
        issues.append(
            issue(
                "summary_count_invalid",
                "summary total_attempted is not a non-negative integer",
                mode=mode,
            )
        )
        attempted = 0
    checks["attempted"] = attempted
    if require_attempts and attempted <= 0:
        issues.append(
            issue(
                "summary_empty",
                "batch summary has no attempted challenges",
                mode=mode,
                path=str(summary_path),
            )
        )

    experiment_config = summary.get("experiment_config") or {}
    if (
        isinstance(experiment_config, dict)
        and experiment_config.get("rag_mode") != mode
    ):
        issues.append(
            issue(
                "summary_rag_mode",
                "summary experiment_config.rag_mode does not match mode",
                mode=mode,
            )
        )

    details = summary.get("details") or []
    if not isinstance(details, list):
        issues.append(
            issue("summary_details_invalid", "summary details is not a list", mode=mode)
        )
        details = []
    if attempted and len(details) != attempted:
        issues.append(
            issue(
                "summary_details_count",
                "summary detail count does not match attempted count",
                mode=mode,
            )
        )

    monitor_counts = monitor.get("counts") if isinstance(monitor, dict) else {}
    if isinstance(monitor_counts, dict) and attempted:
        completed_count = count_value(monitor_counts.get("completed"))
        if completed_count is None:
            issues.append(
                issue(
                    "monitor_count_invalid",
                    "monitor completed count is not a non-negative integer",
                    mode=mode,
                    monitor_key="completed",
                )
            )
        elif completed_count != attempted:
            issues.append(
                issue(
                    "monitor_completed_count",
                    "monitor completed count does not match summary attempts",
                    mode=mode,
                )
            )
    if isinstance(monitor_counts, dict):
        issues.extend(_audit_monitor_summary_counts(mode, summary, monitor_counts))

    summary_finished = bool(summary.get("finished"))
    mode_requires_rag = require_rag and mode != "disabled"
    if summary_finished and isinstance(monitor, dict) and not monitor.get("finished"):
        issues.append(
            issue(
                "monitor_unfinished",
                "batch summary is finished but monitor is not marked finished",
                mode=mode,
            )
        )

    if monitor:
        expected_monitor_details = {
            str(
                detail.get("monitor_challenge") or detail.get("challenge") or ""
            ): detail
            for detail in details
            if isinstance(detail, dict)
            and str(detail.get("monitor_challenge") or detail.get("challenge") or "")
        }
        issues.extend(
            _audit_monitor_payload(
                mode,
                monitor,
                require_rag=mode_requires_rag,
                expected_challenges=set(expected_monitor_details),
                expected_details=expected_monitor_details,
                require_finished=summary_finished,
            )
        )

    for detail in details:
        if not isinstance(detail, dict):
            continue
        checks["details_checked"] += 1
        challenge = str(detail.get("challenge") or "")
        if detail.get("rag_mode") != mode:
            issues.append(
                issue(
                    "detail_rag_mode",
                    "challenge detail rag_mode does not match mode",
                    mode=mode,
                    challenge=challenge,
                )
            )
        if detail.get("api_error") or detail.get("llm_error"):
            issues.append(
                issue(
                    "detail_llm_error",
                    "challenge detail records an API/LLM error",
                    mode=mode,
                    challenge=challenge,
                )
            )
        issues.extend(_audit_detail_runtime_error(mode, challenge, detail))
        status_path = _resolve_under(logdir, detail.get("status_file"))
        status_payload = read_json_object(status_path) if status_path else {}
        if not status_payload:
            issues.append(
                issue(
                    "status_missing",
                    "challenge status file is missing or unreadable",
                    mode=mode,
                    challenge=challenge,
                )
            )
        else:
            checks["status_files_checked"] += 1
            issues.extend(
                _audit_status_payload(
                    mode,
                    challenge,
                    status_payload,
                    detail=detail,
                    require_rag=mode_requires_rag,
                )
            )
        artifact_issues, artifact_checks = _audit_artifacts(
            mode, challenge, detail, require_rag=mode_requires_rag
        )
        issues.extend(artifact_issues)
        checks["artifact_runs_checked"] += artifact_checks["artifact_runs_checked"]
        checks["events_checked"] += artifact_checks["events_checked"]

    return issues, checks


def _audit_monitor_summary_counts(
    mode: str,
    summary: dict[str, Any],
    monitor_counts: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = (
        ("solved", "solved_count"),
        ("failed", "failed_count"),
        ("skipped", "skipped_count"),
        ("interrupted", "interrupted_count"),
    )
    issues: list[dict[str, Any]] = []
    for monitor_key, summary_key in checks:
        if monitor_key not in monitor_counts or summary_key not in summary:
            issues.append(
                issue(
                    "monitor_summary_count_missing",
                    "monitor or summary is missing a status count",
                    mode=mode,
                    monitor_key=monitor_key,
                    summary_key=summary_key,
                )
            )
            continue
        monitor_value = count_value(monitor_counts.get(monitor_key))
        summary_value = count_value(summary.get(summary_key))
        if monitor_value is None or summary_value is None:
            issues.append(
                issue(
                    "monitor_summary_count_invalid",
                    "monitor or summary status count is not a non-negative integer",
                    mode=mode,
                    monitor_key=monitor_key,
                    summary_key=summary_key,
                    monitor_value=monitor_counts.get(monitor_key),
                    summary_value=summary.get(summary_key),
                )
            )
            continue
        if monitor_value == summary_value:
            continue
        issues.append(
            issue(
                "monitor_summary_count_mismatch",
                "monitor status count does not match batch summary",
                mode=mode,
                monitor_key=monitor_key,
                summary_key=summary_key,
                monitor_value=monitor_value,
                summary_value=summary_value,
            )
        )
    return issues


def _audit_monitor_payload(
    mode: str,
    monitor: dict[str, Any],
    *,
    require_rag: bool,
    expected_challenges: set[str] | None = None,
    expected_details: dict[str, dict[str, Any]] | None = None,
    require_finished: bool = False,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    entries = monitor.get("entries")
    if not isinstance(entries, list):
        return [
            issue("monitor_entries_invalid", "monitor entries is not a list", mode=mode)
        ]

    issues.extend(_audit_monitor_paths(mode, monitor))

    raw_rag_keys = {
        "mode",
        "top_score",
        "top_challenge_id",
        "hit_provenance",
        "knowledge_hints",
        "challenge_identity_hit",
        "excluded_challenge_ids",
        "excluded_event_keys",
        "strict_exclude",
    }
    entry_by_challenge: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        challenge = str(entry.get("challenge") or "")
        if challenge:
            if challenge in entry_by_challenge:
                issues.append(
                    issue(
                        "monitor_duplicate_entry",
                        "monitor has duplicate challenge entries",
                        mode=mode,
                        challenge=challenge,
                    )
                )
            else:
                entry_by_challenge[challenge] = entry
        state = str(entry.get("state") or "")
        if require_finished and state != "completed":
            issues.append(
                issue(
                    "monitor_entry_not_completed",
                    "finished monitor entry is not completed",
                    mode=mode,
                    challenge=challenge,
                    state=state,
                )
            )
        result = entry.get("result")
        if not isinstance(result, dict):
            if state == "completed":
                issues.append(
                    issue(
                        "monitor_result_missing",
                        "completed monitor entry is missing result payload",
                        mode=mode,
                        challenge=challenge,
                    )
                )
            continue
        rag = result.get("rag")
        if require_rag and not isinstance(rag, dict):
            issues.append(
                issue(
                    "monitor_rag_missing",
                    "completed monitor result is missing public RAG status",
                    mode=mode,
                    challenge=challenge,
                )
            )
            continue
        if not isinstance(rag, dict):
            continue
        issues.extend(
            _audit_public_rag_payload(
                mode,
                challenge,
                rag,
                "monitor",
                raw_rag_keys=raw_rag_keys,
            )
        )
    for challenge in sorted(expected_challenges or set()):
        entry = entry_by_challenge.get(challenge)
        if not entry:
            issues.append(
                issue(
                    "monitor_detail_missing",
                    "summary detail is missing from monitor entries",
                    mode=mode,
                    challenge=challenge,
                )
            )
            continue
        if not entry.get("status_file"):
            issues.append(
                issue(
                    "monitor_status_file_missing",
                    "monitor entry is missing status_file",
                    mode=mode,
                    challenge=challenge,
                )
            )
        result = entry.get("result")
        detail = (expected_details or {}).get(challenge)
        if isinstance(detail, dict) and isinstance(result, dict):
            issues.extend(_audit_monitor_result_match(mode, challenge, detail, result))
    return issues


def _audit_monitor_result_match(
    mode: str,
    challenge: str,
    detail: dict[str, Any],
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for key in ("status", "run_id"):
        if not result.get(key) or not detail.get(key):
            continue
        if str(result.get(key)) == str(detail.get(key)):
            continue
        issues.append(
            issue(
                f"monitor_result_{key}_mismatch",
                f"monitor result {key} does not match summary detail",
                mode=mode,
                challenge=challenge,
                monitor_value=result.get(key),
                summary_value=detail.get(key),
            )
        )
    if (
        "solved" in result
        and "solved" in detail
        and bool(result.get("solved")) != bool(detail.get("solved"))
    ):
        issues.append(
            issue(
                "monitor_result_solved_mismatch",
                "monitor result solved flag does not match summary detail",
                mode=mode,
                challenge=challenge,
                monitor_value=bool(result.get("solved")),
                summary_value=bool(detail.get("solved")),
            )
        )
    issues.extend(
        _audit_runtime_error_match(mode, challenge, detail, result, "monitor")
    )
    return issues


def _audit_monitor_paths(
    mode: str, payload: Any, *, prefix: str = "monitor"
) -> list[dict[str, Any]]:
    return _audit_frontend_paths(
        mode,
        payload,
        prefix=prefix,
        issue_code="monitor_path_unsafe",
        message="monitor JSON exposes an unsafe path-like value",
    )


def _audit_status_paths(
    mode: str, challenge: str, payload: Any
) -> list[dict[str, Any]]:
    return _audit_frontend_paths(
        mode,
        payload,
        prefix="status",
        issue_code="status_path_unsafe",
        message="status JSON exposes an unsafe path-like value",
        challenge=challenge,
    )


def _audit_frontend_paths(
    mode: str,
    payload: Any,
    *,
    prefix: str,
    issue_code: str,
    message: str,
    challenge: str | None = None,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            field = f"{prefix}.{key}"
            if _is_frontend_path_key(key):
                issues.extend(
                    _audit_frontend_path_value(
                        mode,
                        field,
                        value,
                        issue_code=issue_code,
                        message=message,
                        challenge=challenge,
                    )
                )
                continue
            issues.extend(
                _audit_frontend_paths(
                    mode,
                    value,
                    prefix=field,
                    issue_code=issue_code,
                    message=message,
                    challenge=challenge,
                )
            )
        return issues
    if isinstance(payload, list):
        for index, item in enumerate(payload):
            issues.extend(
                _audit_frontend_paths(
                    mode,
                    item,
                    prefix=f"{prefix}[{index}]",
                    issue_code=issue_code,
                    message=message,
                    challenge=challenge,
                )
            )
    return issues


def _audit_frontend_path_value(
    mode: str,
    field: str,
    value: Any,
    *,
    issue_code: str,
    message: str,
    challenge: str | None,
) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        issues: list[dict[str, Any]] = []
        for index, item in enumerate(value):
            issues.extend(
                _audit_frontend_path_value(
                    mode,
                    f"{field}[{index}]",
                    item,
                    issue_code=issue_code,
                    message=message,
                    challenge=challenge,
                )
            )
        return issues
    if _is_frontend_safe_relative_path(value):
        return []
    return [
        issue(
            issue_code,
            message,
            mode=mode,
            challenge=challenge,
            field=field,
            value=str(value),
        )
    ]


def _is_frontend_path_key(key: str) -> bool:
    return key in _FRONTEND_PATH_KEYS or key.endswith(
        ("_path", "_paths", "_dir", "_dirs")
    )


def _is_frontend_safe_relative_path(value: Any) -> bool:
    raw = str(value)
    if raw == ".":
        return True
    if not raw:
        return False
    if _URI_SCHEME_RE.match(raw):
        return False
    if raw.startswith("/") or "\\" in raw:
        return False
    if raw == ".." or raw.startswith("../") or "/../" in raw or raw.endswith("/.."):
        return False
    return True


def _audit_monitor_html(mode: str, html_path: Path) -> list[dict[str, Any]]:
    try:
        html = html_path.read_text(encoding="utf-8")
    except OSError:
        return [
            issue(
                "monitor_html_unreadable",
                "batch monitor HTML is unreadable",
                mode=mode,
                path=str(html_path),
            )
        ]

    required_fragments = {
        "_batch_monitor.json": "snapshot polling",
        "async function loadStatus": "per-run status polling",
        "function safeLink": "safe artifact links",
        "function threadRegistrySummary": "thread registry rendering",
        "function threadSummary": "thread summary rendering",
        "threads.registry": "status thread registry loading",
        "todo.worker": "per-thread worker rendering",
        "event.message": "per-thread latest event message rendering",
        "threadName": "run thread name rendering",
        "writerThreadId": "status writer thread rendering",
        "writerThreadName": "status writer thread name rendering",
        "eventThreadId": "latest event thread rendering",
        "eventThreadName": "latest event thread name rendering",
        "status read failed": "per-run status polling errors",
        'if (row.statusError) return "stale"': "status polling failure liveness downgrade",
        "function pollStatusText": "browser refresh status rendering",
        "browser refresh": "browser refresh timestamp",
        "polling ${(refreshMs / 1000).toFixed(0)}s": "browser polling interval",
        "const failedStatuses = new Set": "terminal failure status badge mapping",
        '"unsolved_exhausted"': "unsolved terminal status badge mapping",
        'if (normalized === "interrupted") return "interrupted"': "interrupted status badge mapping",
        "failedStatuses.has(normalized)": "failed status badge lookup",
    }
    missing = [
        label for fragment, label in required_fragments.items() if fragment not in html
    ]
    if missing:
        return [
            issue(
                "monitor_html_stale",
                "batch monitor HTML is missing realtime monitor capabilities",
                mode=mode,
                path=str(html_path),
                missing=missing,
            )
        ]
    return []


def _audit_status_payload(
    mode: str,
    challenge: str,
    payload: dict[str, Any],
    *,
    detail: dict[str, Any],
    require_rag: bool,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if payload.get("challenge") != challenge:
        issues.append(
            issue(
                "status_challenge",
                "status challenge does not match summary detail",
                mode=mode,
                challenge=challenge,
            )
        )
    issues.extend(_audit_status_observability(mode, challenge, payload))
    issues.extend(_audit_status_paths(mode, challenge, payload))
    if (
        payload.get("status")
        and detail.get("status")
        and payload.get("status") != detail.get("status")
    ):
        issues.append(
            issue(
                "status_result_mismatch",
                "status file status does not match summary detail",
                mode=mode,
                challenge=challenge,
                status=payload.get("status"),
                detail_status=detail.get("status"),
            )
        )
    if (
        payload.get("run_id")
        and detail.get("run_id")
        and payload.get("run_id") != detail.get("run_id")
    ):
        issues.append(
            issue(
                "status_run_id_mismatch",
                "status file run_id does not match summary detail",
                mode=mode,
                challenge=challenge,
                run_id=payload.get("run_id"),
                detail_run_id=detail.get("run_id"),
            )
        )
    if (
        "solved" in payload
        and "solved" in detail
        and bool(payload.get("solved")) != bool(detail.get("solved"))
    ):
        issues.append(
            issue(
                "status_solved_mismatch",
                "status file solved flag does not match summary detail",
                mode=mode,
                challenge=challenge,
                solved=bool(payload.get("solved")),
                detail_solved=bool(detail.get("solved")),
            )
        )
    rag = payload.get("rag")
    if require_rag and not isinstance(rag, dict):
        issues.append(
            issue(
                "status_rag_missing",
                "status file is missing RAG payload",
                mode=mode,
                challenge=challenge,
            )
        )
    if isinstance(rag, dict):
        issues.extend(_audit_public_rag_payload(mode, challenge, rag, "status"))
    issues.extend(
        _audit_runtime_error_match(mode, challenge, detail, payload, "status")
    )
    return issues


def _audit_detail_runtime_error(
    mode: str,
    challenge: str,
    detail: dict[str, Any],
) -> list[dict[str, Any]]:
    runtime_error = detail.get("runtime_error")
    if not isinstance(runtime_error, dict):
        return []
    buckets = detail.get("failure_buckets")
    if isinstance(buckets, list) and "runtime_error" in buckets:
        return []
    return [
        issue(
            "runtime_error_bucket_missing",
            "runtime_error detail is missing the runtime_error failure bucket",
            mode=mode,
            challenge=challenge,
        )
    ]


def _runtime_error_type(payload: dict[str, Any]) -> str:
    runtime_error = payload.get("runtime_error")
    if not isinstance(runtime_error, dict):
        return ""
    return str(runtime_error.get("type") or "").strip()


def _audit_runtime_error_match(
    mode: str,
    challenge: str,
    detail: dict[str, Any],
    payload: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    detail_type = _runtime_error_type(detail)
    if not detail_type:
        return []
    payload_type = _runtime_error_type(payload)
    if not payload_type:
        return [
            issue(
                "runtime_error_missing",
                f"{source} is missing runtime_error from summary detail",
                mode=mode,
                challenge=challenge,
                source=source,
                expected_type=detail_type,
            )
        ]
    if payload_type == detail_type:
        return []
    return [
        issue(
            "runtime_error_mismatch",
            f"{source} runtime_error type does not match summary detail",
            mode=mode,
            challenge=challenge,
            source=source,
            expected_type=detail_type,
            actual_type=payload_type,
        )
    ]


def _audit_status_observability(
    mode: str, challenge: str, payload: dict[str, Any]
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for key in ("pid", "thread_id", "status_writer_thread_id"):
        if not isinstance(payload.get(key), int):
            issues.append(
                issue(
                    "status_observability_missing",
                    "status file is missing process/thread observability",
                    mode=mode,
                    challenge=challenge,
                    field=key,
                )
            )
    for key in ("thread_name", "status_writer_thread_name"):
        if not isinstance(payload.get(key), str) or not payload.get(key):
            issues.append(
                issue(
                    "status_observability_missing",
                    "status file is missing process/thread observability",
                    mode=mode,
                    challenge=challenge,
                    field=key,
                )
            )
    if not payload.get("updated_at"):
        issues.append(
            issue(
                "status_observability_missing",
                "status file is missing update timestamp",
                mode=mode,
                challenge=challenge,
                field="updated_at",
            )
        )
    status = str(payload.get("status") or "")
    if status not in {"skipped", "load_error"} and not isinstance(
        payload.get("runtime_sec"), (int, float)
    ):
        issues.append(
            issue(
                "status_runtime_missing",
                "status file is missing numeric runtime_sec",
                mode=mode,
                challenge=challenge,
            )
        )
    issues.extend(_audit_thread_registry(mode, challenge, payload))
    return issues


def _audit_thread_registry(
    mode: str, challenge: str, payload: dict[str, Any]
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    threads = payload.get("threads")
    registry = threads.get("registry") if isinstance(threads, dict) else None
    if not isinstance(registry, list) or not registry:
        return [
            issue(
                "status_thread_registry_missing",
                "status file is missing thread registry",
                mode=mode,
                challenge=challenge,
            )
        ]
    for index, entry in enumerate(registry):
        if not isinstance(entry, dict):
            return [
                issue(
                    "status_thread_registry_shape",
                    "thread registry entry is not an object",
                    mode=mode,
                    challenge=challenge,
                    index=index,
                )
            ]
        roles = entry.get("roles")
        if not isinstance(roles, list) or not roles:
            return [
                issue(
                    "status_thread_registry_shape",
                    "thread registry entry is missing roles",
                    mode=mode,
                    challenge=challenge,
                    index=index,
                )
            ]
        if entry.get("id") is None and not entry.get("name"):
            return [
                issue(
                    "status_thread_registry_shape",
                    "thread registry entry is missing id/name",
                    mode=mode,
                    challenge=challenge,
                    index=index,
                )
            ]
        for key in ("challenge", "stage", "status"):
            if not entry.get(key):
                return [
                    issue(
                        "status_thread_registry_shape",
                        "thread registry entry is missing runtime context",
                        mode=mode,
                        challenge=challenge,
                        index=index,
                        field=key,
                    )
                ]
    latest_event = payload.get("latest_event")
    if isinstance(latest_event, dict) and not _registry_has_thread(
        registry,
        latest_event.get("thread_id"),
        latest_event.get("thread_name"),
    ):
        issues.append(
            issue(
                "status_thread_registry_latest_event_missing",
                "thread registry is missing the latest event thread",
                mode=mode,
                challenge=challenge,
            )
        )
    return issues


def _registry_has_thread(
    registry: list[Any], thread_id: object, thread_name: object
) -> bool:
    for entry in registry:
        if not isinstance(entry, dict):
            continue
        if thread_id is not None and entry.get("id") == thread_id:
            return True
        if thread_name and entry.get("name") == thread_name:
            return True
    return False


def _audit_public_rag_payload(
    mode: str,
    challenge: str,
    rag: dict[str, Any],
    source: str,
    *,
    raw_rag_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    raw_keys = raw_rag_keys or {
        "mode",
        "top_score",
        "top_challenge_id",
        "hit_provenance",
        "knowledge_hints",
        "challenge_identity_hit",
        "excluded_challenge_ids",
        "excluded_event_keys",
        "strict_exclude",
    }
    leaked = sorted(key for key in raw_keys if key in rag)
    if leaked:
        issues.append(
            issue(
                "public_rag_raw_payload",
                "public RAG status exposes raw retrieval fields",
                mode=mode,
                challenge=challenge,
                source=source,
                leaked_keys=leaked,
            )
        )

    if "policy" not in rag or "hint_count" not in rag:
        issues.append(
            issue(
                "public_rag_shape",
                "RAG status is not the public payload shape",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
        return issues
    hint_count = count_value(rag.get("hint_count"))
    if hint_count is None:
        issues.append(
            issue(
                "public_rag_count_invalid",
                "RAG hint_count is not a non-negative integer",
                mode=mode,
                challenge=challenge,
                source=source,
                hint_count=rag.get("hint_count"),
            )
        )
    if mode == "disabled":
        if rag.get("enabled"):
            issues.append(
                issue(
                    "public_rag_enabled",
                    "disabled mode reported RAG as enabled",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                )
            )
        if rag.get("policy") != "disabled":
            issues.append(
                issue(
                    "public_rag_policy",
                    "disabled mode public RAG policy is not disabled",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                    policy=rag.get("policy"),
                )
            )
        if rag.get("status") not in {"disabled", "unavailable", None}:
            issues.append(
                issue(
                    "public_rag_status",
                    "disabled mode public RAG status is not disabled",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                    status=rag.get("status"),
                )
            )
        return issues
    if not rag.get("enabled"):
        issues.append(
            issue(
                "public_rag_disabled",
                "RAG status is disabled",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
    if rag.get("status") in {
        "unavailable",
        "disabled",
        "error",
        "miss",
        "empty_query",
        "metadata_only",
    }:
        issues.append(
            issue(
                "public_rag_unavailable",
                "RAG status is unavailable",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
    if hint_count is not None and hint_count <= 0:
        issues.append(
            issue(
                "public_rag_empty",
                "RAG status has no actionable hints",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )

    expected_policy = {
        "enabled": "retrieved_context",
        "strict": "filtered_context",
    }.get(mode)
    if expected_policy and rag.get("policy") != expected_policy:
        issues.append(
            issue(
                "public_rag_policy",
                "RAG status policy does not match mode",
                mode=mode,
                challenge=challenge,
                source=source,
                policy=rag.get("policy"),
                expected_policy=expected_policy,
            )
        )
    return issues


def _audit_artifacts(
    mode: str,
    challenge: str,
    detail: dict[str, Any],
    *,
    require_rag: bool,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    issues: list[dict[str, Any]] = []
    checks = {"artifact_runs_checked": 0, "events_checked": 0}
    artifacts = detail.get("artifacts")
    if not isinstance(artifacts, dict):
        return issues, checks

    summary_path = Path(str(artifacts.get("summary_path") or ""))
    state_path = Path(str(artifacts.get("state_path") or ""))
    events_path = Path(str(artifacts.get("events_path") or ""))
    for key, raw_path in artifacts.items():
        if key.endswith("_path") and raw_path and not Path(str(raw_path)).exists():
            issues.append(
                issue(
                    "artifact_path_missing",
                    "artifact path does not exist",
                    mode=mode,
                    challenge=challenge,
                    path=str(raw_path),
                )
            )
    issues.extend(
        _audit_runtime_error_artifact_visibility(mode, challenge, detail, artifacts)
    )

    artifact_summary = read_json_object(summary_path) if summary_path.exists() else {}
    state_payload = read_json_object(state_path) if state_path.exists() else {}
    if artifact_summary:
        checks["artifact_runs_checked"] += 1
        issues.extend(
            _audit_runtime_error_match(
                mode,
                challenge,
                detail,
                artifact_summary,
                "artifact_summary",
            )
        )
        rag = artifact_summary.get("rag")
        if require_rag and not isinstance(rag, dict):
            issues.append(
                issue(
                    "artifact_rag_missing",
                    "artifact summary is missing RAG payload",
                    mode=mode,
                    challenge=challenge,
                )
            )
        if isinstance(rag, dict):
            issues.extend(
                _audit_public_rag_payload(mode, challenge, rag, "artifact_summary")
            )

    raw_rag = _state_rag_payload(state_payload)
    if isinstance(raw_rag, dict):
        issues.extend(_audit_rag_payload(mode, challenge, raw_rag, "state_metadata"))

    records = read_json_lines(events_path) if events_path.exists() else []
    if not records:
        issues.append(
            issue(
                "events_missing",
                "events JSONL is missing or invalid",
                mode=mode,
                challenge=challenge,
                path=str(events_path),
            )
        )
        return issues, checks

    checks["events_checked"] += len(records)
    for record in records:
        if not record.get("event_type") or not record.get("level"):
            issues.append(
                issue(
                    "event_shape",
                    "event record is missing level or event_type",
                    mode=mode,
                    challenge=challenge,
                )
            )
            break
        if not isinstance(record.get("pid"), int) or not isinstance(
            record.get("thread_id"), int
        ):
            issues.append(
                issue(
                    "event_observability",
                    "event record is missing pid/thread_id",
                    mode=mode,
                    challenge=challenge,
                )
            )
            break
        if not isinstance(record.get("thread_name"), str) or not record.get(
            "thread_name"
        ):
            issues.append(
                issue(
                    "event_observability",
                    "event record is missing thread_name",
                    mode=mode,
                    challenge=challenge,
                )
            )
            break
        context = record.get("context")
        if (
            not isinstance(context, dict)
            or not context.get("run_id")
            or not context.get("challenge")
        ):
            issues.append(
                issue(
                    "event_context",
                    "event record is missing run_id/challenge context",
                    mode=mode,
                    challenge=challenge,
                )
            )
            break
        lifecycle_issues = _audit_worker_event_context(mode, challenge, record)
        if lifecycle_issues:
            issues.extend(lifecycle_issues)
            break
    return issues, checks


def _audit_worker_event_context(
    mode: str,
    challenge: str,
    record: dict[str, Any],
) -> list[dict[str, Any]]:
    event_type = str(record.get("event_type") or "")
    if event_type != "dispatch" and not event_type.startswith("worker_"):
        return []
    context = record.get("context")
    if not isinstance(context, dict):
        return [
            issue(
                "event_worker_context",
                "worker lifecycle event is missing context",
                mode=mode,
                challenge=challenge,
                event_type=event_type,
            )
        ]
    missing = [
        key
        for key in ("todo_id", "todo_status", "todo_phase", "worker")
        if not context.get(key)
    ]
    if not missing:
        return []
    return [
        issue(
            "event_worker_context",
            "worker lifecycle event is missing todo/worker context",
            mode=mode,
            challenge=challenge,
            event_type=event_type,
            missing=missing,
        )
    ]


def _state_rag_payload(state_payload: dict[str, Any]) -> dict[str, Any] | None:
    metadata = (
        state_payload.get("metadata") if isinstance(state_payload, dict) else None
    )
    if not isinstance(metadata, dict):
        return None
    rag = metadata.get("rag")
    return rag if isinstance(rag, dict) else None


def _artifact_path(artifacts: dict[str, Any], key: str) -> Path | None:
    raw = artifacts.get(key)
    return Path(str(raw)) if raw else None


def _audit_runtime_error_artifact_visibility(
    mode: str,
    challenge: str,
    detail: dict[str, Any],
    artifacts: dict[str, Any],
) -> list[dict[str, Any]]:
    expected_type = _runtime_error_type(detail)
    if not expected_type:
        return []
    issues: list[dict[str, Any]] = []
    compact_path = _artifact_path(artifacts, "compact_json_path")
    if compact_path and compact_path.exists():
        compact = read_json_object(compact_path)
        run = compact.get("run") if isinstance(compact.get("run"), dict) else {}
        if _runtime_error_type(run) != expected_type:
            issues.append(
                issue(
                    "runtime_error_compact_missing",
                    "compact JSON is missing the runtime_error from summary detail",
                    mode=mode,
                    challenge=challenge,
                    expected_type=expected_type,
                )
            )
    for key, source in (
        ("report_path", "report"),
        ("compact_markdown_path", "compact_markdown"),
    ):
        path = _artifact_path(artifacts, key)
        if path and path.exists() and expected_type not in read_text_payload(path):
            issues.append(
                issue(
                    "runtime_error_text_missing",
                    f"{source} is missing the runtime_error type from summary detail",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                    expected_type=expected_type,
                )
            )
    return issues


def _audit_rag_payload(
    mode: str, challenge: str, rag: dict[str, Any], source: str
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if rag.get("mode") != mode:
        issues.append(
            issue(
                "rag_mode",
                "RAG payload mode does not match audit mode",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
    if mode == "disabled":
        if rag.get("enabled"):
            issues.append(
                issue(
                    "rag_disabled_enabled",
                    "disabled mode artifact RAG payload is enabled",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                )
            )
        if rag.get("status") not in {"disabled", "unavailable", None}:
            issues.append(
                issue(
                    "rag_disabled_status",
                    "disabled mode artifact RAG status is not disabled",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                    status=rag.get("status"),
                )
            )
        issues.extend(_audit_rag_hint_redaction(mode, challenge, rag, source))
        return issues
    if not rag.get("enabled"):
        issues.append(
            issue(
                "rag_disabled",
                "RAG payload is disabled",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
    issues.extend(_audit_rag_hint_redaction(mode, challenge, rag, source))
    if mode == "strict":
        if not rag.get("strict_exclude"):
            issues.append(
                issue(
                    "rag_strict_exclude",
                    "strict mode did not enable strict exclusion",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                )
            )
        if rag.get("challenge_identity_hit"):
            issues.append(
                issue(
                    "rag_strict_identity_hit",
                    "strict mode returned a challenge-identical hit",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                )
            )
        issues.extend(_audit_strict_rag_provenance(mode, challenge, rag, source))
    if mode == "enabled" and rag.get("strict_exclude"):
        issues.append(
            issue(
                "rag_enabled_strict",
                "enabled mode unexpectedly enabled strict exclusion",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        )
    return issues


def _audit_rag_hint_redaction(
    mode: str,
    challenge: str,
    rag: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    hints = rag.get("knowledge_hints")
    if not isinstance(hints, list):
        return []

    issues: list[dict[str, Any]] = []
    for index, hint in enumerate(hints):
        if not isinstance(hint, dict):
            continue
        for field in ("description", "solution_sketch"):
            value = hint.get(field)
            if isinstance(value, str) and redact_flag_literals(value) != value:
                issues.append(
                    issue(
                        "rag_hint_literal_leak",
                        "RAG hint contains unredacted flag-like literal",
                        mode=mode,
                        challenge=challenge,
                        source=source,
                        hint_index=index,
                        field=field,
                    )
                )
        files = hint.get("files")
        if not isinstance(files, list):
            continue
        for file_index, value in enumerate(files):
            if isinstance(value, str) and redact_file_path_literals(value) != value:
                issues.append(
                    issue(
                        "rag_hint_literal_leak",
                        "RAG hint contains unredacted flag-like literal",
                        mode=mode,
                        challenge=challenge,
                        source=source,
                        hint_index=index,
                        field="files",
                        file_index=file_index,
                    )
                )
    return issues


def _audit_strict_rag_provenance(
    mode: str,
    challenge: str,
    rag: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    hit_count = count_value(rag.get("hit_count"))
    if hit_count is None:
        return [
            issue(
                "rag_hit_count_invalid",
                "RAG hit_count is not a non-negative integer",
                mode=mode,
                challenge=challenge,
                source=source,
                hit_count=rag.get("hit_count"),
            )
        ]
    if hit_count <= 0:
        return []

    excluded_event_keys = {
        str(value or "").strip().lower()
        for value in rag.get("excluded_event_keys") or []
        if str(value or "").strip()
    }
    challenge_event_key = str(rag.get("challenge_event_key") or "").strip().lower()
    if challenge_event_key:
        excluded_event_keys.add(challenge_event_key)

    raw_hits = rag.get("hit_provenance")
    hits = raw_hits if isinstance(raw_hits, list) else []
    if not hits:
        top_event_key = str(rag.get("top_event_key") or "").strip().lower()
        if top_event_key:
            hits = [
                {
                    "challenge_id": rag.get("top_challenge_id"),
                    "event_key": top_event_key,
                }
            ]
    if not hits:
        return [
            issue(
                "rag_provenance_missing",
                "strict RAG payload has hits but no event provenance to audit",
                mode=mode,
                challenge=challenge,
                source=source,
            )
        ]

    issues: list[dict[str, Any]] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        if str(hit.get("challenge_id") or "") == challenge:
            issues.append(
                issue(
                    "rag_strict_identity_hit",
                    "strict mode returned a challenge-identical hit",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                )
            )
            break
        hit_event_key = str(hit.get("event_key") or "").strip().lower()
        if hit_event_key and hit_event_key in excluded_event_keys:
            issues.append(
                issue(
                    "rag_strict_same_event_hit",
                    "strict mode returned a same-event RAG hit",
                    mode=mode,
                    challenge=challenge,
                    source=source,
                    event_key=hit_event_key,
                )
            )
            break
    return issues


def _path_from_payload(payload: dict[str, Any], key: str, default: Path) -> Path:
    value = payload.get(key)
    if value:
        return Path(str(value)).expanduser()
    return default.expanduser()


def _resolve_under(root: Path, value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return path
    return root / path


def _audit_payload(
    report_path: Path, issues: list[dict[str, Any]], mode_checks: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": not issues,
        "report_path": str(report_path),
        "issue_count": len(issues),
        "issues": issues,
        "modes": mode_checks,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit RAG ablation artifacts for summary, monitor, RAG, and structured-event integrity.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("report_path", help="Path to _rag_ablation.json")
    parser.add_argument(
        "--expected-modes", nargs="+", default=list(DEFAULT_EXPECTED_MODES)
    )
    parser.add_argument("--allow-unfinished", action="store_true")
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--allow-missing-rag", action="store_true")
    parser.add_argument("--output", help="Optional path for the audit JSON payload")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug, quiet=args.quiet)
    payload = audit_ablation_manifest(
        Path(args.report_path).expanduser(),
        expected_modes=tuple(args.expected_modes),
        require_finished=not args.allow_unfinished,
        require_attempts=not args.allow_empty,
        require_rag=not args.allow_missing_rag,
    )
    if args.output:
        output_path = Path(args.output).expanduser()
        write_json_file(output_path, payload)
        LOGGER.info(
            "RAG ablation audit written", extra={"output_path": str(output_path)}
        )
    write_json_stdout(payload)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
