"""Static HTML and JSON status output for batch runs."""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from killchain_docker.rag.status import public_rag_payload
from killchain_docker.logging_utils import get_logger, write_json_file, write_text_file
from killchain_docker.thread_status import build_thread_registry, thread_info


LOGGER = get_logger(__name__)
MONITOR_HTML_NAME = "_batch_monitor.html"
MONITOR_JSON_NAME = "_batch_monitor.json"
STATUS_SUFFIX = ".status.json"
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_PATH_KEYS = frozenset({"logfile", "status_file", "run_dir"})
_MONITOR_RESULT_KEYS = frozenset(
    {
        "challenge",
        "monitor_challenge",
        "replica",
        "run_id",
        "solved",
        "status",
        "finish_reason",
        "skip_reason",
        "runtime_sec",
        "rag_mode",
        "category",
        "files_count",
        "has_server",
        "server_type",
        "authorized_scope_count",
        "max_cycles",
        "token_usage",
        "state_metrics",
        "artifacts",
        "rag",
        "threads",
        "runtime_error",
        "error",
        "error_type",
        "logfile",
        "status_file",
        "failure_buckets",
    }
)
_MONITOR_TEXT_LIMIT = 360
_STATUS_CORE_FIELDS = frozenset(
    {
        "schema_version",
        "challenge",
        "pid",
        "thread_id",
        "thread_name",
        "status_writer_thread_id",
        "status_writer_thread_name",
        "threads",
        "stage",
        "status",
        "updated_at",
    }
)


def utc_timestamp(ts: float | None = None) -> str:
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time())
    )


def status_path_for_logfile(logfile: Path) -> Path:
    return logfile.with_suffix(STATUS_SUFFIX)


def relative_path(path: Path, root: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def monitor_path(path: Any, root: Path) -> str | None:
    """Return a frontend-safe relative path under *root*, or ``None``."""

    if not path:
        return None
    candidate = Path(str(path)).expanduser()
    if not candidate.is_absolute():
        posix = candidate.as_posix()
        if _URI_SCHEME_RE.match(posix):
            return None
        if "\\" in posix:
            return None
        if (
            posix == ".."
            or posix.startswith("../")
            or "/../" in posix
            or posix.endswith("/..")
        ):
            return None
        return posix
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _is_path_key(key: str) -> bool:
    return key in _PATH_KEYS or key.endswith(("_path", "_paths", "_dir", "_dirs"))


def _sanitize_path_value(value: Any, root: Path) -> Any:
    if isinstance(value, list):
        paths = [safe for item in value if (safe := monitor_path(item, root))]
        return paths or None
    return monitor_path(value, root)


def sanitize_monitor_paths(payload: dict[str, Any], root: Path) -> dict[str, Any]:
    """Return *payload* with frontend links normalized under *root* only."""

    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_path_key(key):
            safe = _sanitize_path_value(value, root)
            if safe:
                clean[key] = safe
            continue
        if isinstance(value, dict):
            clean[key] = sanitize_monitor_paths(value, root)
            continue
        if isinstance(value, list):
            clean[key] = [
                sanitize_monitor_paths(item, root) if isinstance(item, dict) else item
                for item in value
            ]
            continue
        clean[key] = value
    return clean


def compact_monitor_text(value: Any, *, limit: int = _MONITOR_TEXT_LIMIT) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"


def monitor_error(value: Any) -> dict[str, str] | None:
    if isinstance(value, dict):
        payload = {
            key: compact_monitor_text(value.get(key))
            for key in ("type", "message")
            if value.get(key)
        }
        return payload or None
    if value:
        return {"message": compact_monitor_text(value)}
    return None


def monitor_result(
    result: dict[str, Any] | None, logdir: Path
) -> dict[str, Any] | None:
    """Trim result payloads to fields the static monitor can safely link to."""

    if not isinstance(result, dict):
        return None
    payload = {
        key: value
        for key, value in result.items()
        if key in _MONITOR_RESULT_KEYS and value is not None
    }
    for key in ("error", "runtime_error"):
        error = monitor_error(payload.get(key))
        if error:
            payload[key] = error
        else:
            payload.pop(key, None)
    clean = sanitize_monitor_paths(payload, logdir)
    if isinstance(clean.get("rag"), dict):
        clean["rag"] = public_rag_payload(clean["rag"])
    return clean


def _status_error(extra: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("runtime_error", "error"):
        value = extra.get(key)
        if isinstance(value, dict):
            return value
    return None


def write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_file(path, payload)


def write_text(path: Path, payload: str) -> None:
    write_text_file(path, payload)


def write_run_status(
    path: Path,
    *,
    challenge: str,
    stage: str,
    status: str,
    **extra: Any,
) -> None:
    current_thread_id = threading.get_ident()
    current_thread_name = threading.current_thread().name
    observed = thread_info(current_thread_id, current_thread_name)
    status_writer = thread_info(current_thread_id, current_thread_name)
    threads = {
        "observed": observed,
        "status_writer": status_writer,
    }
    latest_event = extra.get("latest_event")
    if isinstance(latest_event, dict):
        threads["latest_event"] = thread_info(
            latest_event.get("thread_id"),
            latest_event.get("thread_name"),
        )
    threads["registry"] = build_thread_registry(
        challenge=challenge,
        stage=stage,
        status=status,
        pid=os.getpid(),
        observed=observed,
        status_writer=status_writer,
        latest_event=latest_event if isinstance(latest_event, dict) else None,
        current_todo=extra.get("current_todo")
        if isinstance(extra.get("current_todo"), dict)
        else None,
        runtime_error=_status_error(extra),
        message=extra.get("message"),
    )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "challenge": challenge,
        "pid": os.getpid(),
        "thread_id": current_thread_id,
        "thread_name": current_thread_name,
        "status_writer_thread_id": current_thread_id,
        "status_writer_thread_name": current_thread_name,
        "threads": threads,
        "stage": stage,
        "status": status,
        "updated_at": utc_timestamp(),
    }
    payload.update(
        {
            key: value
            for key, value in extra.items()
            if value is not None and key not in _STATUS_CORE_FIELDS
        }
    )
    payload = sanitize_monitor_paths(payload, path.parent)
    try:
        write_json(path, payload)
    except OSError:
        LOGGER.exception("failed to write run status", extra={"status_path": str(path)})


def build_monitor_snapshot(
    *,
    logdir: Path,
    challenge_names: list[str],
    results: list[dict[str, Any]],
    batch_start: float,
    active_runs: list[dict[str, Any]] | None = None,
    finished: bool = False,
) -> dict[str, Any]:
    def entry_name(item: dict[str, Any]) -> str:
        return str(item.get("monitor_challenge") or item.get("challenge"))

    completed = {entry_name(result): result for result in results}
    active_by_name = {entry_name(item): item for item in active_runs or []}
    entries: list[dict[str, Any]] = []

    for name in challenge_names:
        result = completed.get(name)
        active = active_by_name.get(name)
        status_file = None
        if result and result.get("status_file"):
            status_file = monitor_path(result["status_file"], logdir)
        elif active and active.get("status_file"):
            status_file = monitor_path(active["status_file"], logdir)
        else:
            status_file = monitor_path(f"{name}{STATUS_SUFFIX}", logdir)

        safe_result = monitor_result(result, logdir)
        safe_active = sanitize_monitor_paths(active, logdir) if active else None
        entries.append(
            {
                "challenge": name,
                "state": "completed" if result else ("active" if active else "queued"),
                "status_file": status_file,
                "result": safe_result,
                "active": safe_active,
            }
        )

    active_count = sum(1 for entry in entries if entry["state"] == "active")
    return {
        "schema_version": 1,
        "finished": finished,
        "updated_at": utc_timestamp(),
        "elapsed_sec": round(time.time() - batch_start, 3),
        "logdir": monitor_path(logdir, logdir) or ".",
        "summary_file": "_batch_summary.json",
        "counts": {
            "total": len(challenge_names),
            "completed": len(results),
            "active": active_count,
            "solved": sum(1 for result in results if result.get("solved")),
            "failed": sum(
                1
                for result in results
                if (
                    not result.get("solved")
                    and result.get("status") not in {"skipped", "interrupted"}
                )
            ),
            "skipped": sum(
                1 for result in results if result.get("status") == "skipped"
            ),
            "interrupted": sum(
                1 for result in results if result.get("status") == "interrupted"
            ),
        },
        "entries": entries,
    }


def write_batch_monitor(
    *,
    logdir: Path,
    challenge_names: list[str],
    results: list[dict[str, Any]],
    batch_start: float,
    active_runs: list[dict[str, Any]] | None = None,
    finished: bool = False,
) -> Path:
    write_batch_monitor_snapshot(
        logdir=logdir,
        challenge_names=challenge_names,
        results=results,
        batch_start=batch_start,
        active_runs=active_runs,
        finished=finished,
    )
    html_path = logdir / MONITOR_HTML_NAME
    write_text(html_path, render_monitor_html())
    return html_path


def write_batch_monitor_snapshot(
    *,
    logdir: Path,
    challenge_names: list[str],
    results: list[dict[str, Any]],
    batch_start: float,
    active_runs: list[dict[str, Any]] | None = None,
    finished: bool = False,
) -> Path:
    snapshot = build_monitor_snapshot(
        logdir=logdir,
        challenge_names=challenge_names,
        results=results,
        batch_start=batch_start,
        active_runs=active_runs,
        finished=finished,
    )
    json_path = logdir / MONITOR_JSON_NAME
    write_json(json_path, snapshot)
    return json_path


def render_monitor_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Killchain Batch Monitor</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fa;
      color: #1d252d;
      --panel: #ffffff;
      --panel-subtle: #f8fafc;
      --line: #d9e2ec;
      --muted: #667789;
      --accent: #0f766e;
    }
    body { margin: 0; }
    header { padding: 20px 24px 14px; background: var(--panel); border-bottom: 1px solid var(--line); }
    h1 { margin: 0 0 12px; font-size: 22px; font-weight: 650; letter-spacing: 0; }
    .stats { display: flex; flex-wrap: wrap; gap: 8px; align-items: stretch; }
    .stat { padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel-subtle); min-width: 110px; }
    .stat span { display: block; font-size: 11px; color: #607080; }
    .stat strong { display: block; font-size: 18px; margin-top: 2px; }
    .stat-details { border: 1px solid var(--line); border-radius: 6px; background: var(--panel-subtle); padding: 8px 10px; min-width: 150px; }
    .stat-details summary { cursor: pointer; font-size: 12px; color: var(--muted); }
    .stat-detail-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    main { padding: 18px 24px 28px; }
    .toolbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 12px; }
    .muted { color: var(--muted); font-size: 13px; }
    input { width: min(460px, 100%); padding: 9px 10px; border: 1px solid #cbd5df; border-radius: 6px; font: inherit; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .run-list { display: grid; gap: 12px; }
    .run-card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    .run-head { display: grid; grid-template-columns: minmax(220px, 1fr) auto; gap: 12px; padding: 14px 16px; border-bottom: 1px solid var(--line); align-items: start; }
    .run-title { min-width: 0; }
    .run-title strong { display: block; font-size: 15px; overflow-wrap: anywhere; }
    .run-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px; color: var(--muted); font-size: 12px; }
    .run-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
    .badge { display: inline-block; padding: 3px 7px; border-radius: 999px; font-size: 12px; border: 1px solid transparent; white-space: nowrap; }
    .running { background: #e8f3ff; color: #075985; border-color: #b7d8f6; }
    .solved { background: #e7f7ed; color: #166534; border-color: #b8e2c4; }
    .failed { background: #fdecec; color: #991b1b; border-color: #f2b8b8; }
    .interrupted { background: #fff1e8; color: #9a3412; border-color: #fdba74; }
    .queued { background: #f2f4f7; color: #475467; border-color: #d0d5dd; }
    .skipped { background: #fff5db; color: #92400e; border-color: #f4d58d; }
    .stale { background: #fff5db; color: #92400e; border-color: #f4d58d; }
    .current { padding: 12px 16px; display: grid; gap: 6px; border-bottom: 1px solid var(--line); }
    .current-label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
    .current-text { font-size: 14px; line-height: 1.45; overflow-wrap: anywhere; }
    .flow { padding: 12px 16px 14px; }
    .flow h2 { margin: 0 0 10px; font-size: 13px; font-weight: 650; letter-spacing: 0; color: #304050; }
    .timeline { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
    .timeline li { display: grid; grid-template-columns: 104px minmax(0, 1fr); gap: 10px; }
    .step-tag { color: var(--muted); font-size: 12px; padding-top: 2px; white-space: nowrap; }
    .step-body { border-left: 3px solid var(--line); padding-left: 10px; min-width: 0; }
    .step-title { font-weight: 650; font-size: 13px; }
    .step-text { color: #304050; font-size: 13px; line-height: 1.45; margin-top: 2px; overflow-wrap: anywhere; }
    .step-meta { color: var(--muted); font-size: 12px; margin-top: 4px; display: flex; flex-wrap: wrap; gap: 8px; }
    .details { padding: 0 16px 14px; }
    .details details { border-top: 1px solid var(--line); padding-top: 10px; }
    .details summary { cursor: pointer; color: var(--muted); font-size: 13px; }
    .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 10px; }
    .detail-block { background: var(--panel-subtle); border: 1px solid var(--line); border-radius: 6px; padding: 9px 10px; min-width: 0; }
    .detail-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }
    .detail-text { font-size: 12px; line-height: 1.45; overflow-wrap: anywhere; white-space: pre-line; }
    .links a { display: inline-block; margin-right: 8px; color: var(--accent); text-decoration: none; }
    .links a:hover { text-decoration: underline; }
    @media (prefers-color-scheme: dark) {
      :root {
        background: #121416;
        color: #e7edf2;
        --panel: #191d21;
        --panel-subtle: #15191d;
        --line: #303840;
        --muted: #a2afba;
      }
      header, .run-card { background: var(--panel); border-color: var(--line); }
      .stat, .stat-details, .detail-block { background: var(--panel-subtle); border-color: var(--line); }
      .run-head, .current, .details details { border-color: var(--line); }
      .flow h2, .step-text { color: #d3dde6; }
      input { background: #111820; color: #e5edf5; border-color: #3a4653; }
      .muted, .stat span { color: #9caeba; }
    }
    @media (max-width: 760px) {
      header, main { padding-left: 14px; padding-right: 14px; }
      .toolbar { display: grid; }
      .run-head { grid-template-columns: 1fr; }
      .run-actions { justify-content: flex-start; }
      .timeline li { grid-template-columns: 1fr; gap: 4px; }
      .step-body { border-left-width: 2px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Killchain Batch Monitor</h1>
    <div class="stats" id="stats"></div>
  </header>
  <main>
    <div class="toolbar">
      <input id="filter" type="search" placeholder="Filter challenges, workers, or status">
      <div class="muted" id="updated">Loading...</div>
    </div>
    <section class="run-list" id="rows"></section>
  </main>
  <script>
    const refreshMs = 3000;
    const staleAfterSec = 20;
    const filterInput = document.getElementById("filter");
    let lastRows = [];
    const failedStatuses = new Set([
      "failed",
      "worker_error",
      "load_error",
      "runtime_error",
      "unsolved_exhausted",
      "max_cycles_exhausted",
      "router_no_assignments",
      "todo_blocked",
      "partial_todos_unsolved",
      "completed",
      "stopped",
      "blocked",
      "partial"
    ]);

    function badgeClass(status, solved) {
      const normalized = String(status || "");
      if (solved) return "solved";
      if (normalized === "running" || normalized === "active" || normalized === "starting") return "running";
      if (normalized === "interrupted") return "interrupted";
      if (failedStatuses.has(normalized)) return "failed";
      if (normalized === "skipped") return "skipped";
      return "queued";
    }

    function fmtRuntime(value) {
      if (typeof value !== "number") return "";
      if (value < 60) return `${value.toFixed(1)}s`;
      return `${Math.floor(value / 60)}m ${(value % 60).toFixed(0)}s`;
    }

    function finiteNumber(value) {
      const number = Number(value);
      return Number.isFinite(number) ? number : null;
    }

    function fmtTokenUsage(value) {
      if (!value || typeof value !== "object") return "";
      const calls = finiteNumber(value.llm_calls);
      const total = finiteNumber(value.total_tokens);
      const parts = [];
      if (calls !== null) parts.push(`${calls} calls`);
      if (total !== null) parts.push(`${total} tok`);
      return parts.length ? `LLM ${parts.join(" / ")}` : "";
    }

    function sumTokenUsage(rows) {
      return rows.reduce((total, row) => {
        const usage = row.tokenUsage || {};
        total.llmCalls += finiteNumber(usage.llm_calls) || 0;
        total.totalTokens += finiteNumber(usage.total_tokens) || 0;
        return total;
      }, { llmCalls: 0, totalTokens: 0 });
    }

    function countEventLevels(rows) {
      return rows.reduce((total, row) => {
        const level = String(row.latestEventLevel || "").toUpperCase();
        if (level === "WARNING") total.warnings += 1;
        if (level === "ERROR" || level === "CRITICAL") total.errors += 1;
        return total;
      }, { warnings: 0, errors: 0 });
    }

    function countRagStatus(rows) {
      return rows.reduce((total, row) => {
        const rag = row.rag || {};
        if (rag.enabled) total.enabled += 1;
        if (rag.status === "hit") total.hits += 1;
        total.hints += finiteNumber(rag.hint_count) || 0;
        return total;
      }, { enabled: 0, hits: 0, hints: 0 });
    }

    function firstNonEmptyObject(...values) {
      return values.find((value) => (
        value && typeof value === "object" && Object.keys(value).length
      )) || {};
    }

    function firstPresent(...values) {
      return values.find((value) => value !== undefined && value !== null && value !== "");
    }

    function fmtRagKnowledge(rag) {
      if (!rag || typeof rag !== "object") return "";
      const label = rag.policy || rag.status || "";
      const hintCount = finiteNumber(rag.hint_count);
      const parts = [];
      if (label) parts.push(label);
      if (hintCount !== null) parts.push(`hints ${hintCount}`);
      return parts.join(" ");
    }

    function compactText(value, limit = 260) {
      const text = String(value || "").replace(/\\s+/g, " ").trim();
      if (text.length <= limit) return text;
      return text.slice(0, Math.max(0, limit - 15)).trimEnd() + "...[truncated]";
    }

    function metricNumber(metrics, names) {
      for (const name of names) {
        const value = finiteNumber(metrics && metrics[name]);
        if (value !== null) return value;
      }
      return null;
    }

    function fmtStateMetrics(metrics) {
      if (!metrics || typeof metrics !== "object") return "";
      const parts = [];
      const rounds = metricNumber(metrics, ["round_count", "rounds"]);
      const todos = metricNumber(metrics, ["todo_count", "todos"]);
      const open = metricNumber(metrics, ["open_todo_count", "open_todos"]);
      const evidence = metricNumber(metrics, ["evidence_count", "evidence"]);
      const flags = metricNumber(metrics, ["flag_candidates"]);
      if (rounds !== null) parts.push(`rounds ${rounds}`);
      if (todos !== null) parts.push(`todos ${todos}`);
      if (open !== null) parts.push(`open ${open}`);
      if (evidence !== null) parts.push(`evidence ${evidence}`);
      if (flags !== null) parts.push(`flags ${flags}`);

      const todoCounts = metrics.todo_status_counts || {};
      const statuses = Object.entries(todoCounts)
        .filter(([_status, count]) => finiteNumber(count))
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([status, count]) => `${status}=${count}`);
      if (statuses.length) parts.push(`todo ${statuses.join(",")}`);
      return parts.join(" / ");
    }

    function workerCountsText(metrics) {
      const counts = metrics && metrics.worker_counts;
      if (!counts || typeof counts !== "object") return "";
      return Object.entries(counts)
        .filter(([_worker, count]) => finiteNumber(count) !== null)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([worker, count]) => `${worker} ${count}`)
        .join(" / ");
    }

    function ageSeconds(value) {
      const ts = Date.parse(value || "");
      if (!Number.isFinite(ts)) return null;
      return Math.max(0, (Date.now() - ts) / 1000);
    }

    function fmtAge(value) {
      const age = ageSeconds(value);
      if (age === null) return "";
      if (age < 60) return `${age.toFixed(0)}s ago`;
      return fmtRuntime(age) + " ago";
    }

    function pollStatusText(snapshotUpdatedAt) {
      const parts = [`browser refresh ${new Date().toLocaleTimeString()}`, `polling ${(refreshMs / 1000).toFixed(0)}s`];
      if (snapshotUpdatedAt) parts.unshift(`snapshot ${snapshotUpdatedAt}`);
      return parts.join(" | ");
    }

    function liveness(row) {
      if (!["running", "starting", "active"].includes(row.status)) return "";
      if (row.statusError) return "stale";
      if (row.heartbeatAgeSec !== null && row.heartbeatAgeSec > staleAfterSec) return "stale";
      return "live";
    }

    function statusLabel(status, solved) {
      if (solved) return "solved";
      return String(status || "queued");
    }

    function isCurrentTodoStatus(status) {
      return ["running", "pending", "partial", "failed", "blocked", "interrupted"].includes(String(status || ""));
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      })[char]);
    }

    function isRelativeSafePath(value) {
      const raw = String(value || "");
      return raw
        && !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(raw)
        && !raw.startsWith("/")
        && !raw.includes("\\\\")
        && raw !== ".."
        && !raw.startsWith("../")
        && !raw.includes("/../")
        && !raw.endsWith("/..");
    }

    function safeLink(href, label) {
      if (!href) return "";
      const raw = String(href);
      let url;
      try {
        url = new URL(raw, window.location.href);
      } catch (_err) {
        return "";
      }
      if (window.location.protocol === "file:") {
        if (!isRelativeSafePath(raw) || url.protocol !== "file:") return "";
        return `<a href="${escapeHtml(raw)}">${escapeHtml(label)}</a>`;
      }
      if (!["http:", "https:"].includes(url.protocol)) return "";
      if (url.origin !== window.location.origin) return "";
      return `<a href="${escapeHtml(raw)}">${escapeHtml(label)}</a>`;
    }

    async function readJson(path) {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      return response.json();
    }

    async function readText(path) {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      if (typeof response.text !== "function") return "";
      return response.text();
    }

    async function loadStatus(entry) {
      if (entry.state === "queued") return null;
      if (!entry.status_file) return null;
      try {
        return await readJson(entry.status_file);
      } catch (err) {
        return { _status_error: err && err.message ? err.message : String(err) };
      }
    }

    function artifactPath(payload, key) {
      const artifacts = payload && payload.artifacts;
      return artifacts && artifacts[key] ? artifacts[key] : "";
    }

    async function loadEventTimeline(live, result) {
      const eventPath = firstPresent(
        artifactPath(live, "events_path"),
        artifactPath(result, "events_path")
      );
      if (!eventPath || !isRelativeSafePath(eventPath)) return [];
      try {
        const text = await readText(eventPath);
        return parseEventLog(text);
      } catch (_err) {
        return [];
      }
    }

    function parseEventLog(text) {
      return String(text || "")
        .split(/\\r?\\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          try {
            return JSON.parse(line);
          } catch (_err) {
            return null;
          }
        })
        .filter(Boolean)
        .filter(isTimelineEvent)
        .slice(-14)
        .map(timelineItemFromEvent);
    }

    function isTimelineEvent(event) {
      const type = String(event.event_type || "");
      if (["dispatch", "worker_progress", "worker_result", "planner", "router_summary", "flag_candidate_queued"].includes(type)) return true;
      const message = String(event.message || "");
      return /planning next todos|routing ready todos|validation|flag/i.test(message);
    }

    function eventCycle(event) {
      const context = event.context || {};
      if (context.cycle !== undefined && context.cycle !== null) return `cycle ${context.cycle}`;
      const match = String(event.message || "").match(/\\[cycle\\s+(\\d+)\\]/i);
      return match ? `cycle ${match[1]}` : "";
    }

    function extractTool(message) {
      const match = String(message || "").match(/\\b(?:selected|executing|completed)\\s+([A-Za-z0-9_.-]+)\\s+for step\\s+(\\d+)/i);
      if (!match) return { tool: "", step: "" };
      return { tool: match[1], step: match[2] };
    }

    function stripCyclePrefix(message) {
      return String(message || "")
        .replace(/^\\[cycle\\s+\\d+\\]\\s*/i, "")
        .replace(/^todo-[A-Za-z0-9]+:\\s*/i, "")
        .trim();
    }

    function timelineItemFromEvent(event) {
      const context = event.context || {};
      const type = String(event.event_type || "event");
      const message = String(event.message || "");
      const cycle = eventCycle(event);
      const worker = context.worker || "";
      const todo = context.todo_id || "";
      const phase = context.todo_phase || "";
      const status = context.todo_status || "";
      const toolInfo = extractTool(message);
      let title = type.replace(/_/g, " ");
      let text = stripCyclePrefix(message);

      if (type === "dispatch") {
        title = "Worker chosen";
        text = [todo, worker ? `to ${worker}` : ""].filter(Boolean).join(" ");
      } else if (type === "worker_progress" && /choosing tool/i.test(message)) {
        title = "Choosing tool";
        text = todo ? `${worker || "worker"} is selecting a tool for ${todo}` : text;
      } else if (type === "worker_progress" && /selected\\s+/i.test(message)) {
        title = "Tool selected";
        text = [toolInfo.tool, toolInfo.step ? `step ${toolInfo.step}` : "", worker].filter(Boolean).join(" / ");
      } else if (type === "worker_progress" && /executing\\s+/i.test(message)) {
        title = "Tool running";
        text = [toolInfo.tool, toolInfo.step ? `step ${toolInfo.step}` : "", worker].filter(Boolean).join(" / ");
      } else if (type === "worker_progress" && /completed\\s+/i.test(message)) {
        title = "Tool finished";
        text = [toolInfo.tool, toolInfo.step ? `step ${toolInfo.step}` : "", worker].filter(Boolean).join(" / ");
      } else if (type === "worker_result") {
        title = context.result_success === false ? "Worker result failed" : (context.result_partial ? "Worker result partial" : "Worker result");
        text = stripCyclePrefix(message).replace(/^(ok|FAILED|PARTIAL)\\s+todo-[A-Za-z0-9]+:\\s*/i, "");
      } else if (type === "planner") {
        title = "Plan";
      } else if (type === "router_summary") {
        title = "Worker summary";
      } else if (type === "flag_candidate_queued") {
        title = "Flag candidate queued";
      }

      return {
        key: event.sequence || `${type}-${message}`,
        cycle,
        title,
        text: compactText(text, 300),
        worker,
        tool: toolInfo.tool,
        todo,
        phase,
        status,
        level: event.level || "",
        at: event.timestamp || "",
      };
    }

    function fallbackTimeline(row) {
      const items = [];
      if (row.statusError) {
        items.push({ title: "Status read failed", text: `status read failed: ${row.statusError}`, cycle: "", level: "WARNING" });
      }
      if (row.current) {
        items.push({
          title: row.currentTitle || "Current step",
          text: row.current,
          cycle: row.currentCycle || "",
          worker: row.worker,
          phase: row.currentPhase || "",
          status: row.currentStatus || "",
        });
      }
      if (row.latestEvent) {
        const eventAge = row.latestEventAt ? ` ${fmtAge(row.latestEventAt)}` : "";
        const eventLevel = row.latestEventLevel ? `${row.latestEventLevel} ` : "";
        items.push({
          title: "Latest event",
          text: `${eventLevel}${row.latestEventType || "event"}${eventAge}: ${row.latestEvent}`,
          cycle: "",
          level: row.latestEventLevel || "",
        });
      }
      if (!items.length) {
        items.push({ title: statusLabel(row.status, row.solved), text: row.state === "queued" ? "Waiting for a worker slot" : "Waiting for status update", cycle: "" });
      }
      return items.slice(0, 5);
    }

    function artifactLinks(result, statusFile) {
      const links = [];
      if (statusFile) links.push(safeLink(statusFile, "status"));
      const artifacts = result && result.artifacts;
      if (artifacts && artifacts.compact_markdown_path) links.push(safeLink(artifacts.compact_markdown_path, "compact"));
      if (artifacts && artifacts.report_path) links.push(safeLink(artifacts.report_path, "report"));
      if (artifacts && artifacts.events_path) links.push(safeLink(artifacts.events_path, "events"));
      if (result && result.logfile) links.push(safeLink(result.logfile, "log"));
      return links.join("");
    }

    function threadRegistrySummary(row) {
      const registry = Array.isArray(row.threadRegistry) ? row.threadRegistry : [];
      return registry.map((entry) => {
        const roles = Array.isArray(entry.roles) ? entry.roles.join("+") : (entry.role || "thread");
        const id = entry.id !== undefined && entry.id !== null ? ` (${entry.id})` : "";
        const name = entry.name || "unknown";
        const todo = entry.current_todo || {};
        const event = entry.latest_event || {};
        const todoText = todo.todo_id
          ? `${todo.status || "todo"} ${todo.todo_id}${todo.worker ? ` -> ${todo.worker}` : ""}`
          : "";
        const eventLabel = event.event_type ? `${event.level || ""} ${event.event_type}`.trim() : "";
        const eventText = event.message ? `${eventLabel || "event"}: ${event.message}` : eventLabel;
        const details = [
          `${roles} ${name}${id}`,
          entry.status || "",
          todoText,
          eventText
        ].filter(Boolean);
        return details.join(" | ");
      }).filter(Boolean);
    }

    function threadSummary(row) {
      const registry = threadRegistrySummary(row);
      if (registry.length) return [...registry, row.worker || ""].filter(Boolean);
      const labeledThread = (label, id, name) => {
        if (id && name) return `${label} ${name} (${id})`;
        if (id) return `${label} ${id}`;
        if (name) return `${label} ${name}`;
        return "";
      };
      const threads = row.threads || {};
      const structured = [];
      if (threads.observed) structured.push(labeledThread("observed", threads.observed.id, threads.observed.name));
      if (threads.statusWriter) structured.push(labeledThread("writer", threads.statusWriter.id, threads.statusWriter.name));
      if (threads.latestEvent) structured.push(labeledThread("event", threads.latestEvent.id, threads.latestEvent.name));
      const structuredClean = structured.filter(Boolean);
      if (structuredClean.length) {
        return [
          row.pid ? `pid ${row.pid}` : "",
          ...structuredClean,
          row.worker || ""
        ].filter(Boolean);
      }
      return [
        row.pid ? `pid ${row.pid}` : "",
        labeledThread("run", row.threadId, row.threadName),
        row.writerThreadId !== row.threadId || row.writerThreadName !== row.threadName
          ? labeledThread("writer", row.writerThreadId, row.writerThreadName)
          : "",
        row.eventThreadId !== row.threadId || row.eventThreadName !== row.threadName
          ? labeledThread("event", row.eventThreadId, row.eventThreadName)
          : "",
        row.worker || ""
      ].filter(Boolean);
    }

    function detailBlock(label, text) {
      if (!text) return "";
      return `<div class="detail-block"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-text">${escapeHtml(text)}</div></div>`;
    }

    function linkDetailBlock(result, statusFile) {
      const html = artifactLinks(result, statusFile);
      if (!html) return "";
      return `<div class="detail-block"><div class="detail-label">Artifacts</div><div class="detail-text links">${html}</div></div>`;
    }

    function renderTimelineItem(item) {
      const meta = [
        item.worker ? `worker ${item.worker}` : "",
        item.tool ? `tool ${item.tool}` : "",
        item.todo || "",
        item.phase || "",
        item.status || "",
        item.level && item.level !== "INFO" ? item.level : "",
      ].filter(Boolean);
      const tag = item.cycle || (item.at ? fmtAge(item.at) : "");
      return `<li>
        <div class="step-tag">${escapeHtml(tag)}</div>
        <div class="step-body">
          <div class="step-title">${escapeHtml(item.title || "Event")}</div>
          <div class="step-text">${escapeHtml(item.text || "")}</div>
          ${meta.length ? `<div class="step-meta">${meta.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>` : ""}
        </div>
      </li>`;
    }

    function currentText(row) {
      if (row.current) return row.current;
      if (row.state === "queued") return "Waiting for a worker slot";
      return statusLabel(row.status, row.solved);
    }

    function renderRows() {
      const needle = filterInput.value.trim().toLowerCase();
      const rows = lastRows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle));
      document.getElementById("rows").innerHTML = rows.map((row) => {
        const status = row.solved ? "solved" : row.status;
        const klass = badgeClass(status, row.solved);
        const knowledgeText = row.knowledge ? `knowledge ${row.knowledge}` : "";
        const threads = threadSummary(row);
        const livenessText = liveness(row);
        const stateAgeText = row.stateUpdatedAt ? `state ${fmtAge(row.stateUpdatedAt)}` : "";
        const heartbeatText = row.updatedAt ? `heartbeat ${fmtAge(row.updatedAt)}` : "";
        const tokenText = fmtTokenUsage(row.tokenUsage);
        const eventParts = [];
        if (row.statusError) eventParts.push(`status read failed: ${row.statusError}`);
        if (row.latestEvent) {
          const eventAge = row.latestEventAt ? ` ${fmtAge(row.latestEventAt)}` : "";
          const eventLevel = row.latestEventLevel ? `${row.latestEventLevel} ` : "";
          eventParts.push(`${eventLevel}${row.latestEventType || "event"}${eventAge}: ${row.latestEvent}`);
        }
        const eventText = eventParts.join(" | ");
        const metricsText = row.metricsText || "";
        const workerText = row.worker || row.primaryWorker || "";
        const timeline = row.timeline && row.timeline.length ? row.timeline : fallbackTimeline(row);
        const detailHtml = [
          detailBlock("Knowledge", knowledgeText),
          detailBlock("Runtime", [fmtRuntime(row.runtimeSec), tokenText].filter(Boolean).join(" / ")),
          detailBlock("Metrics", metricsText),
          detailBlock("Workers", row.workerCountsText),
          detailBlock("Latest event", eventText),
          detailBlock("Technical threads", threads.join("\\n")),
          detailBlock("Heartbeat", [heartbeatText, stateAgeText].filter(Boolean).join(" / ")),
          linkDetailBlock(row.result, row.statusFile),
        ].filter(Boolean).join("");
        return `<article class="run-card">
          <div class="run-head">
            <div class="run-title">
              <strong>${escapeHtml(row.challenge)}</strong>
              <div class="run-meta">
                <span>${escapeHtml(row.stage || row.state)}</span>
                ${row.runId ? `<code>${escapeHtml(row.runId)}</code>` : ""}
                ${fmtRuntime(row.runtimeSec) ? `<span>${fmtRuntime(row.runtimeSec)}</span>` : ""}
                ${workerText ? `<span>${escapeHtml(workerText)}</span>` : ""}
              </div>
            </div>
            <div class="run-actions">
              <span class="badge ${klass}">${escapeHtml(status)}</span>
              ${livenessText ? ` <span class="badge ${livenessText === "stale" ? "stale" : "running"}">${escapeHtml(livenessText)}</span>` : ""}
            </div>
          </div>
          <div class="current">
            <div class="current-label">Current</div>
            <div class="current-text">${escapeHtml(currentText(row))}</div>
          </div>
          <div class="flow">
            <h2>Flow</h2>
            <ul class="timeline">${timeline.map(renderTimelineItem).join("")}</ul>
          </div>
          ${detailHtml ? `<div class="details"><details><summary>Details</summary><div class="detail-grid">${detailHtml}</div></details></div>` : ""}
        </article>`;
      }).join("");
    }

    async function refresh() {
      try {
        const snapshot = await readJson("_batch_monitor.json");
        const statuses = await Promise.all(snapshot.entries.map(loadStatus));
        lastRows = await Promise.all(snapshot.entries.map(async (entry, index) => {
          const active = entry.active || {};
          const result = entry.result || {};
          const live = statuses[index] || {};
          const statusError = live._status_error || "";
          const metrics = result.state_metrics || live.state_metrics || {};
          const todos = metrics.todo_status_counts || {};
          const todo = live.current_todo || {};
          const latestEvent = live.latest_event || {};
          const runtimeError = live.runtime_error || result.runtime_error || {};
          const runError = live.error || result.error || {};
          const activeThreads = active.threads || {};
          const tokenUsage = live.token_usage || result.token_usage || {};
          const rag = firstNonEmptyObject(live.rag, result.rag);
          const threads = live.threads || {};
          const threadRegistry = Array.isArray(threads.registry)
            ? threads.registry
            : (Array.isArray(activeThreads.registry) ? activeThreads.registry : []);
          const todoText = todo.goal && isCurrentTodoStatus(todo.status)
            ? `${todo.status || ""} ${todo.todo_id || ""}: ${todo.goal}`
            : "";
          const errorText = runtimeError.type ? `${runtimeError.type}: ${runtimeError.message || ""}` : "";
          const runErrorText = (runError.type || runError.message)
            ? `${runError.type || "Error"}: ${runError.message || ""}`
            : "";
          const current = todoText || errorText || runErrorText || live.message || result.skip_reason || result.status || "";
          const effectiveResult = Object.keys(result).length ? result : {
            artifacts: live.artifacts,
            logfile: live.logfile
          };
          const workerEntry = threadRegistry.find((item) => item && item.worker);
          const timeline = await loadEventTimeline(live, effectiveResult);
          return {
            challenge: entry.challenge,
            state: entry.state,
            status: firstPresent(result.status, live.status, active.status, entry.state),
            solved: Boolean(firstPresent(result.solved, live.solved, false)),
            stage: live.stage || active.stage || entry.state,
            knowledge: fmtRagKnowledge(rag),
            rag,
            runtimeSec: firstPresent(result.runtime_sec, live.runtime_sec, active.runtime_sec),
            tokenUsage,
            pid: firstPresent(live.pid, active.pid),
            threadId: firstPresent(live.thread_id, active.thread_id, live.latest_event && live.latest_event.thread_id),
            threadName: firstPresent(live.thread_name, active.thread_name, live.latest_event && live.latest_event.thread_name),
            writerThreadId: firstPresent(live.status_writer_thread_id, active.status_writer_thread_id),
            writerThreadName: firstPresent(live.status_writer_thread_name, active.status_writer_thread_name),
            eventThreadId: live.latest_event && live.latest_event.thread_id,
            eventThreadName: live.latest_event && live.latest_event.thread_name,
            threads: {
              observed: threads.observed || activeThreads.observed,
              statusWriter: threads.status_writer || activeThreads.status_writer,
              latestEvent: threads.latest_event,
              registry: threadRegistry
            },
            threadRegistry,
            worker: live.worker || active.worker || "",
            primaryWorker: firstPresent(todo.worker, workerEntry && workerEntry.worker, ""),
            current: current || active.message || "",
            currentTitle: todo.todo_id ? "Current todo" : "",
            currentPhase: todo.phase || "",
            currentStatus: todo.status || "",
            currentCycle: "",
            metricsText: fmtStateMetrics(metrics),
            workerCountsText: workerCountsText(metrics),
            latestEvent: latestEvent.message || "",
            latestEventType: latestEvent.event_type || "",
            latestEventLevel: latestEvent.level || "",
            latestEventAt: latestEvent.timestamp || "",
            statusError,
            runId: firstPresent(result.run_id, live.run_id),
            updatedAt: firstPresent(live.updated_at, snapshot.updated_at),
            heartbeatAgeSec: ageSeconds(firstPresent(live.updated_at, snapshot.updated_at)),
            stateUpdatedAt: firstPresent(live.state_updated_at, ""),
            statusFile: entry.status_file,
            result: effectiveResult,
            timeline
          };
        }));
        const counts = snapshot.counts || {};
        const liveActive = lastRows.filter((row) => ["running", "starting", "active"].includes(row.status)).length;
        const staleRows = lastRows.filter((row) => liveness(row) === "stale").length;
        const tokenTotals = sumTokenUsage(lastRows);
        const eventLevels = countEventLevels(lastRows);
        const ragTotals = countRagStatus(lastRows);
        const primaryStats = [
          ["Total", counts.total],
          ["Completed", counts.completed],
          ["Active", Number.isFinite(liveActive) ? liveActive : counts.active],
          ["Stale", staleRows],
          ["Solved", counts.solved],
          ["Failed", counts.failed],
          ["Interrupted", counts.interrupted],
          ["Elapsed", fmtRuntime(snapshot.elapsed_sec)]
        ];
        const secondaryStats = [
          ["Warnings", eventLevels.warnings],
          ["Errors", eventLevels.errors],
          ["Skipped", counts.skipped],
          ["RAG On", ragTotals.enabled],
          ["RAG Hits", ragTotals.hits],
          ["RAG Hints", ragTotals.hints],
          ["LLM Calls", tokenTotals.llmCalls],
          ["LLM Tokens", tokenTotals.totalTokens]
        ];
        const statCard = ([label, value]) => `<div class="stat"><span>${label}</span><strong>${value ?? 0}</strong></div>`;
        document.getElementById("stats").innerHTML = [
          ...primaryStats.map(statCard),
          `<details class="stat-details"><summary>Details</summary><div class="stat-detail-grid">${secondaryStats.map(statCard).join("")}</div></details>`
        ].join("");
        document.getElementById("updated").textContent = pollStatusText(snapshot.updated_at);
        renderRows();
      } catch (err) {
        document.getElementById("updated").textContent = `Monitor read failed: ${err.message} | ${pollStatusText("")}`;
      }
    }

    filterInput.addEventListener("input", renderRows);
    refresh();
    setInterval(refresh, refreshMs);
  </script>
</body>
</html>
"""
