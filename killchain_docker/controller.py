"""Top-level run controller for assembling and executing a session."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from killchain_docker.knowledge import KnowledgeAugmenter, public_rag_payload, rag_mode
from killchain_docker.logging_utils import (
    get_logger,
    json_dumps,
    json_sanitize,
    safe_extra,
    write_json_file,
    write_text_file,
)
from killchain_docker.llm import LLMClient, LLMClientError, TokenLedger, build_llm_client_from_env
from killchain_docker.orchestrator import (
    LLMPlanner,
    Orchestrator,
    RouterAgent,
)
from killchain_docker.reporting import render_markdown_report
from killchain_docker.state import RunState, RunStatus
from killchain_docker.thread_status import build_thread_registry, thread_info
from killchain_docker.tools import ExecutionPlane, build_execution_plane
from killchain_docker.workers import WorkerBuildContext, build_builtin_workers


LOGGER = get_logger(__name__)
STATUS_HEARTBEAT_INTERVAL_S = 5.0
_TERMINAL_RUN_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.SOLVED,
    RunStatus.FAILED,
    RunStatus.STOPPED,
    RunStatus.INTERRUPTED,
}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_file(path, payload)


def _write_text(path: Path, payload: str) -> None:
    write_text_file(path, payload)


def _record_runtime_exception(state: RunState, exc: BaseException) -> None:
    error = {
        "type": type(exc).__name__,
        "message": str(exc).strip() or type(exc).__name__,
    }
    state.metadata["runtime_error"] = error

    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        if state.status not in _TERMINAL_RUN_STATUSES:
            state.status = RunStatus.INTERRUPTED
        state.stop_reason = state.stop_reason or "interrupted"
        note = f"run interrupted by {error['type']}"
    else:
        if state.status not in _TERMINAL_RUN_STATUSES:
            state.status = RunStatus.FAILED
        state.stop_reason = state.stop_reason or (
            "llm_error" if isinstance(exc, LLMClientError) else "runtime_error"
        )
        note = f"run failed with {error['type']}: {error['message']}"

    if note not in state.orchestration_notes:
        state.orchestration_notes.append(note)


def _runtime_error_payload(state: RunState) -> dict[str, Any] | None:
    payload = state.metadata.get("runtime_error")
    return dict(payload) if isinstance(payload, dict) else None


_COMPACT_TEXT_LIMIT = 360
_COMPACT_GOAL_LIMIT = 260
_COMPACT_TIMELINE_LIMIT = 80


def _compact_text(value: object, *, limit: int = _COMPACT_TEXT_LIMIT) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"


def _todo_status_counts(state: RunState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for todo in state.todos:
        key = str(todo.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _worker_counts(state: RunState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for todo in state.todos:
        key = str(todo.assigned_worker or "unassigned")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _current_status_todo(state: RunState) -> Any | None:
    if not state.todos:
        return None
    for todo in reversed(state.todos):
        if str(todo.status) == "running":
            return todo
    for todo in reversed(state.todos):
        if str(todo.status) in {"pending", "partial", "failed", "blocked", "interrupted"}:
            return todo
    return None


def _compact_todos(state: RunState) -> list[dict[str, object]]:
    interesting_statuses = {"pending", "running", "partial", "failed", "blocked", "interrupted"}
    selected = [
        todo for todo in state.todos
        if str(todo.status) in interesting_statuses
    ]
    if len(selected) < 20:
        seen = {todo.todo_id for todo in selected}
        for todo in state.todos[-20:]:
            if todo.todo_id not in seen:
                selected.append(todo)
    return [
        {
            "todo_id": todo.todo_id,
            "phase": str(todo.phase),
            "status": str(todo.status),
            "worker": todo.assigned_worker,
            "attempts": todo.attempts,
            "family": str(todo.context.get("family") or ""),
            "goal": _compact_text(todo.goal, limit=_COMPACT_GOAL_LIMIT),
            "result": _compact_text(todo.result_summary),
            "error": _compact_text(todo.error),
        }
        for todo in selected[-40:]
    ]


def _compact_rounds(state: RunState) -> list[dict[str, object]]:
    timeline: list[dict[str, object]] = []
    for round_record in state.rounds[-_COMPACT_TIMELINE_LIMIT:]:
        timeline.append({
            "cycle": round_record.cycle,
            "planner_summary": _compact_text(round_record.planner_summary),
            "assignments": [
                {
                    "todo_id": assignment.todo_id,
                    "worker": assignment.worker_name,
                    "rationale": _compact_text(assignment.rationale, limit=180),
                }
                for assignment in round_record.assignments
            ],
            "results": [
                {
                    "todo_id": result.todo_id,
                    "worker": result.worker_name,
                    "success": result.success,
                    "partial": result.partial,
                    "quality": result.result_quality,
                    "summary": _compact_text(result.summary),
                    "error": _compact_text(result.error or result.partial_reason),
                    "flag_candidates": len(result.state_delta.flag_candidates) if result.state_delta else 0,
                    "notes": [_compact_text(note, limit=220) for note in result.notes[:3]],
                }
                for result in round_record.results
            ],
            "router_summary": _compact_text(round_record.summary.summary),
            "key_findings": [
                _compact_text(item, limit=260)
                for item in round_record.summary.key_findings[:5]
            ],
            "next_focus": _compact_text(round_record.summary.next_focus),
        })
    return timeline


def build_compact_run_log(
    state: RunState,
    *,
    events: list[str] | None = None,
    token_ledger: TokenLedger | None = None,
) -> dict[str, Any]:
    """Return an LLM-readable run timeline without large stdout/stderr blobs."""

    challenge = state.metadata.get("challenge", {}) or {}
    flags = [
        {
            "value": candidate.value,
            "source": candidate.source,
            "confidence": candidate.confidence,
            "validated": candidate.validated,
            "rejected_reason": candidate.rejected_reason,
        }
        for candidate in state.flag_candidates.values()
    ]
    hypotheses = [
        {
            "title": _compact_text(item.title),
            "status": item.status,
            "confidence": item.confidence,
            "category": item.category,
        }
        for item in state.hypotheses.values()
    ][-20:]
    payload: dict[str, Any] = {
        "schema_version": 1,
        "purpose": "Compact run log for humans and LLMs. See state.json/evidence.json for full stdout, stderr, and raw tool payloads.",
        "run": {
            "run_id": state.run_id,
            "status": str(state.status),
            "stop_reason": state.stop_reason,
            "solved": state.solved,
            "validated_flag": state.validated_flag,
            "runtime_error": _runtime_error_payload(state),
            "created_at": state.created_at.isoformat(),
            "updated_at": state.updated_at.isoformat(),
            "last_cycle_at": state.last_cycle_at.isoformat() if state.last_cycle_at else None,
        },
        "challenge": {
            "canonical_name": challenge.get("canonical_name"),
            "name": challenge.get("name"),
            "category": challenge.get("category"),
            "flag_format": challenge.get("flag_format"),
            "files": challenge.get("files") or [],
            "server_name": challenge.get("server_name"),
            "port": challenge.get("port"),
        },
        "counts": {
            **state.summary(),
            "todo_status_counts": _todo_status_counts(state),
            "worker_counts": _worker_counts(state),
        },
        "rag": public_rag_payload(state.metadata.get("rag")) or {},
        "flag_candidates": flags,
        "working_memory": {
            key: _compact_text(value, limit=260)
            for key, value in list(state.working_memory.items())[-30:]
        },
        "hypotheses_tail": hypotheses,
        "open_or_recent_todos": _compact_todos(state),
        "timeline": _compact_rounds(state),
        "orchestration_notes_tail": [
            _compact_text(note, limit=300)
            for note in state.orchestration_notes[-30:]
        ],
        "events_tail": [
            _compact_text(message, limit=300)
            for message in (events or [])[-80:]
        ],
        "full_artifacts": {
            "state": "state.json",
            "evidence": "evidence.json",
            "events": "events.log",
            "report": "report.md",
        },
    }
    if token_ledger is not None:
        payload["token_usage"] = token_ledger.to_dict()
    return payload


def render_compact_run_markdown(payload: dict[str, Any]) -> str:
    run = payload.get("run") or {}
    challenge = payload.get("challenge") or {}
    counts = payload.get("counts") or {}
    lines = [
        "# Compact Run Log",
        "",
        "This is the LLM-readable timeline. Full raw outputs remain in `state.json`, `evidence.json`, and `events.log`.",
        "",
        "## Run",
        "",
        f"- Run ID: `{run.get('run_id')}`",
        f"- Challenge: `{challenge.get('canonical_name') or challenge.get('name')}` ({challenge.get('category')})",
        f"- Status: `{run.get('status')}` stop_reason=`{run.get('stop_reason')}` solved=`{run.get('solved')}`",
        f"- Validated flag: `{run.get('validated_flag')}`",
        f"- Updated: `{run.get('updated_at')}`",
        f"- Counts: rounds={counts.get('rounds')} todos={counts.get('todos')} open={counts.get('open_todos')} evidence={counts.get('evidence')} flags={counts.get('flag_candidates')}",
        f"- Todo statuses: `{counts.get('todo_status_counts')}`",
        "",
    ]
    runtime_error = run.get("runtime_error")
    if isinstance(runtime_error, dict):
        lines.extend([
            "- Runtime error: "
            f"`{runtime_error.get('type')}` {runtime_error.get('message')}",
            "",
        ])
    rag = payload.get("rag")
    if isinstance(rag, dict) and rag:
        lines.extend([
            "## RAG",
            "",
            f"- Enabled: `{rag.get('enabled')}` status=`{rag.get('status')}` policy=`{rag.get('policy')}` hints={rag.get('hint_count')}",
            "",
        ])

    token_usage = payload.get("token_usage")
    if isinstance(token_usage, dict):
        lines.extend([
            "## Token Usage",
            "",
            f"- Calls: {token_usage.get('llm_calls')} prompt={token_usage.get('prompt_tokens')} completion={token_usage.get('completion_tokens')} total={token_usage.get('total_tokens')}",
            "",
        ])

    flags = payload.get("flag_candidates") or []
    lines.extend(["## Flag Candidates", ""])
    if flags:
        for item in flags:
            lines.append(
                f"- `{item.get('value')}` source={item.get('source')} confidence={item.get('confidence')} validated={item.get('validated')} rejected={item.get('rejected_reason')}"
            )
    else:
        lines.append("- None accepted into state.")
    lines.append("")

    memory = payload.get("working_memory") or {}
    lines.extend(["## Working Memory", ""])
    if memory:
        for key, value in memory.items():
            lines.append(f"- `{key}`: {value}")
    else:
        lines.append("- Empty.")
    lines.append("")

    lines.extend(["## Timeline", ""])
    timeline = payload.get("timeline") or []
    if timeline:
        for item in timeline:
            lines.append(f"### Cycle {item.get('cycle')}")
            lines.append("")
            lines.append(f"- Plan: {item.get('planner_summary')}")
            for assignment in item.get("assignments") or []:
                lines.append(f"- Dispatch: `{assignment.get('todo_id')}` -> `{assignment.get('worker')}`")
            for result in item.get("results") or []:
                lines.append(
                    f"- Result: `{result.get('todo_id')}` `{result.get('worker')}` success={result.get('success')} partial={result.get('partial')} quality={result.get('quality')} flags={result.get('flag_candidates')} :: {result.get('summary')}"
                )
                if result.get("error"):
                    lines.append(f"  Error: {result.get('error')}")
            if item.get("router_summary"):
                lines.append(f"- Router: {item.get('router_summary')}")
            if item.get("next_focus"):
                lines.append(f"- Next focus: {item.get('next_focus')}")
            lines.append("")
    else:
        lines.append("- No rounds recorded yet.")
        lines.append("")

    todos = payload.get("open_or_recent_todos") or []
    lines.extend(["## Open Or Recent Todos", ""])
    if todos:
        for todo in todos:
            lines.append(
                f"- `{todo.get('todo_id')}` status={todo.get('status')} phase={todo.get('phase')} worker={todo.get('worker')} attempts={todo.get('attempts')} family={todo.get('family')} :: {todo.get('goal')}"
            )
            if todo.get("result"):
                lines.append(f"  Result: {todo.get('result')}")
            if todo.get("error"):
                lines.append(f"  Error: {todo.get('error')}")
    else:
        lines.append("- None.")
    lines.append("")

    notes = payload.get("orchestration_notes_tail") or []
    lines.extend(["## Notes Tail", ""])
    if notes:
        lines.extend(f"- {note}" for note in notes)
    else:
        lines.append("- None.")
    lines.append("")

    lines.extend(["## Events Tail", ""])
    for message in payload.get("events_tail") or []:
        lines.append(f"- {message}")
    if not payload.get("events_tail"):
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


class RunPersister:
    """Owns disk paths for one run and writes them lazily.

    ``write_state`` is the cheap checkpoint (state.json + events.log) called
    after every orchestrator cycle so a crash never wipes mid-run progress.
    ``write_all`` is the full snapshot called from controller.run_assessment's
    ``finally`` block to guarantee state/summary/report/evidence/events all
    land on disk regardless of whether ``orchestrator.run`` raised.
    """

    def __init__(
        self,
        run_dir: Path,
        recorder: EventRecorder,
        status_path: Path | None = None,
        token_ledger: TokenLedger | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.recorder = recorder
        self.status_path = status_path
        self.token_ledger = token_ledger
        self._lock = threading.RLock()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = run_dir / "config.json"
        self.state_path = run_dir / "state.json"
        self.summary_path = run_dir / "summary.json"
        self.report_path = run_dir / "report.md"
        self.events_path = run_dir / "events.log"
        self.evidence_path = run_dir / "evidence.json"
        self.compact_json_path = run_dir / "compact_log.json"
        self.compact_markdown_path = run_dir / "compact_log.md"

    def _status_link(self, path: Path) -> str | None:
        root = self.status_path.parent if self.status_path else self.run_dir
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return None

    def _status_artifacts(self) -> dict[str, str]:
        paths = {
            "config_path": self.config_path,
            "state_path": self.state_path,
            "summary_path": self.summary_path,
            "report_path": self.report_path,
            "events_path": self.events_path,
            "evidence_path": self.evidence_path,
            "compact_json_path": self.compact_json_path,
            "compact_markdown_path": self.compact_markdown_path,
        }
        return {
            key: link
            for key, path in paths.items()
            if (link := self._status_link(path))
        }

    def _token_usage(self) -> dict[str, int] | None:
        if self.token_ledger is None:
            return None
        return self.token_ledger.to_dict()

    def _status_payload(self, state: RunState, *, stage: str) -> dict[str, Any]:
        challenge = state.metadata.get("challenge", {}) or {}
        status_todo = _current_status_todo(state)
        messages = self.recorder.messages
        records = self.recorder.records
        latest_event = records[-1] if records else None
        now = datetime.now(timezone.utc)
        latest_thread_id = (
            latest_event.get("thread_id")
            if isinstance(latest_event, dict) and latest_event.get("thread_id") is not None
            else threading.get_ident()
        )
        latest_thread_name = (
            latest_event.get("thread_name")
            if isinstance(latest_event, dict) and latest_event.get("thread_name") is not None
            else threading.current_thread().name
        )
        writer_thread_id = threading.get_ident()
        writer_thread_name = threading.current_thread().name
        threads: dict[str, Any] = {
            "observed": thread_info(latest_thread_id, latest_thread_name),
            "status_writer": thread_info(writer_thread_id, writer_thread_name),
        }
        current_todo = None if status_todo is None else {
            "todo_id": status_todo.todo_id,
            "phase": str(status_todo.phase),
            "status": str(status_todo.status),
            "worker": status_todo.assigned_worker,
            "attempts": status_todo.attempts,
            "goal": _compact_text(status_todo.goal, limit=_COMPACT_GOAL_LIMIT),
            "result": _compact_text(status_todo.result_summary),
            "error": _compact_text(status_todo.error),
        }
        latest_event_payload = None
        if latest_event:
            threads["latest_event"] = thread_info(
                latest_event.get("thread_id"),
                latest_event.get("thread_name"),
            )
            latest_event_payload = {
                "sequence": latest_event.get("sequence"),
                "timestamp": latest_event.get("timestamp"),
                "level": latest_event.get("level"),
                "event_type": latest_event.get("event_type"),
                "thread_id": latest_event.get("thread_id"),
                "thread_name": latest_event.get("thread_name"),
                "message": _compact_text(latest_event.get("message")),
            }
        runtime_error = _runtime_error_payload(state)
        message = messages[-1] if messages else None
        threads["registry"] = build_thread_registry(
            challenge=str(challenge.get("canonical_name") or challenge.get("name") or ""),
            stage=stage,
            status=str(state.status),
            pid=os.getpid(),
            observed=threads["observed"],
            status_writer=threads["status_writer"],
            latest_event=latest_event_payload,
            current_todo=current_todo,
            runtime_error=runtime_error,
            message=message,
            recent_events=records,
        )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "challenge": challenge.get("canonical_name") or challenge.get("name"),
            "pid": os.getpid(),
            "thread_id": latest_thread_id,
            "thread_name": latest_thread_name,
            "status_writer_thread_id": writer_thread_id,
            "status_writer_thread_name": writer_thread_name,
            "threads": threads,
            "stage": stage,
            "status": str(state.status),
            "run_id": state.run_id,
            "solved": state.solved,
            "stop_reason": state.stop_reason,
            "updated_at": now.isoformat(),
            "state_updated_at": state.updated_at.isoformat(),
            "last_cycle_at": state.last_cycle_at.isoformat() if state.last_cycle_at else None,
            "runtime_sec": round(max(0.0, (now - state.created_at).total_seconds()), 3),
            "message": message,
            "worker": status_todo.assigned_worker if status_todo else None,
            "current_todo": current_todo,
            "state_metrics": {
                **state.summary(),
                "todo_status_counts": _todo_status_counts(state),
                "worker_counts": _worker_counts(state),
            },
            "runtime_error": runtime_error,
            "rag": public_rag_payload(state.metadata.get("rag")),
            "artifacts": self._status_artifacts(),
        }
        token_usage = self._token_usage()
        if token_usage is not None:
            payload["token_usage"] = token_usage
        if latest_event_payload:
            payload["latest_event"] = latest_event_payload
        run_dir = self._status_link(self.run_dir)
        if run_dir:
            payload["run_dir"] = run_dir
        return payload

    def write_runtime_status(self, state: RunState, *, stage: str) -> None:
        if self.status_path is None:
            return
        with self._lock:
            _write_json(self.status_path, self._status_payload(state, stage=stage))

    def write_config(self, config: RunConfig) -> None:
        with self._lock:
            _write_json(self.config_path, config.model_dump(mode="json"))

    def _write_events(self) -> None:
        lines = [
            json_dumps(record, indent=None, sort_keys=True)
            for record in self.recorder.records
        ]
        suffix = "\n" if lines else ""
        _write_text(self.events_path, "\n".join(lines) + suffix)

    def _write_compact(self, state: RunState) -> None:
        payload = build_compact_run_log(
            state,
            events=list(self.recorder.messages),
            token_ledger=self.token_ledger,
        )
        _write_json(self.compact_json_path, payload)
        _write_text(self.compact_markdown_path, render_compact_run_markdown(payload))

    def write_state(self, state: RunState) -> None:
        try:
            with self._lock:
                _write_json(self.state_path, state.model_dump(mode="json"))
                self._write_events()
                self._write_compact(state)
                self.write_runtime_status(state, stage="assessment")
        except Exception as exc:
            LOGGER.exception(
                "checkpoint write failed",
                extra={"run_dir": str(self.run_dir), "status_path": str(self.status_path) if self.status_path else None},
            )
            self.recorder.emit(
                f"[persister] checkpoint write failed: {type(exc).__name__}: {exc}",
                level=logging.ERROR,
                event_type="persistence",
            )

    def write_all(self, state: RunState) -> None:
        with self._lock:
            _write_json(self.state_path, state.model_dump(mode="json"))
            summary = state.summary()
            summary["objective"] = state.objective
            summary["authorized_scope"] = state.authorized_scope
            summary["worker_notes"] = len(state.notes)
            summary["orchestration_notes"] = len(state.orchestration_notes)
            runtime_error = _runtime_error_payload(state)
            if runtime_error is not None:
                summary["runtime_error"] = runtime_error
            public_rag = public_rag_payload(state.metadata.get("rag"))
            if public_rag is not None:
                summary["rag"] = public_rag
            token_usage = self._token_usage()
            if token_usage is not None:
                summary["token_usage"] = token_usage
            _write_json(self.summary_path, summary)
            _write_json(
                self.evidence_path,
                {
                    "evidence": {
                        key: value.model_dump(mode="json")
                        for key, value in sorted(state.evidence.items(), key=lambda item: item[0])
                    }
                },
            )
            _write_text(self.report_path, render_markdown_report(state))
            self._write_events()
            self._write_compact(state)
            self.write_runtime_status(state, stage="complete")


class RuntimeStatusHeartbeat:
    """Periodically refresh live status while the orchestrator is blocked."""

    def __init__(
        self,
        persister: RunPersister,
        state: RunState,
        *,
        interval_s: float = STATUS_HEARTBEAT_INTERVAL_S,
    ) -> None:
        self.persister = persister
        self.state = state
        self.interval_s = max(0.0, float(interval_s))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.persister.status_path is None or self.interval_s <= 0:
            return
        self._thread = threading.Thread(
            target=self._run,
            name=f"status-heartbeat-{self.state.run_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_s * 2))

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.persister.write_runtime_status(self.state, stage="assessment")
            except Exception:
                LOGGER.exception("runtime status heartbeat failed", extra={"run_id": self.state.run_id})


class RunConfig(BaseModel):
    """Configuration for one local assessment run."""

    model_config = ConfigDict(extra="ignore")

    objective: str
    authorized_scope: list[str]
    output_root: str = "runs"
    max_cycles: int = Field(default=8, ge=1)
    quiet: bool = False
    status_path: str | None = None
    rag_mode: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "RunConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if "scope" in payload and "authorized_scope" not in payload:
            payload["authorized_scope"] = payload.pop("scope")
        return cls.model_validate(payload)


class RunArtifacts(BaseModel):
    """Filesystem outputs produced by a run."""

    run_id: str
    run_dir: str
    state_path: str
    summary_path: str
    report_path: str
    events_path: str
    config_path: str
    evidence_path: str
    compact_json_path: str
    compact_markdown_path: str
    status: str


class EventRecorder:
    """Collects structured runtime events and optionally logs them."""

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
            self._context.update({
                key: json_sanitize(value)
                for key, value in context.items()
                if value is not None
            })

    def emit(
        self,
        message: str,
        *,
        level: int = logging.INFO,
        event_type: str | None = None,
        **context: Any,
    ) -> None:
        record = self._record(message, level=level, event_type=event_type, context=context)
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


def build_runtime(
    config: RunConfig,
    *,
    recorder: EventRecorder | None = None,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
    llm_client: LLMClient | None = None,
    checkpoint_callback: Callable[[RunState], None] | None = None,
) -> tuple[RunState, Orchestrator, LLMClient]:
    """Assemble state, planner, workers, and execution plane for one run."""

    if llm_client is None:
        llm_client = build_llm_client_from_env()

    # One augmenter per run, used by the planner for RAG writeup context.
    # ``from_default`` resolves to the module-level retriever singleton
    # (or ``None`` when fastembed / the dataset isn't available), so the
    # caller never has to know whether RAG is wired up.
    resolved_rag_mode = rag_mode(config.rag_mode)
    augmenter = KnowledgeAugmenter.from_default(mode=resolved_rag_mode)
    metadata = dict(config.metadata)
    rag_metadata = metadata.get("rag")
    metadata["rag"] = {
        **(rag_metadata if isinstance(rag_metadata, dict) else {}),
        "mode": resolved_rag_mode,
    }

    planner = LLMPlanner(llm_client, augmenter=augmenter)
    router = RouterAgent(llm_client)
    emit = recorder.emit if recorder is not None else LOGGER.info

    execution_plane = execution_plane or build_execution_plane()
    state = RunState(
        objective=config.objective,
        authorized_scope=config.authorized_scope,
        metadata=metadata,
    )
    worker_context = WorkerBuildContext(
        llm_client=llm_client,
        execution_plane=execution_plane,
        augmenter=augmenter,
        expected_flag=expected_flag,
    )
    orchestrator = Orchestrator(
        state=state,
        workers=build_builtin_workers(worker_context),
        planner=planner,
        router=router,
        emit=emit,
        checkpoint_callback=checkpoint_callback,
    )
    return state, orchestrator, llm_client


def run_assessment(
    config: RunConfig,
    *,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
    llm_client: LLMClient | None = None,
) -> RunArtifacts:
    """Run the full local workflow and persist artifacts.

    Persistence is wrapped in ``try/finally`` so that state/summary/report/
    evidence/events are always written, even if ``orchestrator.run`` raises.
    """

    recorder = EventRecorder(quiet=config.quiet)
    state, orchestrator, active_llm_client = build_runtime(
        config,
        recorder=recorder,
        execution_plane=execution_plane,
        expected_flag=expected_flag,
        llm_client=llm_client,
    )
    run_dir = Path(config.output_root) / state.run_id
    status_path = Path(config.status_path) if config.status_path else None
    token_ledger = getattr(active_llm_client, "token_ledger", None)
    persister = RunPersister(run_dir, recorder, status_path, token_ledger)
    recorder.bind_context(
        run_id=state.run_id,
        challenge=(state.metadata.get("challenge", {}) or {}).get("canonical_name")
        or (state.metadata.get("challenge", {}) or {}).get("name"),
    )
    persister.write_config(config)
    persister.write_runtime_status(state, stage="initialized")
    orchestrator.checkpoint_callback = persister.write_state
    heartbeat = RuntimeStatusHeartbeat(persister, state)
    heartbeat.start()

    run_error: BaseException | None = None
    run_traceback = None

    try:
        orchestrator.run(max_cycles=config.max_cycles)
    except (KeyboardInterrupt, SystemExit) as exc:
        run_error = exc
        run_traceback = exc.__traceback__
        _record_runtime_exception(state, exc)
        LOGGER.warning(
            "run interrupted; finalizing artifacts",
            exc_info=True,
            extra={"run_id": state.run_id},
        )
    except BaseException as exc:
        run_error = exc
        run_traceback = exc.__traceback__
        _record_runtime_exception(state, exc)
        LOGGER.exception(
            "run failed; finalizing artifacts",
            extra={"run_id": state.run_id},
        )
    finally:
        heartbeat.stop()
        if token_ledger is not None:
            token_usage = token_ledger.to_dict()
            recorder.emit(
                f"[token usage] calls={token_usage['llm_calls']} "
                f"prompt={token_usage['prompt_tokens']} "
                f"completion={token_usage['completion_tokens']} "
                f"total={token_usage['total_tokens']}",
                event_type="token_usage",
                llm_calls=token_usage["llm_calls"],
                prompt_tokens=token_usage["prompt_tokens"],
                completion_tokens=token_usage["completion_tokens"],
                total_tokens=token_usage["total_tokens"],
            )
        try:
            persister.write_all(state)
        except Exception:
            LOGGER.exception("failed to persist final run artifacts", extra={"run_id": state.run_id})
            if run_error is None:
                raise

    artifacts = RunArtifacts(
        run_id=state.run_id,
        run_dir=str(run_dir),
        state_path=str(persister.state_path),
        summary_path=str(persister.summary_path),
        report_path=str(persister.report_path),
        events_path=str(persister.events_path),
        config_path=str(persister.config_path),
        evidence_path=str(persister.evidence_path),
        compact_json_path=str(persister.compact_json_path),
        compact_markdown_path=str(persister.compact_markdown_path),
        status=state.status,
    )
    if run_error is not None:
        setattr(run_error, "run_artifacts", artifacts)
        raise run_error.with_traceback(run_traceback)
    return artifacts
