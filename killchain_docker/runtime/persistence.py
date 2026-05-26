"""Run artifact persistence and live runtime status."""

from __future__ import annotations
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from killchain_docker.logging_utils import (
    get_logger,
    json_dumps,
    write_json_file,
    write_text_file,
)
from killchain_docker.reporting import render_markdown_report
from killchain_docker.runtime.compact_log import (
    build_compact_run_log,
    render_compact_run_markdown,
    runtime_error_payload,
)
from killchain_docker.runtime.config import RunConfig
from killchain_docker.runtime.events import EventRecorder
from killchain_docker.state.run_state import RunState
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.value_coercion import (
    COMPACT_GOAL_LIMIT,
    compact_text,
)
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.thread_status import build_thread_registry, thread_info

LOGGER = get_logger(__name__)
STATUS_HEARTBEAT_INTERVAL_S = 5.0


def write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_file(path, payload)


def write_text(path: Path, payload: str) -> None:
    write_text_file(path, payload)


class RunPersister:
    """Own run artifact paths and write checkpoint/final snapshots."""

    def __init__(
        self,
        run_dir: Path,
        recorder: EventRecorder,
        status_path: Path | None = None,
        token_ledger: Any | None = None,
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
        challenge_projection = ChallengeProjection(state)
        report_projection = RunReportProjection(state)
        outcome = RunOutcomeStore(state)
        outcome_payload = outcome.summary_payload()
        challenge_name = challenge_projection.name()
        status_todo = report_projection.current_status_todo()
        messages = self.recorder.messages
        records = self.recorder.records
        latest_event = records[-1] if records else None
        now = datetime.now(timezone.utc)
        latest_thread_id = (
            latest_event.get("thread_id")
            if isinstance(latest_event, dict)
            and latest_event.get("thread_id") is not None
            else threading.get_ident()
        )
        latest_thread_name = (
            latest_event.get("thread_name")
            if isinstance(latest_event, dict)
            and latest_event.get("thread_name") is not None
            else threading.current_thread().name
        )
        writer_thread_id = threading.get_ident()
        writer_thread_name = threading.current_thread().name
        threads: dict[str, Any] = {
            "observed": thread_info(latest_thread_id, latest_thread_name),
            "status_writer": thread_info(writer_thread_id, writer_thread_name),
        }
        current_todo = (
            None
            if status_todo is None
            else {
                "todo_id": status_todo.todo_id,
                "phase": str(status_todo.phase),
                "status": str(status_todo.status),
                "worker": status_todo.assigned_worker,
                "attempts": status_todo.attempts,
                "goal": compact_text(status_todo.goal, limit=COMPACT_GOAL_LIMIT),
                "result": compact_text(status_todo.result_summary),
                "error": compact_text(status_todo.error),
            }
        )
        latest_event_payload = None
        if latest_event:
            threads["latest_event"] = thread_info(
                latest_event.get("thread_id"), latest_event.get("thread_name")
            )
            latest_event_payload = {
                "sequence": latest_event.get("sequence"),
                "timestamp": latest_event.get("timestamp"),
                "level": latest_event.get("level"),
                "event_type": latest_event.get("event_type"),
                "thread_id": latest_event.get("thread_id"),
                "thread_name": latest_event.get("thread_name"),
                "message": compact_text(latest_event.get("message")),
            }
        runtime_error = runtime_error_payload(state)
        message = messages[-1] if messages else None
        threads["registry"] = build_thread_registry(
            challenge=str(challenge_name or ""),
            stage=stage,
            status=str(outcome.status_value),
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
            "challenge": challenge_name,
            "pid": os.getpid(),
            "thread_id": latest_thread_id,
            "thread_name": latest_thread_name,
            "status_writer_thread_id": writer_thread_id,
            "status_writer_thread_name": writer_thread_name,
            "threads": threads,
            "stage": stage,
            "status": outcome_payload["status"],
            "run_id": state.run_id,
            "solved": outcome_payload["solved"],
            "stop_reason": outcome_payload["stop_reason"],
            "updated_at": now.isoformat(),
            "state_updated_at": state.updated_at.isoformat(),
            "last_cycle_at": state.last_cycle_at.isoformat()
            if state.last_cycle_at
            else None,
            "runtime_sec": round(max(0.0, (now - state.created_at).total_seconds()), 3),
            "message": message,
            "worker": status_todo.assigned_worker if status_todo else None,
            "current_todo": current_todo,
            "state_metrics": report_projection.metrics(),
            "runtime_error": runtime_error,
            "rag": report_projection.rag_payload(),
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
            write_json(self.status_path, self._status_payload(state, stage=stage))

    def write_config(self, config: RunConfig) -> None:
        with self._lock:
            write_json(self.config_path, config.model_dump(mode="json"))

    def _write_events(self) -> None:
        lines = [
            json_dumps(record, indent=None, sort_keys=True)
            for record in self.recorder.records
        ]
        suffix = "\n" if lines else ""
        write_text(self.events_path, "\n".join(lines) + suffix)

    def _write_compact(self, state: RunState) -> None:
        payload = build_compact_run_log(
            state, events=list(self.recorder.messages), token_ledger=self.token_ledger
        )
        write_json(self.compact_json_path, payload)
        write_text(self.compact_markdown_path, render_compact_run_markdown(payload))

    def write_state(self, state: RunState) -> None:
        try:
            with self._lock:
                write_json(self.state_path, state.model_dump(mode="json"))
                self._write_events()
                self._write_compact(state)
                self.write_runtime_status(state, stage="assessment")
        except Exception as exc:
            LOGGER.exception(
                "checkpoint write failed",
                extra={
                    "run_dir": str(self.run_dir),
                    "status_path": str(self.status_path) if self.status_path else None,
                },
            )
            self.recorder.emit(
                f"[persister] checkpoint write failed: {type(exc).__name__}: {exc}",
                level=logging.ERROR,
                event_type="persistence",
            )

    def write_all(self, state: RunState) -> None:
        with self._lock:
            write_json(self.state_path, state.model_dump(mode="json"))
            summary = RunReportProjection(state).summary()
            summary["objective"] = state.objective
            summary["authorized_scope"] = state.authorized_scope
            summary["worker_notes"] = len(state.notes)
            runtime_error = runtime_error_payload(state)
            if runtime_error is not None:
                summary["runtime_error"] = runtime_error
            public_rag = RunReportProjection(state).rag_payload()
            if public_rag is not None:
                summary["rag"] = public_rag
            token_usage = self._token_usage()
            if token_usage is not None:
                summary["token_usage"] = token_usage
            write_json(self.summary_path, summary)
            write_json(self.evidence_path, EvidenceProjectionStore(state).payload())
            write_text(self.report_path, render_markdown_report(state))
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
            target=self._run, name=f"status-heartbeat-{self.state.run_id}", daemon=True
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
                LOGGER.exception(
                    "runtime status heartbeat failed",
                    extra={"run_id": self.state.run_id},
                )
