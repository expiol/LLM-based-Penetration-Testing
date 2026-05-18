"""Top-level run controller for assembling and executing a session."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, TokenLedger, build_llm_client_from_env
from killchain_docker.orchestrator import (
    LLMPlanner,
    Orchestrator,
    RouterAgent,
)
from killchain_docker.reporting import render_markdown_report
from killchain_docker.state import RunState
from killchain_docker.tools import ExecutionPlane, build_execution_plane
from killchain_docker.workers import WorkerBuildContext, build_builtin_workers


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


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

    def __init__(self, run_dir: Path, recorder: EventRecorder) -> None:
        self.run_dir = run_dir
        self.recorder = recorder
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = run_dir / "config.json"
        self.state_path = run_dir / "state.json"
        self.summary_path = run_dir / "summary.json"
        self.report_path = run_dir / "report.md"
        self.events_path = run_dir / "events.log"
        self.evidence_path = run_dir / "evidence.json"
        self.compact_json_path = run_dir / "compact_log.json"
        self.compact_markdown_path = run_dir / "compact_log.md"

    def write_config(self, config: RunConfig) -> None:
        _write_json(self.config_path, config.model_dump(mode="json"))

    def _write_events(self) -> None:
        messages = list(self.recorder.messages)
        suffix = "\n" if messages else ""
        self.events_path.write_text("\n".join(messages) + suffix, encoding="utf-8")

    def _write_compact(self, state: RunState, token_ledger: TokenLedger | None = None) -> None:
        payload = build_compact_run_log(
            state,
            events=list(self.recorder.messages),
            token_ledger=token_ledger,
        )
        _write_json(self.compact_json_path, payload)
        self.compact_markdown_path.write_text(
            render_compact_run_markdown(payload),
            encoding="utf-8",
        )

    def write_state(self, state: RunState) -> None:
        try:
            _write_json(self.state_path, state.model_dump(mode="json"))
            self._write_events()
            self._write_compact(state)
        except Exception as exc:
            self.recorder.emit(
                f"[persister] checkpoint write failed: {type(exc).__name__}: {exc}"
            )

    def write_all(
        self,
        state: RunState,
        token_ledger: TokenLedger | None,
    ) -> None:
        _write_json(self.state_path, state.model_dump(mode="json"))
        summary = state.summary()
        summary["objective"] = state.objective
        summary["authorized_scope"] = state.authorized_scope
        summary["worker_notes"] = len(state.notes)
        summary["orchestration_notes"] = len(state.orchestration_notes)
        if token_ledger is not None:
            summary["token_usage"] = token_ledger.to_dict()
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
        self.report_path.write_text(render_markdown_report(state), encoding="utf-8")
        self._write_events()
        self._write_compact(state, token_ledger)


class RunConfig(BaseModel):
    """Configuration for one local assessment run."""

    model_config = ConfigDict(extra="ignore")

    objective: str
    authorized_scope: list[str]
    output_root: str = "runs"
    max_cycles: int = Field(default=8, ge=1)
    quiet: bool = False
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
    """Collects orchestrator emit events and optionally echoes them to stdout."""

    def __init__(self, *, quiet: bool = False) -> None:
        self.quiet = quiet
        self.messages: list[str] = []

    def emit(self, message: str) -> None:
        self.messages.append(message)
        if not self.quiet:
            print(message)


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
    augmenter = KnowledgeAugmenter.from_default()

    planner = LLMPlanner(llm_client, augmenter=augmenter)
    router = RouterAgent(llm_client)
    emit = recorder.emit if recorder is not None else print

    execution_plane = execution_plane or build_execution_plane()
    state = RunState(
        objective=config.objective,
        authorized_scope=config.authorized_scope,
        metadata=dict(config.metadata),
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
    persister = RunPersister(run_dir, recorder)
    persister.write_config(config)
    orchestrator.checkpoint_callback = persister.write_state

    token_ledger = getattr(active_llm_client, "token_ledger", None)
    run_error: BaseException | None = None
    run_traceback = None

    try:
        orchestrator.run(max_cycles=config.max_cycles)
    except BaseException as exc:
        run_error = exc
        run_traceback = exc.__traceback__
    finally:
        if token_ledger is not None:
            recorder.emit(
                f"[token usage] calls={token_ledger.llm_calls} "
                f"prompt={token_ledger.prompt_tokens} "
                f"completion={token_ledger.completion_tokens} "
                f"total={token_ledger.total_tokens}"
            )
        persister.write_all(state, token_ledger)

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
