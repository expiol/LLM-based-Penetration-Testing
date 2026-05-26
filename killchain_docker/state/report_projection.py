"""Controller and markdown-report projections over run state."""

from __future__ import annotations
from typing import Any, TYPE_CHECKING
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.todos import TodoStatus
from killchain_docker.state.projection_common import (
    COMPACT_GOAL_LIMIT,
    COMPACT_TIMELINE_LIMIT,
    compact_text,
)

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState
    from killchain_docker.state.todos import TodoItem


class RunReportProjection:
    """Read-only projections used by status, compact logs, and reports."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.metadata = RunMetadataStore(state)

    def summary(self) -> dict[str, Any]:
        state = self.state
        return {
            "run_id": state.run_id,
            "status": state.status,
            "stop_reason": state.stop_reason,
            "solved": state.solved,
            "validated_flag": state.validated_flag,
            "todos": len(state.todos),
            "open_todos": sum(
                (
                    1
                    for todo in state.todos
                    if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
                )
            ),
            "rounds": len(state.rounds),
            "assets": len(state.assets),
            "findings": len(state.findings),
            "credentials": len(state.credentials),
            "artifacts": len(state.artifacts),
            "endpoints": len(state.endpoints),
            "routes": len(state.routes),
            "flag_candidates": len(state.flag_candidates),
            "rejected_flag_candidates": len(state.rejected_flag_candidates),
            "hypotheses": len(state.hypotheses),
            "vulnerabilities": len(state.vulnerabilities),
            "exploit_attempts": len(state.exploit_attempts),
            "sessions": len(state.sessions),
            "evidence": len(state.evidence),
            "executions": len(state.execution_log),
            "orchestration_notes": len(state.orchestration_notes),
        }

    def todo_status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for todo in self.state.todos:
            key = str(todo.status)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def worker_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for todo in self.state.todos:
            key = str(todo.assigned_worker or "unassigned")
            counts[key] = counts.get(key, 0) + 1
        return counts

    def metrics(self) -> dict[str, Any]:
        return {
            **self.summary(),
            "todo_status_counts": self.todo_status_counts(),
            "worker_counts": self.worker_counts(),
        }

    def current_status_todo(self) -> "TodoItem | None":
        if not self.state.todos:
            return None
        for todo in reversed(self.state.todos):
            if str(todo.status) == "running":
                return todo
        for todo in reversed(self.state.todos):
            if str(todo.status) in {
                "pending",
                "partial",
                "failed",
                "blocked",
                "interrupted",
            }:
                return todo
        return None

    def compact_todo(self, todo: "TodoItem") -> dict[str, object]:
        return {
            "todo_id": todo.todo_id,
            "phase": str(todo.phase),
            "status": str(todo.status),
            "worker": todo.assigned_worker,
            "attempts": todo.attempts,
            "depends_on": list(todo.depends_on),
            "family": str(todo.context.get("family") or ""),
            "goal": compact_text(todo.goal, limit=COMPACT_GOAL_LIMIT),
            "result": compact_text(todo.result_summary),
            "error": compact_text(todo.error),
        }

    def open_or_recent_todos(self) -> list[dict[str, object]]:
        interesting_statuses = {
            "pending",
            "running",
            "partial",
            "failed",
            "blocked",
            "interrupted",
        }
        selected = [
            todo
            for todo in self.state.todos
            if str(todo.status) in interesting_statuses
        ]
        if len(selected) < 20:
            seen = {todo.todo_id for todo in selected}
            for todo in self.state.todos[-20:]:
                if todo.todo_id not in seen:
                    selected.append(todo)
        return [self.compact_todo(todo) for todo in selected[-40:]]

    def compact_rounds(
        self, *, limit: int = COMPACT_TIMELINE_LIMIT
    ) -> list[dict[str, object]]:
        timeline: list[dict[str, object]] = []
        for round_record in self.state.rounds[-limit:]:
            timeline.append(
                {
                    "cycle": round_record.cycle,
                    "planner_summary": compact_text(round_record.planner_summary),
                    "assignments": [
                        {
                            "todo_id": assignment.todo_id,
                            "worker": assignment.worker_name,
                            "rationale": compact_text(assignment.rationale, limit=180),
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
                            "summary": compact_text(result.summary),
                            "error": compact_text(
                                result.error or result.partial_reason
                            ),
                            "flag_candidates": len(result.state_delta.flag_candidates)
                            if result.state_delta
                            else 0,
                            "notes": [
                                compact_text(note, limit=220)
                                for note in result.notes[:3]
                            ],
                        }
                        for result in round_record.results
                    ],
                    "router_summary": compact_text(round_record.summary.summary),
                    "key_findings": [
                        compact_text(item, limit=260)
                        for item in round_record.summary.key_findings[:5]
                    ],
                    "next_focus": compact_text(round_record.summary.next_focus),
                }
            )
        return timeline

    def router_round_summaries(self, *, limit: int = 8) -> list[dict[str, object]]:
        return [
            round_record.summary.model_dump(mode="json")
            for round_record in self.state.rounds[-limit:]
        ]

    def compact_flag_candidates(self) -> list[dict[str, object]]:
        return [
            {
                "value": candidate.value,
                "source": candidate.source,
                "confidence": candidate.confidence,
                "validated": candidate.validated,
                "rejected_reason": candidate.rejected_reason,
            }
            for candidate in self.state.flag_candidates.values()
        ]

    def compact_hypotheses_tail(self, *, limit: int = 20) -> list[dict[str, object]]:
        return [
            {
                "title": compact_text(item.title),
                "status": item.status,
                "confidence": item.confidence,
                "category": item.category,
            }
            for item in self.state.hypotheses.values()
        ][-limit:]

    def compact_orchestration_notes_tail(self, *, limit: int = 30) -> list[str]:
        return [
            compact_text(note, limit=300)
            for note in self.state.orchestration_notes[-limit:]
        ]

    def markdown_report_payload(self) -> dict[str, object]:
        return {
            "overview": {
                "run_id": self.state.run_id,
                "objective": self.state.objective,
                "status": str(self.state.status),
                "stop_reason": self.state.stop_reason or "n/a",
                "solved": self.state.solved,
                "validated_flag": self.state.validated_flag or "n/a",
                "scope_entries": len(self.state.authorized_scope),
                "todos": len(self.state.todos),
                "rounds": len(self.state.rounds),
                "assets": len(self.state.assets),
                "findings": len(self.state.findings),
                "artifacts": len(self.state.artifacts),
                "routes": len(self.state.routes),
                "flag_candidates": len(self.state.flag_candidates),
                "vulnerabilities": len(self.state.vulnerabilities),
                "evidence": len(self.state.evidence),
            },
            "runtime_error": self.runtime_error_line(),
            "rag": self.rag_line(),
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "kind": str(asset.kind),
                    "location": asset.base_url
                    or asset.hostname
                    or asset.ip_address
                    or "n/a",
                }
                for asset in sorted(
                    self.state.assets.values(), key=lambda item: item.asset_id
                )
            ],
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "severity": str(finding.severity),
                    "title": finding.title,
                    "description": finding.description or "",
                }
                for finding in sorted(
                    self.state.findings.values(), key=lambda item: item.finding_id
                )
            ],
            "todos": [
                {
                    "status": str(todo.status),
                    "todo_id": todo.todo_id,
                    "goal": todo.goal,
                    "result_summary": todo.result_summary,
                    "error": todo.error or "",
                }
                for todo in self.state.todos
            ],
            "router_rounds": [
                {"cycle": round_record.cycle, "summary": round_record.summary.summary}
                for round_record in self.state.rounds
            ],
            "flag_candidates_tail": [
                {
                    "status": "unknown"
                    if candidate.validated is None
                    else str(candidate.validated),
                    "source": candidate.source or "unknown",
                    "value": candidate.value,
                }
                for candidate in list(self.state.flag_candidates.values())[-20:]
            ],
            "routes_tail": [
                {
                    "status_code": route.status_code
                    if route.status_code is not None
                    else "n/a",
                    "url": route.url,
                }
                for route in list(self.state.routes.values())[-20:]
            ],
            "has_typed_facts": bool(
                self.state.flag_candidates
                or self.state.routes
                or self.state.vulnerabilities
            ),
            "evidence": [
                {
                    "evidence_id": evidence.evidence_id,
                    "tool_name": evidence.tool_name,
                    "summary": evidence.summary,
                }
                for evidence in sorted(
                    self.state.evidence.values(), key=lambda item: item.evidence_id
                )
            ],
            "worker_notes_tail": list(self.state.notes[-50:]),
            "orchestration_notes_tail": list(self.state.orchestration_notes[-50:]),
        }

    def runtime_error_line(self) -> str | None:
        payload = self.runtime_error_payload()
        if payload is None:
            return None
        error_type = compact_text(payload.get("type") or "RuntimeError", limit=80)
        message = compact_text(payload.get("message"), limit=360)
        return f"- Runtime Error: `{error_type}` {message}".rstrip()

    def runtime_error_payload(self) -> dict[str, Any] | None:
        return self.metadata.runtime_error()

    def rag_line(self) -> str | None:
        payload = self.rag_payload()
        if not payload:
            return None
        return f"- RAG: enabled=`{payload.get('enabled')}` status=`{payload.get('status')}` policy=`{payload.get('policy')}` hints={payload.get('hint_count')}"

    def rag_payload(self) -> dict[str, Any] | None:
        from killchain_docker.knowledge.status import public_rag_payload

        return public_rag_payload(self.metadata.rag())
