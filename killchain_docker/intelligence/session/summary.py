"""Per-run session summary writer.

Writes a compact summary into ``RunState.run_memory`` under a reserved key so
later planner cycles can see "what we already learned" without re-reading the
full execution log. The summary itself is generated cheaply from structured run
state (no extra LLM call): older rounds and evidence are rolled up into a small
reference sheet with cycle numbers and evidence ids the planner can cite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.intelligence.session.thresholds import (
    DEFAULT_THRESHOLDS,
    SessionSummaryThresholds,
)
from killchain_docker.value_coercion import compact_text

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


SESSION_SUMMARY_KEY = "__session_summary__"
SESSION_SUMMARY_METADATA_KEY = "session_summary"
MAX_SUMMARY_CHARS = 4200
MAX_ROUNDS_IN_SUMMARY = 12
MAX_EVIDENCE_IN_SUMMARY = 16
MAX_MILESTONES_IN_SUMMARY = 12
MAX_FINDINGS_IN_SUMMARY = 8
MAX_FLAG_CANDIDATES_IN_SUMMARY = 8
MAX_OPEN_TODOS_IN_SUMMARY = 8
MAX_FAILURES_IN_SUMMARY = 6


def maybe_refresh_session_summary(
    state: "RunState",
    *,
    cycle: int,
    thresholds: SessionSummaryThresholds = DEFAULT_THRESHOLDS,
) -> bool:
    """Refresh ``state.run_memory[SESSION_SUMMARY_KEY]`` when thresholds met."""

    if cycle < thresholds.minimum_cycles_to_init:
        return False
    last_cycle = state.metadata.get("session_summary_cycle")
    if isinstance(last_cycle, int) and (
        cycle - last_cycle < thresholds.minimum_cycles_between_updates
    ):
        return False

    summary = _render_summary(state)
    if not summary:
        return False
    state.run_memory[SESSION_SUMMARY_KEY] = summary
    state.metadata["session_summary_cycle"] = cycle
    state.metadata[SESSION_SUMMARY_METADATA_KEY] = {
        "key": SESSION_SUMMARY_KEY,
        "cycle": cycle,
        "rounds": len(state.rounds),
        "evidence": len(state.evidence),
        "executions": len(state.execution_log),
    }
    return True


def _render_summary(state: "RunState") -> str:
    """Project run state into a compact, referenceable markdown summary."""

    lines: list[str] = []
    objective = (state.objective or "").strip()
    if objective:
        lines.append(f"objective: {objective[:240]}")
    lines.append(
        "purpose: rolling run summary for older rounds/evidence; use cited "
        "cycle numbers and evidence ids when planning next steps."
    )

    rounds = len(state.rounds)
    todos = len(state.todos)
    open_todos = sum(
        1
        for todo in state.todos
        if str(getattr(todo, "status", "")).lower() in {"pending", "running"}
    )
    flag_candidates = len(state.flag_candidates)
    findings = len(state.findings)
    evidence = len(state.evidence)
    lines.append(f"coverage: {_coverage_line(state)}")
    lines.append(
        "counts: "
        + " | ".join(
            [
                f"rounds={rounds}",
                f"todos={todos}",
                f"open={open_todos}",
                f"findings={findings}",
                f"evidence={evidence}",
                f"flag_candidates={flag_candidates}",
            ]
        )
    )

    last_round = state.rounds[-1] if state.rounds else None
    if last_round is not None:
        summary_text = getattr(last_round.summary, "summary", "") or ""
        if summary_text:
            lines.append(f"last_round_summary: {summary_text[:300]}")

    last_execution = state.execution_log[-1] if state.execution_log else None
    if last_execution is not None:
        summary_text = getattr(last_execution, "summary", "") or ""
        if summary_text:
            lines.append(f"last_step: {summary_text[:240]}")

    sections = (
        ("historical_milestones", _historical_milestone_lines(state)),
        ("round_rollup", _round_rollup_lines(state)),
        ("evidence_anchors", _evidence_anchor_lines(state)),
        ("accepted_or_pending_flag_candidates", _flag_candidate_lines(state)),
        ("findings", _finding_lines(state)),
        ("open_focus", _open_todo_lines(state)),
        ("recent_failures", _failure_lines(state)),
    )
    for title, section_lines in sections:
        if not section_lines:
            continue
        lines.append(f"{title}:")
        lines.extend(section_lines)

    return _limit_summary("\n".join(line for line in lines if line))


def _coverage_line(state: "RunState") -> str:
    parts: list[str] = []
    rounds = list(state.rounds)
    if rounds:
        first_cycle = getattr(rounds[0], "cycle", None)
        last_cycle = getattr(rounds[-1], "cycle", None)
        parts.append(f"cycles={first_cycle}-{last_cycle}")
    else:
        parts.append("cycles=none")
    evidence_records = list(state.evidence.values())
    if evidence_records:
        first_id = evidence_records[0].evidence_id
        last_id = evidence_records[-1].evidence_id
        parts.append(f"evidence={first_id}..{last_id}")
    else:
        parts.append("evidence=none")
    parts.append(f"executions={len(state.execution_log)}")
    return " | ".join(parts)


def _historical_milestone_lines(state: "RunState") -> list[str]:
    """Select durable anchors from the whole run, not only the recent tail."""

    candidates: list[tuple[int, int, str]] = []
    for index, round_record in enumerate(state.rounds):
        score = 1
        if round_record.summary.key_findings:
            score += 4
        if round_record.summary.next_focus:
            score += 1
        score += sum(3 for result in round_record.results if result.success)
        score += sum(
            8
            for result in round_record.results
            if result.state_delta is not None and result.state_delta.flag_candidates
        )
        if score <= 1:
            continue
        text_parts = [
            f"cycle {round_record.cycle}",
            compact_text(round_record.summary.summary, limit=220),
        ]
        if round_record.summary.key_findings:
            text_parts.append(
                "findings="
                + "; ".join(
                    compact_text(item, limit=120)
                    for item in round_record.summary.key_findings[:3]
                )
            )
        candidates.append(
            (score, index, " | ".join(part for part in text_parts if part))
        )

    for index, evidence in enumerate(state.evidence.values()):
        summary = str(evidence.summary or "")
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        ctx = extracted.get("output_context")
        ctx = ctx if isinstance(ctx, dict) else {}
        score = 0
        if ctx.get("flag_candidates"):
            score += 12
        lowered = summary.lower()
        if any(
            token in lowered
            for token in ("candidate", "credential", "secret", "key", "vulnerab")
        ):
            score += 5
        if not score:
            continue
        text = (
            f"{evidence.evidence_id} | tool={evidence.tool_name} | "
            f"summary={compact_text(summary, limit=220)}"
        )
        flag_preview = _evidence_flag_preview(evidence)
        if flag_preview:
            text += f" | flags={flag_preview}"
        candidates.append((score, len(state.rounds) + index, text))

    selected = sorted(candidates, key=lambda item: (-item[0], item[1]))[
        :MAX_MILESTONES_IN_SUMMARY
    ]
    return [
        f"- {text}"
        for _score, _index, text in sorted(selected, key=lambda item: item[1])
    ]


def _round_rollup_lines(state: "RunState") -> list[str]:
    rounds = list(state.rounds)
    if not rounds:
        return []
    selected = rounds[-MAX_ROUNDS_IN_SUMMARY:]
    lines: list[str] = []
    older_count = len(rounds) - len(selected)
    if older_count > 0:
        last_older = rounds[older_count - 1]
        lines.append(
            f"- earlier_cycles: {rounds[0].cycle}-{last_older.cycle} "
            f"({older_count} round(s)); raw details remain in compact_log/state."
        )
    for round_record in selected:
        result_count = len(round_record.results)
        success_count = sum(1 for result in round_record.results if result.success)
        flag_count = sum(
            len(result.state_delta.flag_candidates)
            for result in round_record.results
            if result.state_delta is not None
        )
        pieces = [
            f"planner={compact_text(round_record.planner_summary, limit=180)}",
            f"summary={compact_text(round_record.summary.summary, limit=220)}",
        ]
        if round_record.summary.key_findings:
            pieces.append(
                "findings="
                + "; ".join(
                    compact_text(item, limit=140)
                    for item in round_record.summary.key_findings[:4]
                )
            )
        if round_record.summary.next_focus:
            pieces.append(
                f"next={compact_text(round_record.summary.next_focus, limit=160)}"
            )
        pieces.append(f"results={success_count}/{result_count} success")
        if flag_count:
            pieces.append(f"new_flag_candidates={flag_count}")
        return_text = " | ".join(
            piece for piece in pieces if piece.split("=", 1)[-1]
        )
        lines.append(f"- cycle {round_record.cycle}: {return_text}")
    return lines


def _evidence_anchor_lines(state: "RunState") -> list[str]:
    records = list(state.evidence.values())
    if not records:
        return []
    selected = records[-MAX_EVIDENCE_IN_SUMMARY:]
    lines: list[str] = []
    older_count = len(records) - len(selected)
    if older_count > 0:
        last_older = records[older_count - 1]
        lines.append(
            f"- earlier_evidence: {records[0].evidence_id}..{last_older.evidence_id} "
            f"({older_count} record(s)); raw output remains in evidence.json."
        )
    for evidence in selected:
        parts = [
            evidence.evidence_id,
            f"tool={evidence.tool_name}",
            f"task={evidence.task_id}",
        ]
        if evidence.capability:
            parts.append(f"capability={evidence.capability}")
        parts.append(f"summary={compact_text(evidence.summary, limit=240)}")
        flag_preview = _evidence_flag_preview(evidence)
        if flag_preview:
            parts.append(f"flags={flag_preview}")
        lines.append("- " + " | ".join(parts))
    return lines


def _evidence_flag_preview(evidence: object) -> str:
    extracted = getattr(evidence, "extracted", None)
    if not isinstance(extracted, dict):
        return ""
    ctx = extracted.get("output_context")
    if not isinstance(ctx, dict):
        return ""
    values = ctx.get("flag_candidates")
    if not isinstance(values, list) or not values:
        return ""
    return ", ".join(compact_text(value, limit=80) for value in values[:4])


def _flag_candidate_lines(state: "RunState") -> list[str]:
    candidates = list(state.flag_candidates.values())[-MAX_FLAG_CANDIDATES_IN_SUMMARY:]
    lines: list[str] = []
    for candidate in candidates:
        refs = ",".join(candidate.evidence_refs[-4:])
        detail = [
            f"id={candidate.candidate_id}",
            f"value={compact_text(candidate.value, limit=180)}",
            f"validated={candidate.validated}",
        ]
        if refs:
            detail.append(f"evidence={refs}")
        if candidate.rejected_reason:
            detail.append(f"rejected={compact_text(candidate.rejected_reason)}")
        lines.append("- " + " | ".join(detail))
    return lines


def _finding_lines(state: "RunState") -> list[str]:
    findings = list(state.findings.values())[-MAX_FINDINGS_IN_SUMMARY:]
    lines: list[str] = []
    for finding in findings:
        refs = ",".join(finding.evidence_refs[-4:])
        detail = [
            f"id={finding.finding_id}",
            f"severity={finding.severity}",
            f"title={compact_text(finding.title, limit=180)}",
        ]
        if refs:
            detail.append(f"evidence={refs}")
        if finding.description:
            detail.append(f"desc={compact_text(finding.description, limit=180)}")
        lines.append("- " + " | ".join(detail))
    return lines


def _open_todo_lines(state: "RunState") -> list[str]:
    interesting_statuses = {"pending", "running", "partial", "failed", "blocked"}
    todos = [
        todo
        for todo in state.todos
        if str(getattr(todo, "status", "")).lower() in interesting_statuses
    ][-MAX_OPEN_TODOS_IN_SUMMARY:]
    lines: list[str] = []
    for todo in todos:
        lines.append(
            "- "
            + " | ".join(
                [
                    f"id={todo.todo_id}",
                    f"status={todo.status}",
                    f"phase={todo.phase}",
                    f"goal={compact_text(todo.goal, limit=220)}",
                ]
            )
        )
    return lines


def _failure_lines(state: "RunState") -> list[str]:
    failures = [
        record
        for record in state.execution_log
        if not bool(getattr(record, "success", False))
    ][-MAX_FAILURES_IN_SUMMARY:]
    lines: list[str] = []
    for record in failures:
        detail = [
            f"task={record.task_id}",
            f"worker={record.worker_name}",
            f"summary={compact_text(record.summary, limit=180)}",
        ]
        if record.error:
            detail.append(f"error={compact_text(record.error, limit=180)}")
        lines.append("- " + " | ".join(detail))
    return lines


def _limit_summary(text: str) -> str:
    if len(text) <= MAX_SUMMARY_CHARS:
        return text
    return (
        text[: max(0, MAX_SUMMARY_CHARS - 40)].rstrip()
        + "\n...[session summary truncated]"
    )
