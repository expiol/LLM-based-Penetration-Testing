"""RouterAgent for persona-worker assignment and round summarization."""

from __future__ import annotations

import json

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.state import (
    RouterDecision,
    RouterRoundSummary,
    RunState,
    TodoPhase,
    TodoItem,
    WorkerAssignment,
    WorkerResult,
    todo_phase_rank,
)


class RouterAgent:
    """Assign ready todos to persona workers and summarize worker returns."""

    SUMMARY_CHAR_THRESHOLD = 4000
    SUMMARY_RESULT_THRESHOLD = 3

    def __init__(self, llm_client: LLMClient) -> None:
        if llm_client is None:
            raise LLMClientError("RouterAgent requires an LLM client.")
        self.llm_client = llm_client

    def route(
        self,
        state: RunState,
        *,
        worker_catalog: list[dict[str, object]],
        max_assignments: int,
    ) -> RouterDecision:
        ready = self._ready_todos_for_focus_phase(state, max_assignments=max_assignments)
        if not ready:
            return RouterDecision(rationale="No ready todos.")
        focus_phase = ready[0].phase
        snapshot = {
            "objective": state.objective,
            "summary": state.summary(),
            "focus_phase": focus_phase,
            "ready_todos": [self._serialize_todo(todo) for todo in ready],
            "worker_catalog": worker_catalog,
            "recent_round_summaries": [
                round_record.summary.model_dump(mode="json")
                for round_record in state.rounds[-8:]
            ],
            "contract": (
                "Choose one persona worker for each selected todo. "
                "Return RouterDecision.assignments with todo_id and worker_name only."
            ),
        }
        decision = self.llm_client.generate_json(
            system_prompt=(
                "You are RouterAgent in a planner-router-worker CTF workflow. "
                "Assign ready high-level todos to the best persona worker from "
                "the provided worker_catalog. Do not invent worker names. "
                "Return only JSON matching RouterDecision."
            ),
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterDecision,
            temperature=0.1,
        )
        return self._validated_decision(decision, ready, worker_catalog, max_assignments)

    def summarize_round(
        self,
        state: RunState,
        *,
        results: list[WorkerResult],
    ) -> RouterRoundSummary:
        result_lines = [
            f"{result.worker_name}({result.todo_id}): {result.summary}"
            for result in results
        ]
        total_chars = sum(len(line) for line in result_lines)
        if len(results) <= self.SUMMARY_RESULT_THRESHOLD and total_chars <= self.SUMMARY_CHAR_THRESHOLD:
            return RouterRoundSummary(
                summary="; ".join(result_lines) if result_lines else "No worker results.",
                direct_results=result_lines,
                key_findings=[
                    result.summary for result in results
                    if result.success and result.summary
                ][:8],
                next_focus="",
                used_llm=False,
            )
        snapshot = {
            "objective": state.objective,
            "state_summary": state.summary(),
            "worker_results": [
                {
                    "todo_id": result.todo_id,
                    "worker_name": result.worker_name,
                    "success": result.success,
                    "summary": result.summary,
                    "error": result.error,
                    "output_context": self._trim_mapping(result.output_context),
                    "notes": result.notes[-6:],
                }
                for result in results
            ],
        }
        summary = self.llm_client.generate_json(
            system_prompt=(
                "Summarize this router execution round for the next planner call. "
                "Preserve confirmed facts, failures, and the best next focus. "
                "Return only JSON matching RouterRoundSummary."
            ),
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterRoundSummary,
            temperature=0.1,
        )
        summary.used_llm = True
        return summary

    def _validated_decision(
        self,
        decision: RouterDecision,
        ready: list[TodoItem],
        worker_catalog: list[dict[str, object]],
        max_assignments: int,
    ) -> RouterDecision:
        ready_ids = {todo.todo_id for todo in ready}
        worker_names = {str(worker.get("name") or "") for worker in worker_catalog}
        assignments: list[WorkerAssignment] = []
        seen: set[str] = set()
        for assignment in decision.assignments:
            if assignment.todo_id not in ready_ids or assignment.todo_id in seen:
                continue
            if assignment.worker_name not in worker_names:
                continue
            assignments.append(assignment)
            seen.add(assignment.todo_id)
            if len(assignments) >= max(1, max_assignments):
                break
        if assignments:
            return RouterDecision(assignments=assignments, rationale=decision.rationale)
        fallback = ready[0]
        worker_name = self._fallback_worker_name(fallback, worker_catalog)
        return RouterDecision(
            assignments=[
                WorkerAssignment(
                    todo_id=fallback.todo_id,
                    worker_name=worker_name,
                    rationale="Fallback assignment after router returned no valid assignments.",
                )
            ],
            rationale=decision.rationale or "Fallback assignment used.",
        )

    @staticmethod
    def _ready_todos_for_focus_phase(state: RunState, *, max_assignments: int) -> list[TodoItem]:
        ready = state.ready_todos(limit=None)
        if not ready:
            return []
        focus_phase = min((todo.phase for todo in ready), key=todo_phase_rank)
        return [todo for todo in ready if todo.phase == focus_phase][: max(1, max_assignments)]

    @staticmethod
    def _fallback_worker_name(todo: TodoItem, worker_catalog: list[dict[str, object]]) -> str:
        goal = todo.goal.lower()
        context = todo.context
        preferred = "artifact-worker"
        if todo.phase == TodoPhase.FLAG_VALIDATION or _has_flag_candidate_context(context):
            preferred = "flag-worker"
        elif "scope" in context or "recon" in goal:
            preferred = "recon-worker"
        elif todo.phase == TodoPhase.ANALYSIS or _has_file_context(context):
            preferred = "artifact-worker"
        elif "base_url" in context or "path" in goal or "web" in goal or "http" in goal:
            preferred = "web-worker"
        elif "exploit" in goal or "vuln" in goal or "credential" in goal:
            preferred = "exploit-worker"
        names = {str(worker.get("name") or "") for worker in worker_catalog}
        if preferred in names:
            return preferred
        return next(iter(names), "")

    @staticmethod
    def _serialize_todo(todo: TodoItem) -> dict[str, object]:
        return {
            "todo_id": todo.todo_id,
            "goal": todo.goal,
            "phase": todo.phase,
            "context": todo.context,
            "priority": todo.priority,
            "success_criteria": todo.success_criteria,
            "constraints": todo.constraints,
            "attempts": todo.attempts,
            "error": todo.error,
        }

    @staticmethod
    def _trim_mapping(value: dict[str, object]) -> dict[str, object]:
        trimmed: dict[str, object] = {}
        for key, item in value.items():
            text = str(item)
            trimmed[key] = text[:1000] if len(text) > 1000 else item
        return trimmed


def _has_flag_candidate_context(context: dict[str, object]) -> bool:
    return any(
        context.get(key)
        for key in (
            "candidate_flag",
            "candidate_flags",
            "flag_candidate",
            "flag_candidates",
            "flag_candidate_id",
            "flag_candidate_ids",
        )
    )


def _has_file_context(context: dict[str, object]) -> bool:
    return any(
        context.get(key)
        for key in (
            "files_root",
            "challenge_files",
            "source_files",
            "binary_files",
            "archive_files",
            "database_files",
            "pcap_files",
            "repo_paths",
            "text_files",
        )
    )
