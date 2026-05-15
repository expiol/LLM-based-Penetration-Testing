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

_ROUTER_SYSTEM_PROMPT = """\
You are RouterAgent in a planner-router-worker CTF workflow.
Assign each ready todo to the single best persona worker from the catalog.

Worker domain guide:
- recon-worker: First-pass scope mapping only (HTTP headers, TCP banners, host inventory).
- artifact-worker: Static file analysis (source review, binary triage, disassembly, pcap, \
archives) AND script execution for offline computation.
- web-worker: HTTP interactions (content fetch, path probing, form submission, login) \
and multi-step web exploits requiring scripting.
- exploit-worker: Script execution against live targets, binary execution, credential \
harvesting, vulnerability probes.
- flag-worker: Final flag validation only.

IMPORTANT: Choose the worker whose CAPABILITIES match the task requirements. \
A web-themed task that requires script execution should go to exploit-worker or \
web-worker (both have SCRIPT_EXECUTE), not recon-worker. \
A task analyzing local files should go to artifact-worker even if the challenge is web-themed.

Do not invent worker names. Return only JSON matching RouterDecision.
"""


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

        # Structural invariant: flag_validation always goes to flag-worker
        flag_todos = [t for t in ready if t.phase == TodoPhase.FLAG_VALIDATION]
        non_flag_todos = [t for t in ready if t.phase != TodoPhase.FLAG_VALIDATION]

        assignments: list[WorkerAssignment] = []
        if flag_todos and "flag-worker" in {str(w.get("name") or "") for w in worker_catalog}:
            for todo in flag_todos:
                assignments.append(WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name="flag-worker",
                    rationale="Structural: flag_validation phase.",
                ))

        if non_flag_todos:
            llm_decision = self._llm_route(state, non_flag_todos, worker_catalog)
            validated = self._validated_decision(llm_decision, state, non_flag_todos, worker_catalog)
            assignments.extend(validated)

        if not assignments:
            return RouterDecision(rationale="No valid assignments.")
        return RouterDecision(assignments=assignments[:max(1, max_assignments)])

    def _llm_route(
        self,
        state: RunState,
        ready: list[TodoItem],
        worker_catalog: list[dict[str, object]],
    ) -> RouterDecision:
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
        return self.llm_client.generate_json(
            system_prompt=_ROUTER_SYSTEM_PROMPT,
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterDecision,
            temperature=0.1,
        )

    def _validated_decision(
        self,
        decision: RouterDecision,
        state: RunState,
        ready: list[TodoItem],
        worker_catalog: list[dict[str, object]],
    ) -> list[WorkerAssignment]:
        ready_ids = {t.todo_id for t in ready}
        worker_names = {str(w.get("name") or "") for w in worker_catalog}
        valid: list[WorkerAssignment] = []
        invalid_reasons: list[str] = []
        seen: set[str] = set()

        for a in decision.assignments:
            if a.todo_id not in ready_ids or a.todo_id in seen:
                continue
            if a.worker_name not in worker_names:
                invalid_reasons.append(f"{a.worker_name} not in catalog")
                continue
            seen.add(a.todo_id)
            valid.append(a)

        if valid:
            return valid

        # Retry once with feedback
        if invalid_reasons:
            return self._retry_route(state, ready, worker_catalog, invalid_reasons)
        return []

    def _retry_route(
        self,
        state: RunState,
        ready: list[TodoItem],
        worker_catalog: list[dict[str, object]],
        errors: list[str],
    ) -> list[WorkerAssignment]:
        worker_names = {str(w.get("name") or "") for w in worker_catalog}
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
            "previous_errors": (
                f"Previous attempt failed: {'; '.join(errors)}. "
                f"Valid workers: {sorted(worker_names)}. Try again."
            ),
        }
        retry_decision = self.llm_client.generate_json(
            system_prompt=_ROUTER_SYSTEM_PROMPT,
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterDecision,
            temperature=0.2,
        )
        # Validate retry — no further retries
        ready_ids = {t.todo_id for t in ready}
        valid: list[WorkerAssignment] = []
        seen: set[str] = set()
        for a in retry_decision.assignments:
            if a.todo_id not in ready_ids or a.todo_id in seen:
                continue
            if a.worker_name not in worker_names:
                continue
            seen.add(a.todo_id)
            valid.append(a)
        return valid

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

    @staticmethod
    def _ready_todos_for_focus_phase(state: RunState, *, max_assignments: int) -> list[TodoItem]:
        ready = state.ready_todos(limit=None)
        if not ready:
            return []
        focus_phase = min((todo.phase for todo in ready), key=todo_phase_rank)
        return [todo for todo in ready if todo.phase == focus_phase][: max(1, max_assignments)]

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
