"""RouterAgent for persona-worker assignment and round summarization."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import TYPE_CHECKING

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.prompt_bounds import bounded_value
from killchain_docker.prompt_projection import router_todo as prompt_router_todo
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

if TYPE_CHECKING:  # pragma: no cover
    from killchain_docker.workers.base import WorkerAgent

_ROUTER_SYSTEM_PROMPT = """\
You are RouterAgent in a planner-router-worker CTF workflow.
Assign each ready todo to the single best persona worker from the catalog.

Worker domain guide (all workers have shell.exec and script.exec capabilities):
- recon-worker: First-pass scope mapping (nmap, curl headers, dig, host inventory).
- artifact-worker: Static file analysis (file, strings, binwalk, r2, objdump, tshark, \
sqlite3) AND script execution for offline computation.
- web-worker: HTTP interactions (curl, wget, sqlmap, form submission, login) \
and multi-step web exploits requiring scripting.
- exploit-worker: Exploit execution against live targets, binary exploitation, credential \
attacks, vulnerability probes.
- flag-worker: Final flag validation only.

IMPORTANT: Choose the worker whose DOMAIN EXPERTISE matches the task requirements. \
A web-themed task that requires exploit scripting should go to exploit-worker or \
web-worker, not recon-worker. \
A task analyzing local files should go to artifact-worker even if the challenge is web-themed.

Do not invent worker names. Return only JSON matching RouterDecision.
"""


class WorkerDirectory:
    """Typed view over Persona Workers used by Router and Orchestrator."""

    def __init__(
        self,
        *,
        workers: Iterable["WorkerAgent"],
    ) -> None:
        self._workers = {worker.name: worker for worker in workers}
        self._catalog = [
            self._catalog_entry(worker)
            for worker in self._workers.values()
        ]
        self._worker_names = {
            str(item.get("name") or "")
            for item in self._catalog
            if str(item.get("name") or "")
        }

    @classmethod
    def from_workers(cls, workers: Iterable["WorkerAgent"]) -> "WorkerDirectory":
        return cls(workers=workers)

    @staticmethod
    def _catalog_entry(worker: "WorkerAgent") -> dict[str, object]:
        return {
            "name": worker.name,
            "supported_todo_kinds": list(worker.supported_todo_kinds),
            "routing_summary": worker.routing_summary,
            "required_context_keys": list(worker.required_context_keys),
            "preferred_challenge_categories": list(worker.preferred_challenge_categories),
        }

    @property
    def worker_names(self) -> set[str]:
        return set(self._worker_names)

    def prompt_catalog(self) -> list[dict[str, object]]:
        return [dict(item) for item in self._catalog]

    def select(
        self,
        worker_name: str,
        todo: TodoItem,
        state: RunState,
    ) -> tuple["WorkerAgent | None", str]:
        worker = self._workers.get(worker_name)
        if worker is None:
            return None, f"router selected unknown worker {worker_name!r}"
        allowed, reason = worker.can_route_task(todo, state)
        if not allowed:
            return None, reason or "worker rejected todo"
        return worker, ""


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
        worker_directory: WorkerDirectory,
        max_assignments: int,
    ) -> RouterDecision:
        ready = self._ready_todos_for_focus_phase(state, max_assignments=max_assignments)
        if not ready:
            return RouterDecision(rationale="No ready todos.")

        # Structural invariant: flag_validation always goes to flag-worker
        flag_todos = [t for t in ready if t.phase == TodoPhase.FLAG_VALIDATION]
        non_flag_todos = [t for t in ready if t.phase != TodoPhase.FLAG_VALIDATION]

        assignments: list[WorkerAssignment] = []
        if flag_todos and "flag-worker" in worker_directory.worker_names:
            for todo in flag_todos:
                assignments.append(WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name="flag-worker",
                    rationale="Structural: flag_validation phase.",
                ))

        if non_flag_todos:
            llm_decision = self._llm_route(state, non_flag_todos, worker_directory)
            validated = self._validated_decision(llm_decision, non_flag_todos, worker_directory)
            assignments.extend(validated)

        if not assignments:
            return RouterDecision(rationale="No valid assignments.")
        return RouterDecision(assignments=assignments[:max(1, max_assignments)])

    def _llm_route(
        self,
        state: RunState,
        ready: list[TodoItem],
        worker_directory: WorkerDirectory,
    ) -> RouterDecision:
        focus_phase = ready[0].phase
        snapshot = {
            "objective": state.objective,
            "summary": state.summary(),
            "focus_phase": focus_phase,
            "ready_todos": [prompt_router_todo(todo) for todo in ready],
            "worker_catalog": worker_directory.prompt_catalog(),
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
        ready: list[TodoItem],
        worker_directory: WorkerDirectory,
    ) -> list[WorkerAssignment]:
        ready_ids = {t.todo_id for t in ready}
        worker_names = worker_directory.worker_names
        valid: list[WorkerAssignment] = []
        seen: set[str] = set()

        for a in decision.assignments:
            if a.todo_id not in ready_ids or a.todo_id in seen:
                continue
            if a.worker_name not in worker_names:
                continue
            seen.add(a.todo_id)
            valid.append(a)

        if valid:
            return valid

        return []

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
                    "output_context": self._bounded_mapping(result.output_context),
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
    def _bounded_mapping(value: dict[str, object]) -> dict[str, object]:
        bounded = bounded_value(value, width=800, list_limit=8, dict_limit=14)
        return bounded if isinstance(bounded, dict) else {}
