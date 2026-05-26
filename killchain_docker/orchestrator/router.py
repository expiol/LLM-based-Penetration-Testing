"""RouterAgent for persona-worker assignment and round summarization."""

from __future__ import annotations
import json
from killchain_docker.llm.gateway import LLMClient, LLMClientError
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.dispatch_types import select_ready_batch
from killchain_docker.orchestrator.assignment_planner import AssignmentPlanner
from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.prompt_bounds import bounded_value
from killchain_docker.prompt_projection import router_todo as prompt_router_todo
from killchain_docker.state.run_state import RunState
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.todos import (
    RouterDecision,
    RouterRoundSummary,
    TodoItem,
    WorkerResult,
)

_ROUTER_SYSTEM_PROMPT = "You are RouterAgent in a planner-router-worker workflow.\nAssign each ready todo to one eligible persona worker from agent_catalog.\nUse the catalog entries and todo context only; do not invent worker names.\nReturn only JSON matching RouterDecision.\n"


class RouterAgent:
    """Assign ready todos to persona workers and summarize worker returns."""

    SUMMARY_CHAR_THRESHOLD = 4000
    SUMMARY_RESULT_THRESHOLD = 3

    def __init__(self, llm_client: LLMClient) -> None:
        if llm_client is None:
            raise LLMClientError("RouterAgent requires an LLM client.")
        self.llm_client = llm_client

    def route(
        self, state: RunState, *, agent_directory: AgentDirectory, max_assignments: int
    ) -> RouterDecision:
        batch = select_ready_batch(TodoQueue(state), max_assignments=max_assignments)
        ready = batch.todos
        if not ready:
            return RouterDecision(rationale="No ready todos.")
        planner = AssignmentPlanner(agent_directory)
        assignments, llm_ready = planner.plan_batch(ready, state)
        if llm_ready:
            llm_decision = self._llm_route(state, llm_ready, agent_directory)
            assignments.extend(planner.validate_llm_decision(llm_decision, llm_ready))
        if not assignments:
            return RouterDecision(rationale="No valid assignments.")
        return RouterDecision(assignments=assignments[: max(1, max_assignments)])

    def _llm_route(
        self, state: RunState, ready: list[TodoItem], agent_directory: AgentDirectory
    ) -> RouterDecision:
        focus_phase = ready[0].phase
        report_projection = RunReportProjection(state)
        snapshot = {
            "objective": state.objective,
            "summary": report_projection.summary(),
            "focus_phase": focus_phase,
            "ready_todos": [prompt_router_todo(todo) for todo in ready],
            "agent_catalog": agent_directory.prompt_catalog(),
            "recent_round_summaries": report_projection.router_round_summaries(),
            "contract": "Choose one persona worker for each selected todo. Return RouterDecision.assignments with todo_id and worker_name only.",
        }
        return self.llm_client.generate_json(
            system_prompt=_ROUTER_SYSTEM_PROMPT,
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterDecision,
            temperature=0.1,
        )

    def summarize_round(
        self, state: RunState, *, results: list[WorkerResult]
    ) -> RouterRoundSummary:
        result_lines = [
            f"{result.worker_name}({result.todo_id}): {result.summary}"
            for result in results
        ]
        total_chars = sum((len(line) for line in result_lines))
        if (
            len(results) <= self.SUMMARY_RESULT_THRESHOLD
            and total_chars <= self.SUMMARY_CHAR_THRESHOLD
        ):
            return RouterRoundSummary(
                summary="; ".join(result_lines)
                if result_lines
                else "No worker results.",
                direct_results=result_lines,
                key_findings=[
                    result.summary
                    for result in results
                    if result.success and result.summary
                ][:8],
                next_focus="",
                used_llm=False,
            )
        snapshot = {
            "objective": state.objective,
            "state_summary": RunReportProjection(state).summary(),
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
            system_prompt="Summarize this router execution round for the next planner call. Preserve confirmed facts, failures, and the best next focus. Return only JSON matching RouterRoundSummary.",
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=RouterRoundSummary,
            temperature=0.1,
        )
        summary.used_llm = True
        return summary

    @staticmethod
    def _bounded_mapping(value: dict[str, object]) -> dict[str, object]:
        bounded = bounded_value(value, width=800, list_limit=8, dict_limit=14)
        return bounded if isinstance(bounded, dict) else {}
