"""Structural assignment planning before optional LLM routing fallback."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch.types import AgentDirectoryView
from killchain_docker.orchestrator.dispatch.candidates import DispatchRoutePolicy
from killchain_docker.state.todos import (
    RouterDecision,
    TodoItem,
    TodoPhase,
    WorkerAssignment,
)


class AssignmentPlanner:
    """Build structural worker assignments before optional LLM fallback."""

    def __init__(self, agent_directory: AgentDirectoryView) -> None:
        self.agent_directory = agent_directory

    def deterministic_assignment(
        self, todo: TodoItem, state
    ) -> WorkerAssignment | None:
        if (
            todo.phase == TodoPhase.FLAG_VALIDATION
            and "flag-worker" in self.agent_directory.worker_names
        ):
            worker, _reason = self.agent_directory.select("flag-worker", todo, state)
            if worker is not None:
                return WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name="flag-worker",
                    rationale="Structural: flag_validation phase.",
                )
        for worker_name, rationale in DispatchRoutePolicy.worker_candidates(
            todo, self.agent_directory
        ):
            worker, _reason = self.agent_directory.select(worker_name, todo, state)
            if worker is None:
                continue
            return WorkerAssignment(
                todo_id=todo.todo_id, worker_name=worker_name, rationale=rationale
            )
        return None

    def deterministic_decision(self, todos: list[TodoItem], state) -> RouterDecision:
        assignments = [
            assignment
            for todo in todos
            if (assignment := self.deterministic_assignment(todo, state)) is not None
        ]
        if not assignments:
            return RouterDecision(rationale="No structural assignments.")
        return RouterDecision(assignments=assignments, rationale="Structural dispatch.")

    def plan_batch(
        self, todos: list[TodoItem], state
    ) -> tuple[list[WorkerAssignment], list[TodoItem]]:
        assignments: list[WorkerAssignment] = []
        llm_ready: list[TodoItem] = []
        seen: set[str] = set()
        for todo in todos:
            assignment = self.deterministic_assignment(todo, state)
            if assignment is None:
                llm_ready.append(todo)
                continue
            if assignment.todo_id in seen:
                continue
            seen.add(assignment.todo_id)
            assignments.append(assignment)
        return (assignments, llm_ready)

    def validate_llm_decision(
        self, decision: RouterDecision, ready: list[TodoItem]
    ) -> list[WorkerAssignment]:
        ready_ids = {todo.todo_id for todo in ready}
        valid: list[WorkerAssignment] = []
        seen: set[str] = set()
        for assignment in decision.assignments:
            if assignment.todo_id not in ready_ids or assignment.todo_id in seen:
                continue
            if assignment.worker_name not in self.agent_directory.worker_names:
                continue
            seen.add(assignment.todo_id)
            valid.append(assignment)
        return valid


__all__ = ["AssignmentPlanner"]
