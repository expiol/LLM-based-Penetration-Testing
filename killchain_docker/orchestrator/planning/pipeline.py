"""Planning pipeline for normalization, dedupe, and progress gates."""

from __future__ import annotations
from killchain_docker.orchestrator.planning.schemas import (
    PlannedTodo,
    PlannerAgent,
    PlannerDecision,
)
from killchain_docker.orchestrator.planning.dependency_gate import (
    gate_planned_dependencies,
)
from killchain_docker.orchestrator.planning.seed_planner import PlanningSeedPlanner
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.progress_families import family_counts
from killchain_docker.orchestrator.progress_gate import progress_allows
from killchain_docker.orchestrator.progress_limits import FAILURE_COOLDOWN_THRESHOLD
from killchain_docker.orchestrator.todo_keys import default_key
from killchain_docker.orchestrator.todo_normalization import normalize_todo
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.scope_guard import (
    todo_ephemeral_artifact_dependency_reason,
    todo_loopback_block_reason,
    todo_registered_scratch_dependency_reason,
)
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.grounding_projection import GroundingProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.scope_projection import ScopeProjection
from killchain_docker.state.todos import TodoPhase, todo_phase_rank


class PlanningPipeline(PlannerAgent):
    """Deterministic planner post-processor and seed planner.

    The LLM planner proposes intent.  This pipeline decides which proposed
    todos are allowed to enter the queue.
    """

    def __init__(self, seed_planner: PlanningSeedPlanner | None = None) -> None:
        self.seed_planner = seed_planner or PlanningSeedPlanner()

    def plan(self, state: RunState) -> PlannerDecision:
        todos, notes = self.seed_planner.seed_todos(state)
        return PlannerDecision(
            summary=f"Planning pipeline proposed {len(todos)} seed todo(s).",
            todos=todos,
            notes=notes,
        )

    def merge(
        self, state: RunState, *, llm_decision: PlannerDecision | None
    ) -> PlannerDecision:
        llm_todos = list((llm_decision.todos if llm_decision else []) or [])
        seed_todos, seed_notes = self.seed_planner.seed_todos(
            state,
            include_execution_closure_seed=self.seed_planner.include_execution_closure_seed(
                state, llm_todos
            ),
        )
        notes = list((llm_decision.notes if llm_decision else []) or [])
        notes.extend(seed_notes)
        normalized: list[PlannedTodo] = []
        for todo in [*seed_todos, *llm_todos]:
            normalize_todo(todo, state)
            normalized.append(todo)
        deduped, dedupe_notes = self._dedupe(normalized, state)
        dependency_gated, dependency_notes = self._dependency_gate(deduped, state)
        gated, gate_notes = self._phase_gate(dependency_gated, state)
        scoped, scope_notes = self._scope_gate(gated, state)
        progress_gated, progress_notes = self._progress_gate(scoped, state)
        allowed, final_dependency_notes = self._dependency_gate(progress_gated, state)
        return PlannerDecision(
            summary=(llm_decision.summary if llm_decision else "")
            or f"Planning pipeline proposed {len(allowed)} todo(s).",
            todos=allowed,
            notes=[
                *notes,
                *dedupe_notes,
                *dependency_notes,
                *gate_notes,
                *scope_notes,
                *progress_notes,
                *final_dependency_notes,
            ],
            stop_run=bool(llm_decision.stop_run) if llm_decision else False,
        )

    _ATOMIC_RECON_FAMILIES = frozenset({"artifact-inventory", "recon"})

    def _dedupe(
        self, todos: list[PlannedTodo], state: RunState
    ) -> tuple[list[PlannedTodo], list[str]]:
        queue = TodoQueueReader(state)
        seen = queue.dedupe_keys()
        atomic_seen = queue.atomic_recon_keys(set(self._ATOMIC_RECON_FAMILIES))
        validation_seen = queue.active_validation_candidates(
            lambda todo: CandidatePolicy.first_candidate_from_context(
                state, todo.context, todo.goal
            )
        )
        out: list[PlannedTodo] = []
        dropped = 0
        for todo in todos:
            if not todo.dedupe_key:
                todo.dedupe_key = default_key(todo)
            if todo.dedupe_key in seen:
                dropped += 1
                continue
            family = str(todo.context.get("family") or "")
            if family in self._ATOMIC_RECON_FAMILIES and todo.phase == TodoPhase.RECON:
                atomic_key = (family, str(todo.context.get("files_root") or ""))
                if atomic_key in atomic_seen:
                    dropped += 1
                    continue
                atomic_seen.add(atomic_key)
            if todo.phase == TodoPhase.FLAG_VALIDATION:
                candidate = CandidatePolicy.first_candidate_from_context(
                    state, todo.context, todo.goal
                )
                if candidate and candidate in validation_seen:
                    dropped += 1
                    continue
                if candidate:
                    validation_seen.add(candidate)
            seen.add(todo.dedupe_key)
            out.append(todo)
        notes = (
            [f"Planning pipeline dropped {dropped} duplicate todo(s)."]
            if dropped
            else []
        )
        return (out, notes)

    def _dependency_gate(
        self, todos: list[PlannedTodo], state: RunState
    ) -> tuple[list[PlannedTodo], list[str]]:
        return gate_planned_dependencies(todos, state)

    def _phase_gate(
        self, todos: list[PlannedTodo], state: RunState
    ) -> tuple[list[PlannedTodo], list[str]]:
        focus = self._frontier_phase(todos, state)
        if focus is None:
            return (todos, [])
        kept: list[PlannedTodo] = []
        phase_dropped: list[PlannedTodo] = []
        grounding_dropped: list[PlannedTodo] = []
        for todo in todos:
            if todo.phase != focus:
                phase_dropped.append(todo)
                continue
            if not self._grounded(todo, state):
                grounding_dropped.append(todo)
                continue
            kept.append(todo)
        notes: list[str] = []
        if phase_dropped:
            notes.append(
                f"Planning phase gate kept {focus.value} todos and dropped {len(phase_dropped)} todo(s) from other phases."
            )
        if grounding_dropped:
            notes.append(
                f"Planning phase gate dropped {len(grounding_dropped)} ungrounded {focus.value} todo(s)."
            )
        return (kept, notes)

    def _progress_gate(
        self, todos: list[PlannedTodo], state: RunState
    ) -> tuple[list[PlannedTodo], list[str]]:
        out: list[PlannedTodo] = []
        notes: list[str] = []
        for todo in todos:
            allowed, reason = progress_allows(todo, state)
            if allowed:
                out.append(todo)
            else:
                notes.append(f"Planning progress gate dropped todo: {reason}.")
        return (out, notes)

    def _scope_gate(
        self, todos: list[PlannedTodo], state: RunState
    ) -> tuple[list[PlannedTodo], list[str]]:
        kept: list[PlannedTodo] = []
        dropped = 0
        authorized_scope = ScopeProjection(state).entries()
        challenge_files = ChallengeProjection(state).files()
        artifact_paths = ArtifactProjectionStore(state).paths()
        for todo in todos:
            reason = todo_loopback_block_reason(
                goal=todo.goal,
                context=todo.context or {},
                authorized_scope=authorized_scope,
            )
            reason = reason or todo_registered_scratch_dependency_reason(
                goal=todo.goal,
                context=todo.context or {},
                allowed_artifact_paths=artifact_paths,
            )
            reason = reason or todo_ephemeral_artifact_dependency_reason(
                goal=todo.goal,
                context=todo.context or {},
                challenge_files=challenge_files,
                files_root=(todo.context or {}).get("files_root"),
                allowed_artifact_paths=artifact_paths,
            )
            if reason:
                dropped += 1
                continue
            kept.append(todo)
        notes = (
            [f"Planning scope gate dropped {dropped} out-of-scope todo(s)."]
            if dropped
            else []
        )
        return (kept, notes)

    @staticmethod
    def _frontier_phase(todos: list[PlannedTodo], state: RunState) -> TodoPhase | None:
        open_phases = TodoQueueReader(state).open_phases()
        if open_phases:
            return min(open_phases, key=todo_phase_rank)
        if todos and CandidatePolicy.validation_ready_candidates(state):
            if any((todo.phase == TodoPhase.FLAG_VALIDATION for todo in todos)):
                _, failed = family_counts(state, "flag-validation")
                if failed < FAILURE_COOLDOWN_THRESHOLD:
                    return TodoPhase.FLAG_VALIDATION
        if todos:
            return min((todo.phase for todo in todos), key=todo_phase_rank)
        return None

    @staticmethod
    def _grounded(todo: PlannedTodo, state: RunState) -> bool:
        context = todo.context or {}
        if todo.phase == TodoPhase.EXPLOIT:
            return GroundingProjection(state).exploit_grounded(context)
        if todo.phase == TodoPhase.FLAG_VALIDATION:
            return (
                CandidatePolicy.first_candidate_from_context(state, context, todo.goal)
                is not None
            )
        return True
