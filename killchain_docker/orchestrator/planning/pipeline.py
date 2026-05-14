"""Planning pipeline for seed, normalization, dedupe, and progress gates."""

from __future__ import annotations

from killchain_docker.orchestrator.planning.schemas import (
    PlannedTodo,
    PlannerAgent,
    PlannerDecision,
)
from killchain_docker.orchestrator.policy import CandidatePolicy, ProgressPolicy, TodoPolicy
from killchain_docker.state import RunState, TodoPhase, TodoStatus, todo_phase_rank


class PlanningPipeline(PlannerAgent):
    """Deterministic planner post-processor and seed planner.

    The LLM planner proposes intent.  This pipeline decides which proposed
    todos are allowed to enter the queue.
    """

    def plan(self, state: RunState) -> PlannerDecision:
        todos, notes = self.seed_todos(state)
        return PlannerDecision(
            summary=f"Planning pipeline proposed {len(todos)} seed todo(s).",
            todos=todos,
            notes=notes,
        )

    def merge(
        self,
        state: RunState,
        *,
        llm_decision: PlannerDecision | None,
    ) -> PlannerDecision:
        seed_todos, seed_notes = self.seed_todos(state)
        llm_todos = list((llm_decision.todos if llm_decision else []) or [])
        notes = list((llm_decision.notes if llm_decision else []) or [])
        notes.extend(seed_notes)

        normalized: list[PlannedTodo] = []
        for todo in [*seed_todos, *llm_todos]:
            TodoPolicy.normalize(todo, state)
            normalized.append(todo)

        deduped, dedupe_notes = self._dedupe(normalized, state)
        gated, gate_notes = self._phase_gate(deduped, state)
        allowed, progress_notes = self._progress_gate(gated, state)

        return PlannerDecision(
            summary=(llm_decision.summary if llm_decision else "")
            or f"Planning pipeline proposed {len(allowed)} todo(s).",
            todos=allowed,
            notes=[*notes, *dedupe_notes, *gate_notes, *progress_notes],
            stop_run=bool(llm_decision.stop_run) if llm_decision else False,
        )

    def seed_todos(self, state: RunState) -> tuple[list[PlannedTodo], list[str]]:
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        challenge = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge.get("files", []) or [])

        if challenge_files and not self._has_todo_key(state, "bootstrap:artifact-inventory"):
            todos.append(
                PlannedTodo(
                    goal="Inventory and classify bundled challenge files.",
                    phase=TodoPhase.RECON,
                    priority=95,
                    context={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "challenge_files": challenge_files,
                        "family": "artifact-inventory",
                        "capability_hint": "artifact.triage",
                    },
                    success_criteria=[
                        "Classify files by kind.",
                        "Surface source, binary, archive, database, pcap, repo, and flag-like evidence.",
                    ],
                    constraints=["Use only files under /home/ctfplayer/ctf_files."],
                    dedupe_key="bootstrap:artifact-inventory",
                )
            )

        for candidate in CandidatePolicy.validation_ready_candidates(state)[:4]:
            dedupe_key = f"bootstrap:flag-validation:{candidate.value}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal="Validate recovered flag candidate.",
                    phase=TodoPhase.FLAG_VALIDATION,
                    priority=100,
                    context={
                        "candidate_flag": candidate.value,
                        "flag_candidate_id": candidate.candidate_id,
                        "family": "flag-validation",
                    },
                    success_criteria=["Confirm whether the candidate is the challenge flag."],
                    constraints=["Validate only grounded candidates already present in state."],
                    dedupe_key=dedupe_key,
                )
            )

        for index, scope in enumerate(state.authorized_scope, start=1):
            dedupe_key = f"bootstrap:scope:{scope}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal=f"Map authorized scope entry {index}.",
                    phase=TodoPhase.RECON,
                    priority=100,
                    context={
                        "scope": scope,
                        "asset_id": "seed-asset" if len(state.authorized_scope) == 1 else f"seed-asset-{index}",
                        "family": "recon",
                    },
                    success_criteria=[
                        "Create or update a tracked asset.",
                        "Collect first-pass service or HTTP metadata when possible.",
                    ],
                    constraints=["Stay inside the authorized scope entry."],
                    dedupe_key=dedupe_key,
                )
            )

        if not todos and not state.todos:
            notes.append("No authorized scope or challenge files are available for bootstrap.")
        return todos, notes

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return any(todo.dedupe_key == dedupe_key for todo in state.todos)

    def _dedupe(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        seen = {todo.dedupe_key for todo in state.todos if todo.dedupe_key}
        out: list[PlannedTodo] = []
        dropped = 0
        for todo in todos:
            if not todo.dedupe_key:
                todo.dedupe_key = TodoPolicy.default_key(todo)
            if todo.dedupe_key in seen:
                dropped += 1
                continue
            seen.add(todo.dedupe_key)
            out.append(todo)
        notes = [f"Planning pipeline dropped {dropped} duplicate todo(s)."] if dropped else []
        return out, notes

    def _phase_gate(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        focus = self._frontier_phase(todos, state)
        if focus is None:
            return todos, []

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
                f"Planning phase gate kept {focus.value} todos and dropped "
                f"{len(phase_dropped)} todo(s) from other phases."
            )
        if grounding_dropped:
            notes.append(
                f"Planning phase gate dropped {len(grounding_dropped)} ungrounded "
                f"{focus.value} todo(s)."
            )
        return kept, notes

    def _progress_gate(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        out: list[PlannedTodo] = []
        notes: list[str] = []
        for todo in todos:
            allowed, reason = ProgressPolicy.allows(todo, state)
            if allowed:
                out.append(todo)
            else:
                notes.append(f"Planning progress gate dropped todo: {reason}.")
        return out, notes

    @staticmethod
    def _frontier_phase(todos: list[PlannedTodo], state: RunState) -> TodoPhase | None:
        open_phases = [
            todo.phase
            for todo in state.todos
            if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
        ]
        if open_phases:
            return min(open_phases, key=todo_phase_rank)
        if todos and CandidatePolicy.validation_ready_candidates(state):
            if any(todo.phase == TodoPhase.FLAG_VALIDATION for todo in todos):
                return TodoPhase.FLAG_VALIDATION
        if todos:
            return min((todo.phase for todo in todos), key=todo_phase_rank)
        return None

    @staticmethod
    def _grounded(todo: PlannedTodo, state: RunState) -> bool:
        context = todo.context or {}
        if todo.phase == TodoPhase.EXPLOIT:
            return bool(
                state.findings
                or state.vulnerabilities
                or state.credentials
                or state.sessions
                or state.hypotheses
                or state.evidence
                or any(
                    context.get(key)
                    for key in (
                        "finding_id",
                        "finding_ids",
                        "vulnerability_id",
                        "vulnerability_ids",
                        "credential_id",
                        "credential_ids",
                        "session_id",
                        "session_ids",
                        "hypothesis_id",
                        "hypothesis_ids",
                        "evidence_id",
                        "evidence_ids",
                    )
                )
            )
        if todo.phase == TodoPhase.FLAG_VALIDATION:
            return CandidatePolicy.first_candidate_from_context(state, context, todo.goal) is not None
        return True


class TodoNormalizer:
    """Compatibility facade backed by :class:`TodoPolicy`."""

    def fill(self, todo: PlannedTodo, state: RunState) -> None:
        TodoPolicy.normalize(todo, state)


class TodoDeduper:
    """Compatibility facade backed by the pipeline dedupe rule."""

    def merge(
        self,
        proposed: list[PlannedTodo],
        state: RunState,
        existing_keys: set[str] | None = None,
    ) -> list[PlannedTodo]:
        pipeline = PlanningPipeline()
        for todo in proposed:
            TodoPolicy.normalize(todo, state)
        merged, _notes = pipeline._dedupe(proposed, state)
        if existing_keys:
            merged = [todo for todo in merged if todo.dedupe_key not in existing_keys]
        return merged


BootstrapSeeder = PlanningPipeline
