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

        # Seed near-miss refinement todos: garbled output is a strong signal
        # that the algorithm is correct but has a byte-level encoding error.
        for evidence_id, evidence in list(state.evidence.items()):
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context") or {}
            near_misses = list(ctx.get("near_miss_candidates") or [])
            if not near_misses:
                continue
            dedupe_key = f"bootstrap:near-miss-refinement:{evidence_id}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal="Refine decryption script: near-miss output detected — fix byte-level encoding error.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={
                        "family": "crypto-decrypt",
                        "evidence_ids": [evidence_id],
                        "near_miss_candidates": near_misses[:3],
                        "novelty_key": f"near-miss:{evidence_id}",
                        "files_root": str(ctx.get("files_root") or "/home/ctfplayer/ctf_files"),
                        "challenge_files": challenge_files,
                    },
                    success_criteria=["Produce a valid flag candidate from the near-miss output."],
                    constraints=["Try: bytes.fromhex(), base64.b64decode(), latin-1 decode, XOR with 0xFF."],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded near-miss refinement todo for evidence {evidence_id}.")

        if not todos and not state.todos:
            notes.append("No authorized scope or challenge files are available for bootstrap.")
        return todos, notes

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return any(todo.dedupe_key == dedupe_key for todo in state.todos)

    # Atomic recon families: at most one open/done todo of this family per
    # files_root.  Re-running them adds no signal beyond the first execution.
    _ATOMIC_RECON_FAMILIES = frozenset({"artifact-inventory", "recon"})

    def _dedupe(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        # Only block against pending/running todos and successfully completed ones.
        # Partial todos should not block re-attempts with the same key.
        seen = {
            todo.dedupe_key
            for todo in state.todos
            if todo.dedupe_key and todo.status != TodoStatus.PARTIAL
        }
        atomic_seen: set[tuple[str, str]] = set()
        for todo in state.todos:
            family = str(todo.context.get("family") or "")
            if family in self._ATOMIC_RECON_FAMILIES and todo.phase == TodoPhase.RECON:
                atomic_seen.add((family, str(todo.context.get("files_root") or "")))
        out: list[PlannedTodo] = []
        dropped = 0
        for todo in todos:
            if not todo.dedupe_key:
                todo.dedupe_key = TodoPolicy.default_key(todo)
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
                # Only force FLAG_VALIDATION if the family is not in cooldown
                _, failed = ProgressPolicy._family_counts(state, "flag-validation")
                if failed < ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD:
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
