"""Recovery and execution-closure seed planning."""

from __future__ import annotations
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.candidate_projection import CandidateProjection
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class RecoverySeedPlanner:
    """Builds deterministic todos for validation feedback and closure runs."""

    def candidate_recovery_seeds(
        self, state: RunState, challenge_files: list[object]
    ) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return ([], [])
        expected_prefix = ChallengeProjection(state).flag_format_prefix()
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        for rejected in reversed(CandidateProjection(state).rejected_records()):
            if not self._rejection_is_actionable(rejected.reason):
                continue
            dedupe_key = f"bootstrap:candidate-recovery:{rejected.rejection_id}"
            if self._has_todo_key(state, dedupe_key):
                continue
            context: dict[str, object] = {
                "family": "candidate-recovery",
                "dispatch_intent": {"profile": "candidate_recovery"},
                "recovery_trigger": "validator_rejection",
                "rejected_candidate": {
                    "value": rejected.value,
                    "reason": rejected.reason,
                    "source": rejected.source,
                },
                "novelty_key": f"validator-rejection:{rejected.rejection_id}",
            }
            refs = EvidenceProjectionStore(state).existing_refs(rejected.evidence_refs)
            if refs:
                context["evidence_ids"] = refs[:3]
            if expected_prefix:
                context["flag_format_prefix"] = f"{expected_prefix}{{"
            if challenge_files:
                context["files_root"] = "/home/ctfplayer/ctf_files"
                context["challenge_files"] = list(challenge_files)
            todos.append(
                PlannedTodo(
                    goal="Re-derive a corrected flag candidate from the original evidence after validator rejection.",
                    phase=TodoPhase.ANALYSIS,
                    priority=96,
                    context=context,
                    success_criteria=[
                        "Explain which evidence supports or invalidates the rejected value.",
                        "Return one corrected candidate with provenance, or a blocker naming the missing fact.",
                    ],
                    constraints=[
                        "Do not resubmit the rejected value unchanged.",
                        "Use only current-state evidence and authorized challenge artifacts.",
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(
                f"Seeded candidate recovery todo from validator feedback {rejected.rejection_id}."
            )
            break
        return (todos, notes)

    def execution_closure_seed(
        self, state: RunState, challenge_files: list[object]
    ) -> PlannedTodo | None:
        if CandidatePolicy.validation_ready_candidates(state):
            return None
        if not challenge_files:
            return None
        if not self.artifact_inventory_completed(state):
            return None
        dedupe_key = "bootstrap:evidence-execution-closure"
        if self._has_todo_key(state, dedupe_key):
            return None
        return PlannedTodo(
            goal="Build and run a bounded solver harness from current evidence and local challenge artifacts.",
            phase=TodoPhase.ANALYSIS,
            priority=92,
            context={
                "family": self._execution_closure_family(state),
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": list(challenge_files),
                "dispatch_intent": {
                    "profile": "execution_closure",
                    "required_capability": "script.exec",
                },
            },
            success_criteria=[
                "Use only local artifacts or authorized runtime evidence.",
                "Return any recovered candidate through normal tool output.",
            ],
            constraints=[
                "Do not copy or guess a flag from supplemental context.",
                "Use installed tools or Python standard library; do not install packages.",
                "Keep loops and searches bounded.",
            ],
            dedupe_key=dedupe_key,
        )

    def include_execution_closure_seed(
        self, state: RunState, llm_todos: list[PlannedTodo]
    ) -> bool:
        if llm_todos:
            return False
        return self.artifact_inventory_completed(state)

    @staticmethod
    def artifact_inventory_completed(state: RunState) -> bool:
        return TodoQueueReader(state).completed_dedupe_key(
            "bootstrap:artifact-inventory"
        )

    @staticmethod
    def _execution_closure_family(state: RunState) -> str:
        category = ChallengeProjection(state).category_raw()
        if category in {"forensics", "forensic", "stego", "steganography"}:
            return "forensics-extract"
        if category in {"rev", "reversing", "pwn"}:
            return "algorithm-verification"
        if category in {"crypto", "cryptography", "misc"}:
            return "algorithm-verification"
        return "technical-context-execution"

    @staticmethod
    def _rejection_is_actionable(reason: str) -> bool:
        return reason not in {
            "empty_candidate",
            "escaped_byte_candidate",
            "invalid_candidate_shape",
            "invalid_prefix_candidate",
        }

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return TodoQueueReader(state).has_dedupe_key(dedupe_key)
