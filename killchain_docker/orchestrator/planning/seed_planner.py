"""Deterministic bootstrap and follow-up todo seed planning."""

from __future__ import annotations
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.planning.artifact_followup_seeds import (
    ArtifactFollowupSeedPlanner,
)
from killchain_docker.orchestrator.planning.disk_extract_seeds import (
    DiskExtractSeedPlanner,
)
from killchain_docker.orchestrator.planning.near_miss_seeds import NearMissSeedPlanner
from killchain_docker.orchestrator.planning.recovery_seeds import RecoverySeedPlanner
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.orchestrator.planning.suspicious_media_seeds import (
    SuspiciousMediaSeedPlanner,
)
from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class PlanningSeedPlanner:
    """Builds deterministic bootstrap and evidence follow-up todos."""

    def __init__(
        self,
        artifact_followup_seed_planner: ArtifactFollowupSeedPlanner | None = None,
        suspicious_media_seed_planner: SuspiciousMediaSeedPlanner | None = None,
        disk_extract_seed_planner: DiskExtractSeedPlanner | None = None,
        near_miss_seed_planner: NearMissSeedPlanner | None = None,
        recovery_seed_planner: RecoverySeedPlanner | None = None,
    ) -> None:
        self.artifact_followup_seed_planner = (
            artifact_followup_seed_planner or ArtifactFollowupSeedPlanner()
        )
        self.suspicious_media_seed_planner = (
            suspicious_media_seed_planner or SuspiciousMediaSeedPlanner()
        )
        self.disk_extract_seed_planner = (
            disk_extract_seed_planner or DiskExtractSeedPlanner()
        )
        self.near_miss_seed_planner = near_miss_seed_planner or NearMissSeedPlanner()
        self.recovery_seed_planner = recovery_seed_planner or RecoverySeedPlanner()

    def seed_todos(
        self, state: RunState, *, include_execution_closure_seed: bool = True
    ) -> tuple[list[PlannedTodo], list[str]]:
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        challenge_files = ChallengeProjection(state).files()
        authorized_scope = list(state.authorized_scope)
        if challenge_files and (
            not self._has_todo_key(state, "bootstrap:artifact-inventory")
        ):
            todos.append(
                PlannedTodo(
                    goal="Inventory and classify bundled challenge files.",
                    phase=TodoPhase.RECON,
                    priority=95,
                    context={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "challenge_files": challenge_files,
                        "family": "artifact-inventory",
                        "dispatch_intent": {
                            "profile": "artifact_analysis",
                            "required_capability": "artifact.triage",
                        },
                    },
                    success_criteria=[
                        "Classify files by kind.",
                        "Surface source, binary, archive, database, pcap, repo, and flag-like evidence.",
                    ],
                    constraints=["Use only files under /home/ctfplayer/ctf_files."],
                    dedupe_key="bootstrap:artifact-inventory",
                )
            )
        if include_execution_closure_seed:
            closure_seed = self.recovery_seed_planner.execution_closure_seed(
                state, challenge_files
            )
            if closure_seed is not None:
                todos.append(closure_seed)
        for candidate in CandidatePolicy.validation_ready_candidates(state)[:1]:
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
                        "dispatch_intent": {"profile": "flag_validation"},
                    },
                    success_criteria=[
                        "Confirm whether the candidate is the challenge flag."
                    ],
                    constraints=[
                        "Validate only grounded candidates already present in state."
                    ],
                    dedupe_key=dedupe_key,
                )
            )
        for seed_planner in (
            self.artifact_followup_seed_planner,
            self.suspicious_media_seed_planner,
            self.disk_extract_seed_planner,
        ):
            artifact_todos, artifact_notes = seed_planner.seed_todos(state)
            todos.extend(artifact_todos)
            notes.extend(artifact_notes)
        recovery_todos, recovery_notes = (
            self.recovery_seed_planner.candidate_recovery_seeds(state, challenge_files)
        )
        todos.extend(recovery_todos)
        notes.extend(recovery_notes)
        for index, scope in enumerate(authorized_scope, start=1):
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
                        "asset_id": "seed-asset"
                        if len(authorized_scope) == 1
                        else f"seed-asset-{index}",
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
        near_miss_todos, near_miss_notes = self.near_miss_seed_planner.seed_todos(
            state, challenge_files
        )
        todos.extend(near_miss_todos)
        notes.extend(near_miss_notes)
        if not todos and TodoQueue(state).empty():
            notes.append(
                "No authorized scope or challenge files are available for bootstrap."
            )
        return (todos, notes)

    def include_execution_closure_seed(
        self, state: RunState, llm_todos: list[PlannedTodo]
    ) -> bool:
        return self.recovery_seed_planner.include_execution_closure_seed(
            state, llm_todos
        )

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return TodoQueue(state).has_dedupe_key(dedupe_key)
