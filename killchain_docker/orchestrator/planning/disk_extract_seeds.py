"""Planning seeds for deterministic disk image extraction."""

from __future__ import annotations

from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.planning.artifact_seed_common import (
    FILES_ROOT,
    has_todo_key,
)
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class DiskExtractSeedPlanner:
    """Build deterministic extraction todos for discovered disk images."""

    def seed_todos(self, state: RunState) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return ([], [])
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        for artifact in ArtifactProjectionStore(state).disk_images():
            key_material = artifact.key_material
            dedupe_key = f"bootstrap:disk-extract:{key_material}"
            if has_todo_key(state, dedupe_key):
                continue
            path = artifact.path
            todos.append(
                PlannedTodo(
                    goal="Extract files from the detected disk image.",
                    phase=TodoPhase.ANALYSIS,
                    priority=94,
                    context={
                        "family": "forensics-extract",
                        "dispatch_intent": {
                            "profile": "container_extraction",
                            "required_capability": "disk.extract",
                        },
                        "artifact_id": artifact.artifact_id,
                        "artifact_path": path,
                        "path": path,
                        "files_root": FILES_ROOT,
                        "novelty_key": f"disk-extract:{key_material}",
                    },
                    success_criteria=[
                        "Create durable artifacts for recovered filesystem or container files."
                    ],
                    constraints=["Keep extraction bounded and preserve provenance."],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded disk extraction todo for {artifact.artifact_id}.")
        return (todos, notes)
