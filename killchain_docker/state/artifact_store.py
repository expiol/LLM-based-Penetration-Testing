"""Artifact fact store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.fact_merges import merge_artifact
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import Artifact
    from killchain_docker.state.run_state import RunState


class ArtifactFactStore:
    """Mutable store for durable artifacts."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def artifact(self, artifact: "Artifact", *, touch: bool = True) -> None:
        key = artifact.digest or artifact.path
        existing_id = next(
            (
                current_id
                for current_id, current in self.state.artifacts.items()
                if artifact.digest
                and current.digest == artifact.digest
                or current.path == artifact.path
            ),
            None,
        )
        if existing_id is not None:
            merge_artifact(self.state.artifacts[existing_id], artifact)
        else:
            artifact.artifact_id = artifact.artifact_id or key
            self.state.artifacts[artifact.artifact_id] = artifact
        if touch:
            self.maintenance.touch()
