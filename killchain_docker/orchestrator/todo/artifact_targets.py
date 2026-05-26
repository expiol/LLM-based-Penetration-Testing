"""Bind planned todos to concrete artifacts and artifact tooling."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from killchain_docker.orchestrator.artifact_capability import (
    artifact_dispatch_profile,
    requested_capability_targets_artifact,
)
from killchain_docker.orchestrator.todo.context_paths import context_path
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoPhase

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


class TodoArtifactTargetNormalizer:
    """Binds todo context to concrete artifacts and artifact tooling."""

    @classmethod
    def normalize(
        cls,
        todo: "PlannedTodo",
        state: "RunState",
        family: str,
        *,
        set_required_capability,
    ) -> str:
        context = todo.context or {}
        goal_l = todo.goal.lower()
        if todo.phase not in {TodoPhase.ANALYSIS, TodoPhase.EXPLOIT}:
            if not cls.looks_like_disk_extraction(goal_l):
                return family
            if todo.phase == TodoPhase.RECON:
                todo.phase = TodoPhase.ANALYSIS
        path = context_path(context)
        artifacts = ArtifactProjectionStore(state)
        if path:
            artifact = artifacts.by_path(path)
            if artifact is not None:
                cls.bind_artifact_target(context, artifact)
                return cls._normalize_bound_artifact_context(
                    todo,
                    context,
                    artifact,
                    family,
                    goal_l,
                    set_required_capability=set_required_capability,
                )
            return family
        mentioned = artifacts.unique_mentioned(goal_l)
        if mentioned is not None:
            cls.bind_artifact_target(context, mentioned)
            return cls._normalize_bound_artifact_context(
                todo,
                context,
                mentioned,
                family,
                goal_l,
                default_when_unhinted=True,
                set_required_capability=set_required_capability,
            )
        if cls.looks_like_disk_extraction(goal_l):
            disk_artifacts = artifacts.disk_images()
            if len(disk_artifacts) == 1:
                cls.bind_artifact_target(context, disk_artifacts[0])
                set_required_capability(
                    context, profile="container_extraction", capability="disk.extract"
                )
            return "forensics-extract"
        return family

    @classmethod
    def _normalize_bound_artifact_context(
        cls,
        todo: "PlannedTodo",
        context: dict[str, Any],
        artifact: Any,
        family: str,
        goal_l: str,
        *,
        set_required_capability,
        default_when_unhinted: bool = False,
    ) -> str:
        if artifact.is_disk_image and cls.looks_like_disk_extraction(goal_l):
            if todo.phase == TodoPhase.RECON:
                todo.phase = TodoPhase.ANALYSIS
            set_required_capability(
                context, profile="container_extraction", capability="disk.extract"
            )
            return "forensics-extract"
        capability = artifact.followup_capability
        requested = requested_capability_targets_artifact(
            DispatchIntent.from_context(context).required_capability, artifact
        )
        should_use_artifact_capability = (
            requested
            or cls.looks_like_disk_extraction(goal_l)
            or default_when_unhinted
            or (
                family in {"other", "source-review", "forensics-extract"}
                and capability != "artifact.triage"
            )
        )
        if should_use_artifact_capability:
            set_required_capability(
                context,
                profile=artifact_dispatch_profile(capability),
                capability=capability,
            )
            if family in {"other", "source-review", "forensics-extract"}:
                return "artifact-followup"
        return family

    @staticmethod
    def bind_artifact_target(context: dict[str, Any], artifact: Any) -> None:
        if artifact.artifact_id:
            context.setdefault("artifact_id", artifact.artifact_id)
        if artifact.path:
            context.setdefault("artifact_path", artifact.path)
            context.setdefault("path", artifact.path)
            context.setdefault("files_root", DEFAULT_FILES_ROOT)

    @staticmethod
    def looks_like_disk_extraction(goal_l: str) -> bool:
        return any(
            (
                token in goal_l
                for token in (
                    "disk image",
                    "filesystem",
                    "file system",
                    "partition",
                    "mbr",
                    "boot sector",
                    "embedded zip",
                    "carve",
                )
            )
        ) and any(
            (
                token in goal_l
                for token in (
                    "extract",
                    "carve",
                    "recover",
                    "analyze",
                    "analyse",
                    "inspect",
                )
            )
        )


__all__ = ["TodoArtifactTargetNormalizer"]
