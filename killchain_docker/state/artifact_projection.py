"""Artifact projections over durable run state."""

from __future__ import annotations
from dataclasses import dataclass
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


@dataclass(frozen=True)
class ArtifactProjection:
    """Derived artifact facts used by planning, dispatch, and prompts."""

    artifact: object
    artifact_id: str
    path: str
    digest: str | None
    source: str
    relative_path: str
    is_disk_image: bool
    followup_priority: int
    followup_capability: str
    generated: bool
    terminal_source: bool
    is_low_signal: bool
    is_png: bool
    evidence_ids: list[str]

    @property
    def key_material(self) -> str:
        return self.digest or self.path


class ArtifactProjectionStore:
    """Builds and queries artifact projections."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def all(self) -> list[ArtifactProjection]:
        from killchain_docker.state.artifact_facts import (
            artifact_followup_capability,
            artifact_followup_priority,
            facts_from_artifact,
        )

        out: list[ArtifactProjection] = []
        for artifact in self.state.artifacts.values():
            facts = facts_from_artifact(artifact)
            path = str(getattr(artifact, "path", "") or "").strip()
            digest = getattr(artifact, "digest", None)
            out.append(
                ArtifactProjection(
                    artifact=artifact,
                    artifact_id=str(getattr(artifact, "artifact_id", "") or ""),
                    path=path,
                    digest=str(digest) if digest else None,
                    source=str(getattr(artifact, "source", "") or ""),
                    relative_path=self._relative_path(artifact),
                    is_disk_image=bool(facts.is_disk_image),
                    followup_priority=artifact_followup_priority(artifact),
                    followup_capability=artifact_followup_capability(artifact),
                    generated=bool(facts.generated),
                    terminal_source=bool(facts.terminal_source),
                    is_low_signal=bool(facts.is_low_signal),
                    is_png=bool(facts.is_png),
                    evidence_ids=self._evidence_ids(artifact),
                )
            )
        return out

    def paths(self) -> list[str]:
        return [artifact.path for artifact in self.all() if artifact.path]

    def by_path(self, path: str) -> ArtifactProjection | None:
        target = str(path or "").strip()
        if not target:
            return None
        for artifact in self.all():
            if artifact.path == target:
                return artifact
        return None

    def by_relative_path(self, relative_path: str) -> ArtifactProjection | None:
        target = relative_path.strip().strip("/")
        if not target:
            return None
        for artifact in self.all():
            if artifact.relative_path == target:
                return artifact
        return None

    def durable_directory_for_relative_prefix(self, relative_prefix: str) -> str | None:
        prefix = relative_prefix.strip().strip("/")
        if not prefix:
            return None
        prefix_with_sep = prefix + "/"
        for artifact in self.all():
            if not artifact.relative_path.startswith(
                prefix_with_sep
            ) or not artifact.path.endswith(artifact.relative_path):
                continue
            return artifact.path[: -len(artifact.relative_path)] + prefix
        return None

    def unique_mentioned(self, goal_l: str) -> ArtifactProjection | None:
        matches: list[ArtifactProjection] = []
        for artifact in self.all():
            if not artifact.path:
                continue
            basename = artifact.path.rsplit("/", 1)[-1].lower()
            if basename and re.search(
                f"(?<![A-Za-z0-9_.-]){re.escape(basename)}(?![A-Za-z0-9_.-])", goal_l
            ):
                matches.append(artifact)
        if len(matches) != 1:
            return None
        return matches[0]

    def disk_images(self) -> list[ArtifactProjection]:
        return [artifact for artifact in self.all() if artifact.is_disk_image]

    def sorted_followups(self) -> list[ArtifactProjection]:
        return sorted(
            self.all(), key=lambda artifact: artifact.followup_priority, reverse=True
        )

    def has_generated_artifact(self) -> bool:
        for artifact in self.all():
            if "/.autopentest_artifacts/" not in artifact.path:
                continue
            if artifact.source.strip().lower() in {
                "artifact_triage",
                "file",
                "strings",
                "exiftool",
            }:
                continue
            return True
        return False

    @staticmethod
    def _evidence_ids(artifact: object) -> list[str]:
        metadata = getattr(artifact, "metadata", {}) or {}
        raw = metadata.get("evidence_ids") or metadata.get("evidence_id")
        values = raw if isinstance(raw, list) else [raw]
        out: list[str] = []
        for value in values:
            text = str(value or "").strip()
            if text and text not in out:
                out.append(text)
        return out

    @staticmethod
    def _relative_path(artifact: object) -> str:
        metadata = getattr(artifact, "metadata", {}) or {}
        rel = str(metadata.get("relative_path") or "").strip().strip("/")
        if rel:
            return rel
        path = str(getattr(artifact, "path", "") or "").strip()
        marker = "/.autopentest_artifacts/"
        if marker not in path:
            return ""
        for token in ("/work/", "/scratch/", "/manual/"):
            if token in path:
                return path.split(token, 1)[1].strip("/")
        return ""
