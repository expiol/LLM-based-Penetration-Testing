"""Rewrite planner todo references from files_root paths to durable artifacts."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.constants import DEFAULT_FILES_ROOT

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


class DurableArtifactReferenceNormalizer:
    """Rewrites files-root references to durable artifact paths."""

    @classmethod
    def normalize(
        cls, todo: "PlannedTodo", state: "RunState", context: dict[str, Any]
    ) -> None:
        if not ArtifactProjectionStore(state).all():
            return
        files_root = str(context.get("files_root") or DEFAULT_FILES_ROOT).rstrip("/")
        if not files_root:
            return
        original_values = [
            todo.goal,
            *todo.success_criteria,
            *todo.constraints,
            str(context),
        ]
        base_prefixes = cls._referenced_artifact_directory_prefixes(
            "\n".join(original_values), state, files_root
        )

        def rewrite(value: Any) -> Any:
            if isinstance(value, str):
                return cls._rewrite_files_root_artifact_paths(value, state, files_root)
            if isinstance(value, list):
                return [rewrite(item) for item in value]
            if isinstance(value, tuple):
                return tuple((rewrite(item) for item in value))
            if isinstance(value, dict):
                return {key: rewrite(item) for key, item in value.items()}
            return value

        todo.goal = rewrite(todo.goal)
        todo.success_criteria = list(rewrite(list(todo.success_criteria)))
        todo.constraints = list(rewrite(list(todo.constraints)))
        for key, value in list(context.items()):
            context[key] = rewrite(value)
        durable_paths = cls._durable_paths_from_relative_context(
            context, state, base_prefixes
        )
        if not durable_paths:
            return
        context["durable_artifact_paths"] = durable_paths
        existing_paths = context.get("paths")
        if not isinstance(existing_paths, list) or not existing_paths:
            context["paths"] = durable_paths

    @classmethod
    def _rewrite_files_root_artifact_paths(
        cls, text: str, state: "RunState", files_root: str
    ) -> str:
        pattern = re.compile(re.escape(files_root) + "/[^\\s'\\\"`<>|&;]+")

        def replace(match: re.Match[str]) -> str:
            raw = match.group(0)
            suffix = raw[len(raw.rstrip(".,:)]}")) :]
            path = raw[: len(raw) - len(suffix)]
            replacement = cls._durable_artifact_path_for_files_root_path(
                path, state, files_root
            )
            return f"{replacement}{suffix}" if replacement else raw

        return pattern.sub(replace, text)

    @classmethod
    def _referenced_artifact_directory_prefixes(
        cls, text: str, state: "RunState", files_root: str
    ) -> list[str]:
        pattern = re.compile(re.escape(files_root) + "/[^\\s'\\\"`<>|&;]+")
        prefixes: list[str] = []
        seen: set[str] = set()
        for match in pattern.finditer(text):
            path = match.group(0).rstrip(".,:)]}")
            rel = cls._files_root_relative(path, files_root)
            if not rel or rel.startswith(".autopentest_artifacts/"):
                continue
            projection = ArtifactProjectionStore(state)
            if projection.by_relative_path(rel) is not None:
                continue
            if not projection.durable_directory_for_relative_prefix(rel):
                continue
            if rel not in seen:
                seen.add(rel)
                prefixes.append(rel)
        return prefixes

    @classmethod
    def _durable_paths_from_relative_context(
        cls,
        context: dict[str, Any],
        state: "RunState",
        base_prefixes: list[str],
        *,
        limit: int = 20,
    ) -> list[str]:
        paths: list[str] = []
        seen: set[str] = set()
        for value in cls._iter_context_strings(context):
            rel = cls._relative_path_like(value)
            if not rel:
                continue
            candidates = [rel]
            candidates.extend(
                (f"{prefix.rstrip('/')}/{rel.lstrip('./')}" for prefix in base_prefixes)
            )
            for candidate in candidates:
                artifact = ArtifactProjectionStore(state).by_relative_path(candidate)
                if artifact is None:
                    continue
                path = artifact.path
                if not path or path in seen:
                    continue
                seen.add(path)
                paths.append(path)
                if len(paths) >= limit:
                    return paths
        return paths

    @staticmethod
    def _iter_context_strings(value: Any) -> list[str]:
        out: list[str] = []
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                out.extend(
                    DurableArtifactReferenceNormalizer._iter_context_strings(item)
                )
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                out.extend(
                    DurableArtifactReferenceNormalizer._iter_context_strings(item)
                )
        return out

    @staticmethod
    def _relative_path_like(value: str) -> str | None:
        text = value.strip().strip("'\"")
        if (
            not text
            or text.startswith("/")
            or "://" in text
            or any((char.isspace() for char in text))
            or ("/" not in text)
            or (len(text) > 240)
        ):
            return None
        return text.lstrip("./")

    @classmethod
    def _durable_artifact_path_for_files_root_path(
        cls, path: str, state: "RunState", files_root: str
    ) -> str | None:
        rel = cls._files_root_relative(path, files_root)
        if not rel or rel.startswith(".autopentest_artifacts/"):
            return None
        projection = ArtifactProjectionStore(state)
        artifact = projection.by_relative_path(rel)
        if artifact is not None:
            return artifact.path or None
        return projection.durable_directory_for_relative_prefix(rel)

    @staticmethod
    def _files_root_relative(path: str, files_root: str) -> str | None:
        root = files_root.rstrip("/")
        if not root or not path.startswith(root + "/"):
            return None
        return path[len(root) + 1 :].strip("/")


__all__ = ["DurableArtifactReferenceNormalizer"]
