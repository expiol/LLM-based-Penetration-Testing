"""Todo context normalization for planner output."""

from __future__ import annotations

from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state import RunState

_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"


class TaskNormalizer:
    """Normalize high-level todo context against challenge metadata and assets."""

    def fill(self, todo: PlannedTodo, state: RunState) -> None:
        context = todo.context
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge_meta.get("files", []) or [])
        goal_l = todo.goal.lower()

        if challenge_files and (
            "file" in goal_l
            or "artifact" in goal_l
            or "source" in goal_l
            or "binary" in goal_l
            or "flag" in goal_l
        ):
            context.setdefault("files_root", _DEFAULT_FILES_ROOT)
            context.setdefault("challenge_files", challenge_files)

        if state.authorized_scope and "scope" not in context and "recon" in goal_l:
            context["scope"] = state.authorized_scope[0]

        if any(token in goal_l for token in ("web", "http", "route", "form", "exploit", "vulnerability")):
            state.infer_asset_identity(context)

