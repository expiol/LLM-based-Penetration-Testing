"""Todo context normalization for planner output."""

from __future__ import annotations

from typing import Any

from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state import RunState, TodoPhase, normalize_todo_phase, todo_phase_rank

_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"

_RECON_SIGNALS = (
    "scope", "inventory", "discover", "discovery", "enumerate", "enumeration",
    "map", "mapping", "service", "http metadata", "metadata",
)
_ANALYSIS_SIGNALS = (
    "source", "binary", "route review", "review", "analyze", "analysis",
    "inspect", "hypothesis", "vulnerability identification", "vuln identification",
    "vulnerability", "weakness", "decompile", "reverse",
)
_EXPLOIT_SIGNALS = (
    "exploit", "exploitation", "poc", "proof of concept", "payload", "shell",
    "remote code execution", "leverage", "execute vulnerability", "confirmed vulnerability",
    "use credential", "credential use", "try credential", "use session",
    "session use",
)
_FLAG_VALIDATION_SIGNALS = (
    "validate", "validation", "verify", "check", "submit", "confirm",
    "candidate flag", "flag candidate", "recover flag", "flag recovery",
)


class TodoNormalizer:
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

        todo.phase = self.normalize_phase(todo.goal, context, todo.phase)

    @classmethod
    def normalize_phase(
        cls,
        goal: str,
        context: dict[str, Any],
        explicit_phase: TodoPhase | str | None,
    ) -> TodoPhase:
        """Keep explicit phases unless the todo text clearly implies a later stage."""
        current = normalize_todo_phase(explicit_phase)
        inferred = cls.infer_phase(goal, context)
        if todo_phase_rank(inferred) > todo_phase_rank(current):
            return inferred
        return current

    @staticmethod
    def infer_phase(goal: str, context: dict[str, Any] | None = None) -> TodoPhase:
        context = context or {}
        text = _phase_text(goal, context)
        if context.get("candidate_flag") or context.get("flag_candidate_id"):
            return TodoPhase.FLAG_VALIDATION
        if any(signal in text for signal in _EXPLOIT_SIGNALS):
            return TodoPhase.EXPLOIT
        if "flag" in text and any(signal in text for signal in _FLAG_VALIDATION_SIGNALS):
            return TodoPhase.FLAG_VALIDATION
        if context.get("credential_id") or context.get("session_id"):
            return TodoPhase.EXPLOIT
        if any(signal in text for signal in _ANALYSIS_SIGNALS):
            return TodoPhase.ANALYSIS
        if any(signal in text for signal in _RECON_SIGNALS):
            return TodoPhase.RECON
        return TodoPhase.RECON


def _phase_text(goal: str, context: dict[str, Any]) -> str:
    values: list[str] = [goal]
    for key, value in context.items():
        values.append(str(key))
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value[:8])
    return " ".join(values).lower().replace("_", " ")
