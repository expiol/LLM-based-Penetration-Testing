"""Trust policy for run-memory writes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from killchain_docker.value_coercion import coerce_string_mapping

if TYPE_CHECKING:
    from killchain_docker.state.todos import TodoItem, WorkerResult


class MemoryWritePolicy:
    """Trust rules for accepting model-proposed memory updates."""

    _BLOCKED_RESULT_QUALITIES = {
        "partial_no_candidate",
        "script_failed",
        "timeout",
        "unbounded_loop_guard",
        "syntax_error",
        "parse_error",
        "binary_structure_error",
        "undefined_name",
        "type_error",
        "no_candidate",
    }

    @classmethod
    def trusted_worker_updates(
        cls,
        todo: "TodoItem",
        result: "WorkerResult",
        updates: Any,
        *,
        require_candidate: bool = False,
    ) -> dict[str, str]:
        """Return updates that are safe to persist after a worker result."""
        normalized = coerce_string_mapping(updates)
        if not normalized or not result.success or result.partial:
            return {}
        if (
            str(result.result_quality or "").strip().lower()
            in cls._BLOCKED_RESULT_QUALITIES
        ):
            return {}
        has_candidates = bool(result.state_delta and result.state_delta.flag_candidates)
        if require_candidate and (not has_candidates):
            return {}
        del todo
        return normalized
