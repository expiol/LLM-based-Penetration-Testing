"""Policy pipeline: composable policy evaluation with verdict tracing.

Separate policy objects are composed via PolicyPipeline, which threads a
shared PolicyContext through each policy in defined order. Each policy
reads/writes to the context and produces PolicyVerdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state import RunState


@dataclass(frozen=True)
class PolicyVerdict:
    """Result of a policy evaluation: accepted or rejected with reasons."""

    accepted: bool
    reasons: list[str] = field(default_factory=list)

    @classmethod
    def accept(cls) -> "PolicyVerdict":
        return cls(accepted=True)

    @classmethod
    def reject(cls, *reasons: str) -> "PolicyVerdict":
        return cls(accepted=False, reasons=list(reasons))


@dataclass
class PolicyContext:
    """Shared mutable context threaded through the policy pipeline.

    Policies read from and write to this context to communicate
    decisions and accumulated state between pipeline stages.
    """

    state: "RunState"
    # Accumulated rejection reasons across all policies
    rejections: dict[str, list[str]] = field(default_factory=dict)
    # Metadata policies can share (e.g., stagnation snapshot)
    memo: dict[str, Any] = field(default_factory=dict)

    def record_rejection(self, item_key: str, reason: str) -> None:
        self.rejections.setdefault(item_key, []).append(reason)

    def verdict_for(self, item_key: str) -> PolicyVerdict:
        reasons = self.rejections.get(item_key, [])
        if reasons:
            return PolicyVerdict.reject(*reasons)
        return PolicyVerdict.accept()


class PolicyStage:
    """Base class for a single policy stage in the pipeline."""

    def evaluate_todo(
        self, todo: "PlannedTodo", context: PolicyContext
    ) -> PolicyVerdict:
        """Evaluate a single todo. Override in subclasses."""
        return PolicyVerdict.accept()

    def evaluate_candidate(
        self, candidate: str, context: PolicyContext
    ) -> PolicyVerdict:
        """Evaluate a flag candidate. Override in subclasses."""
        return PolicyVerdict.accept()


class PolicyPipeline:
    """Runs policy stages in order, threading a shared PolicyContext."""

    def __init__(self, stages: list[PolicyStage] | None = None) -> None:
        self.stages = list(stages or [])

    def add(self, stage: PolicyStage) -> "PolicyPipeline":
        self.stages.append(stage)
        return self

    def evaluate_todos(
        self,
        todos: list["PlannedTodo"],
        state: "RunState",
    ) -> list[tuple["PlannedTodo", PolicyVerdict]]:
        """Run all todos through the pipeline, return (todo, verdict) pairs."""
        context = PolicyContext(state=state)
        results: list[tuple["PlannedTodo", PolicyVerdict]] = []
        for todo in todos:
            key = todo.dedupe_key or todo.goal[:80]
            for stage in self.stages:
                verdict = stage.evaluate_todo(todo, context)
                if not verdict.accepted:
                    context.record_rejection(key, *verdict.reasons)
                    break
            results.append((todo, context.verdict_for(key)))
        return results

    def filter_todos(
        self,
        todos: list["PlannedTodo"],
        state: "RunState",
    ) -> tuple[list["PlannedTodo"], list[str]]:
        """Convenience: return accepted todos and rejection notes."""
        evaluated = self.evaluate_todos(todos, state)
        accepted = [todo for todo, verdict in evaluated if verdict.accepted]
        notes = [
            f"Policy rejected: {'; '.join(verdict.reasons)}"
            for _todo, verdict in evaluated
            if not verdict.accepted
        ]
        return accepted, notes

    def evaluate_candidate(
        self,
        candidate: str,
        state: "RunState",
    ) -> PolicyVerdict:
        """Run a flag candidate through all stages."""
        context = PolicyContext(state=state)
        for stage in self.stages:
            verdict = stage.evaluate_candidate(candidate, context)
            if not verdict.accepted:
                return verdict
        return PolicyVerdict.accept()


__all__ = [
    "PolicyContext",
    "PolicyPipeline",
    "PolicyStage",
    "PolicyVerdict",
]
