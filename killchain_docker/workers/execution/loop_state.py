"""Mutable state accumulated by a worker tool loop."""

from __future__ import annotations

from dataclasses import dataclass, field

from killchain_docker.state.domain import Hypothesis
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle


@dataclass
class ToolLoopState:
    """Tracks prior tool attempts and final-result inputs for one worker run."""

    prior_steps: list[dict[str, object]] = field(default_factory=list)
    last_bundle: ToolExecutionBundle | None = None
    last_capability: ToolCapability | None = None
    last_rationale: str = ""
    accumulated_hypotheses: list[Hypothesis] = field(default_factory=list)
    accumulated_memory: dict[str, str] = field(default_factory=dict)

    def record_step(
        self,
        *,
        bundle: ToolExecutionBundle,
        capability: ToolCapability,
        rationale: str,
        step_record: dict[str, object],
    ) -> None:
        self.last_bundle = bundle
        self.last_capability = capability
        self.last_rationale = rationale
        self.prior_steps.append(step_record)
