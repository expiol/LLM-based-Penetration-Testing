"""Authorized-scope projection over durable run state."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class ScopeProjection:
    """Read-only authorized scope view."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def entries(self) -> list[str]:
        return list(self.state.authorized_scope)
