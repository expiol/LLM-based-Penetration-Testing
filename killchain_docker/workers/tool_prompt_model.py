"""Worker tool prompt result model."""

from __future__ import annotations

from dataclasses import dataclass

from killchain_docker.tools.capabilities import ToolCapability


@dataclass(frozen=True)
class ToolUsePrompt:
    system_prompt: str
    user_prompt: str
    allowed: set[ToolCapability]
    allowed_values: list[str]
    fixed_capability: ToolCapability | None = None
