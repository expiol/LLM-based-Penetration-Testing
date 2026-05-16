"""Explicit protocols for the tool plugin system.

Each plugin must define `build_tool_output()` and return the shared ToolOutput
schema. The execution plane does not infer typed findings from plugin-specific
output_context fields.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from killchain_docker.tools.core import (
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
)


# ---------------------------------------------------------------------------
# Plugin protocol
# ---------------------------------------------------------------------------

# Type alias for the legacy command builder signature
CommandBuilder = Callable[["ToolExecutionRequest"], list[str]]

# Signature for a plugin-owned output builder.
ToolOutputBuilder = Callable[
    ["ToolExecutionRequest", "ToolExecutionResult", "ParsedToolOutput"],
    ToolOutput,
]


@runtime_checkable
class ToolPluginModule(Protocol):
    """Protocol that every tool plugin module must satisfy.

    At minimum, a plugin module defines TOOL_NAME, build_arguments, and
    build_tool_output.
    """

    TOOL_NAME: str

    def build_arguments(self, request: "ToolExecutionRequest") -> list[str]: ...

    def build_tool_output(
        self,
        request: "ToolExecutionRequest",
        result: "ToolExecutionResult",
        parsed: "ParsedToolOutput",
    ) -> ToolOutput: ...


def get_tool_output_builder(module: Any) -> ToolOutputBuilder | None:
    """Return the module's build_tool_output if defined."""
    fn = getattr(module, "build_tool_output", None)
    return fn if callable(fn) else None


__all__ = [
    "CommandBuilder",
    "ToolOutput",
    "ToolOutputBuilder",
    "ToolOutputStatus",
    "ToolPluginModule",
    "get_tool_output_builder",
]
