"""Backward-compatible execution-plane exports.

The implementation is split across:
- ``core.py`` for shared execution types and plugins
- ``parsers.py`` for output parsing
- ``registry.py`` for default tool registration
"""

from killchain_docker.tools.core import (
    AllowlistedCommandPlugin,
    ExecutionMode,
    ExecutionPlane,
    LoopbackRestPlugin,
    ParsedToolOutput,
    ToolExecutionBundle,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from killchain_docker.tools.parsers import json_payload_parser, jsonl_signal_parser
from killchain_docker.tools.registry import build_execution_plane, build_safe_execution_plane

__all__ = [
    "AllowlistedCommandPlugin",
    "ExecutionMode",
    "ExecutionPlane",
    "LoopbackRestPlugin",
    "ParsedToolOutput",
    "ToolExecutionBundle",
    "ToolExecutionError",
    "ToolExecutionRequest",
    "ToolExecutionResult",
    "build_execution_plane",
    "build_safe_execution_plane",
    "json_payload_parser",
    "jsonl_signal_parser",
]
