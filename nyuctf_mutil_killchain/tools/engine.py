"""Backward-compatible execution-plane exports.

The implementation is split across:
- ``core.py`` for shared execution types and plugins
- ``parsers.py`` for output parsing
- ``registry.py`` for default tool registration
"""

from nyuctf_mutil_killchain.tools.core import (
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
from nyuctf_mutil_killchain.tools.parsers import json_payload_parser, jsonl_signal_parser
from nyuctf_mutil_killchain.tools.registry import build_execution_plane, build_safe_execution_plane

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
