"""Execution-plane registry and default tool wiring."""

from __future__ import annotations

import sys

from nyuctf_mutil_killchain.tools.core import AllowlistedCommandPlugin, ExecutionPlane
from nyuctf_mutil_killchain.tools.parsers import json_payload_parser, jsonl_signal_parser
from nyuctf_mutil_killchain.tools.plugins import ALL_COMMAND_TOOLS


def build_execution_plane(
    *,
    argv_prefix: list[str] | None = None,
    python_executable: str | None = None,
) -> ExecutionPlane:
    """Create the default execution plane and register all local command tools."""

    plane = ExecutionPlane()
    plane.register_parser("jsonl_signals", jsonl_signal_parser)
    plane.register_parser("json_payload", json_payload_parser)

    command_prefix = list(argv_prefix or [])
    executable = python_executable or sys.executable or "python3"
    for tool_module in ALL_COMMAND_TOOLS:
        plane.register_plugin(
            AllowlistedCommandPlugin(
                name=tool_module.TOOL_NAME,
                executable=executable,
                build_arguments=tool_module.build_arguments,
                argv_prefix=command_prefix,
            )
        )
    return plane


build_safe_execution_plane = build_execution_plane
