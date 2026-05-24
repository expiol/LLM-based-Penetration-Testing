"""Render a legacy transcript JSON file as plain Markdown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.logging_utils import configure_logging, get_logger, write_stdout


LOGGER = get_logger(__name__)


def _render_mapping(title: str, payload: dict[str, Any]) -> list[str]:
    lines = [f"**{title}**", ""]
    for key, value in payload.items():
        lines.extend([f"- {key}:", "", "```", str(value), "```", ""])
    return lines


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _render_message(message: dict[str, Any]) -> list[str]:
    role = str(message.get("role", "unknown")).removeprefix("MessageRole.")
    lines = [f"### {role.title()}", "", str(message.get("content") or ""), ""]

    tool_call = message.get("tool_call")
    if isinstance(tool_call, dict):
        lines.extend(
            _render_mapping(
                tool_call.get("name", "tool_call"),
                _mapping(tool_call.get("parsed_args")),
            )
        )

    tool_result = message.get("tool_result")
    if isinstance(tool_result, dict):
        result = tool_result.get("result")
        if isinstance(result, dict):
            lines.extend(
                _render_mapping(tool_result.get("name", "tool_result"), result)
            )
        else:
            lines.extend([
                f"**{tool_result.get('name', 'tool_result')}**",
                "",
                "```",
                str(result),
                "```",
                "",
            ])
    return lines


def _message_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def render_transcript(transcript: dict[str, Any]) -> str:
    lines: list[str] = []
    for section in ("autoprompter", "planner"):
        messages = _message_items(transcript.get(section))
        if not messages:
            continue
        lines.extend([f"## {section.title()}", ""])
        exec_count = 0
        for message in messages:
            lines.extend(_render_message(message))
            tool_call = message.get("tool_call") if isinstance(message, dict) else None
            if not isinstance(tool_call, dict) or tool_call.get("name") != "delegate":
                continue
            executors = transcript.get("executors") or []
            if not isinstance(executors, list):
                executors = []
            if exec_count >= len(executors):
                continue
            executor = executors[exec_count]
            lines.extend([f"## Executor {exec_count + 1}", ""])
            for executor_message in _message_items(executor):
                lines.extend(_render_message(executor_message))
            exec_count += 1
    return "\n".join(lines).rstrip() + "\n"


def read_transcript(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.error("transcript unreadable", exc_info=True, extra={"path": str(path)})
        return None
    if not isinstance(payload, dict):
        LOGGER.error(
            "transcript payload is not an object",
            extra={"path": str(path), "payload_type": type(payload).__name__},
        )
        return None
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("Render a legacy multi-agent transcript.")
    parser.add_argument(
        "-t", "--transcript", required=True, help="Transcript JSON file"
    )
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    payload = read_transcript(Path(args.transcript).expanduser().resolve())
    if payload is None:
        return 1
    write_stdout(render_transcript(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
