from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from tabulate import tabulate

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.logging_utils import configure_logging, get_logger, write_stdout


LOGGER = get_logger(__name__)


def get_subdirs(path: Path):
    return filter(lambda item: item.is_dir(), path.iterdir())


def get_conversations(path: Path, model: str | None = None):
    for item in path.iterdir():
        if item.suffix != ".json":
            continue
        if model and model not in item.name:
            continue
        yield item


def filter_challenge(
    args: argparse.Namespace,
    year: str,
    event: str,
    category: str,
    challenge: str,
) -> bool:
    if args.year and year not in args.year:
        return False
    if args.event and event not in args.event:
        return False
    if args.cat and category not in args.cat:
        return False
    if args.chal and challenge not in args.chal:
        return False
    return True


def check_for_mistakes(conversation: dict[str, Any]) -> set[str]:
    mistakes: set[str] = set()
    for message in conversation.get("messages") or []:
        content = _message_content(message)
        if not content:
            continue
        if "{PORT}" in content or "{port}" in content:
            mistakes.add("PortMissing")
        if "{box}" in content or "nc None" in content:
            mistakes.add("ServerMissing")
    return mistakes


def _message_content(message: Any) -> str:
    if not isinstance(message, (list, tuple)) or len(message) < 2:
        return ""
    payload = message[1]
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("content") or payload.get("text") or "")


def failure_reason(conversation: dict[str, Any]) -> str:
    finish_reason = str(conversation.get("finish_reason") or "unknown")
    if finish_reason != "exception":
        return finish_reason

    info = conversation.get("exception_info") or {}
    if not isinstance(info, dict):
        return "exception"
    exception_type = str(info.get("exception_type") or "exception")
    message = str(info.get("exception_message") or "")
    if exception_type == "BadRequestError" and (
        "context_length_exceeded" in message or "string_above_max_length" in message
    ):
        return "context_length"
    if exception_type == "RateLimitError":
        return "rate_limit"
    return exception_type


def iter_challenge_dirs(logdir: Path, args: argparse.Namespace):
    for year in get_subdirs(logdir):
        for event in get_subdirs(year):
            for category in get_subdirs(event):
                for challenge in get_subdirs(category):
                    if filter_challenge(
                        args,
                        year.name,
                        event.name,
                        category.name,
                        challenge.name,
                    ):
                        yield year, event, category, challenge


def read_conversation(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("invalid json", exc_info=True, extra={"path": str(path)})
        return None
    if not isinstance(payload, dict):
        LOGGER.warning(
            "invalid conversation payload",
            extra={"path": str(path), "payload_type": type(payload).__name__},
        )
        return None
    return payload


def summarize_challenge(
    challenge: Path,
    model: str | None,
) -> tuple[list[str], bool] | None:
    conversations = list(get_conversations(challenge, model))
    if not conversations:
        LOGGER.warning(
            "no logs for challenge",
            extra={"challenge": str(challenge), "model": model},
        )
        return None

    solved_count = 0
    mistakes: set[str] = set()
    reasons: set[str] = set()
    for path in conversations:
        conversation = read_conversation(path)
        if conversation is None:
            reasons.add("invalid_json")
            continue

        mistakes |= check_for_mistakes(conversation)
        if conversation.get("solved"):
            solved_count += 1
            continue
        reasons.add(failure_reason(conversation))

    event = challenge.parts[-3]
    label = f"{challenge.name}({challenge.parts[-4]}{'f' if 'Final' in event else 'q'})"
    row = [
        label,
        f"{solved_count}/{len(conversations)}",
        ", ".join(sorted(mistakes)),
        ", ".join(sorted(reasons)),
    ]
    return row, solved_count > 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("Log summary")
    parser.add_argument("-l", "--log-dir", required=True, help="Logs directory")
    parser.add_argument(
        "-y", "--year", default=[], nargs="+", help="Years to select"
    )
    parser.add_argument(
        "-e", "--event", default=[], nargs="+", help="Events to select"
    )
    parser.add_argument(
        "-t", "--cat", default=[], nargs="+", help="Categories to select"
    )
    parser.add_argument(
        "-c", "--chal", default=[], nargs="+", help="Challenges to select"
    )
    parser.add_argument(
        "-m",
        "--model",
        default="gpt-3.5-turbo-1106",
        help="Full name of model to select",
    )
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    logdir = Path(args.log_dir).expanduser().resolve()
    if not logdir.is_dir():
        LOGGER.error("log directory does not exist", extra={"logdir": str(logdir)})
        return 1

    rows: list[list[str]] = []
    success_count = 0
    total_count = 0
    for _year, _event, _category, challenge in iter_challenge_dirs(logdir, args):
        summary = summarize_challenge(challenge, args.model)
        if summary is None:
            continue
        row, solved = summary
        rows.append(row)
        total_count += 1
        success_count += int(solved)

    if total_count == 0:
        LOGGER.error("no challenges")
        return 2

    write_stdout(
        tabulate(
            rows,
            headers=["Challenge", "Solved", "Mistakes", "Reason"],
            tablefmt="tsv",
        )
    )
    write_stdout(
        f"Success: {success_count}/{total_count} "
        f"{success_count / total_count * 100:.2f}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
