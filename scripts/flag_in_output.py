from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from _bootstrap import add_project_root


add_project_root()

from nyuctf.dataset import CTFDataset
from nyuctf.challenge import CTFChallenge

from killchain_docker.logging_utils import configure_logging, get_logger, write_stdout
from killchain_docker.batch.result_logs import iter_result_logs


LOGGER = get_logger(__name__)


def message_content(message: Any) -> str:
    if not isinstance(message, dict):
        return ""
    return str(message.get("content") or "")


def message_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def log_contains_flag(raw_text: str, payload: dict[str, Any], flag: str) -> bool:
    if not flag:
        return False
    if flag in raw_text:
        return True

    for message in message_items(payload.get("planner")):
        if flag in message_content(message):
            return True

    for executor in payload.get("executors") or []:
        for message in message_items(executor):
            if flag in message_content(message):
                return True

    return False


def read_log(path: Path) -> tuple[str, dict[str, Any]] | None:
    try:
        raw_text = path.read_text(encoding="utf-8")
        payload = json.loads(raw_text)
    except (OSError, json.JSONDecodeError):
        LOGGER.warning(
            "skipping unreadable log",
            exc_info=True,
            extra={"path": str(path)},
        )
        return None
    if not isinstance(payload, dict):
        LOGGER.warning(
            "skipping non-object log",
            extra={"path": str(path), "payload_type": type(payload).__name__},
        )
        return None
    return raw_text, payload


def challenge_for_log(dataset: CTFDataset, name: str) -> CTFChallenge | None:
    try:
        return CTFChallenge(dataset.get(name), dataset.basedir)
    except Exception:
        LOGGER.warning(
            "skipping log without dataset challenge",
            exc_info=True,
            extra={"challenge": name},
        )
        return None


def iter_flag_hits(logdir: Path, dataset: CTFDataset) -> list[str]:
    hits: list[str] = []
    for log in iter_result_logs(logdir):
        loaded = read_log(log)
        if loaded is None:
            continue
        raw_text, payload = loaded
        if payload.get("success") or payload.get("solved"):
            continue
        challenge = challenge_for_log(dataset, log.stem)
        if challenge is None:
            continue
        flag = str(getattr(challenge, "flag", "") or "")
        if not flag:
            LOGGER.warning(
                "skipping challenge without flag",
                extra={"challenge": log.stem},
            )
            continue
        if log_contains_flag(raw_text, payload, flag):
            hits.append(log.stem)
    return hits


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("Check if flag was found in any of the messages")
    parser.add_argument("--logdir", required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    if args.dataset is not None:
        dataset = CTFDataset(dataset_json=args.dataset)
    else:
        dataset = CTFDataset(split=args.split)

    for name in iter_flag_hits(Path(args.logdir).expanduser().resolve(), dataset):
        write_stdout(f"Flag found in messages: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
