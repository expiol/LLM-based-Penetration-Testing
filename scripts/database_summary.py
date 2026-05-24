from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.logging_utils import (
    configure_logging,
    get_logger,
    write_json_file,
)


LOGGER = get_logger(__name__)


@dataclass(frozen=True)
class ChallengeMetadata:
    year: str
    event: str
    category: str
    name: str
    description: str


def iter_challenge_files(root: Path):
    yield from sorted(root.rglob("challenge.json"))


def _metadata_payload(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def parse_challenge(path: Path, root: Path) -> ChallengeMetadata | None:
    try:
        relative = path.relative_to(root)
        year, event, category, name = relative.parts[:4]
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError, IndexError) as exc:
        LOGGER.warning(
            "challenge metadata skipped",
            exc_info=True,
            extra={"path": str(path), "error": type(exc).__name__},
        )
        return None
    payload = _metadata_payload(raw_payload)
    if payload is None:
        LOGGER.warning(
            "challenge metadata skipped",
            extra={"path": str(path), "error": "invalid_payload"},
        )
        return None
    return ChallengeMetadata(
        year=year,
        event=event,
        category=category,
        name=name,
        description=str(payload.get("description") or ""),
    )


def build_summary(root: Path) -> list[dict[str, str]]:
    items = [
        metadata
        for path in iter_challenge_files(root)
        if (metadata := parse_challenge(path, root)) is not None
    ]
    return [asdict(item) for item in items]


def write_summary(path: Path, payload: list[dict[str, str]]) -> None:
    write_json_file(path, payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("Summarize challenge metadata into JSON")
    parser.add_argument("--dataset-root", default="./LLM_CTF_Database")
    parser.add_argument("--output", default="./chal_data.json")
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    root = Path(args.dataset_root).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    if not root.is_dir():
        LOGGER.error(
            "dataset root is not a directory",
            extra={"dataset_root": str(root)},
        )
        return 1

    summary = build_summary(root)
    write_summary(output, summary)
    LOGGER.info(
        "challenge metadata summary written",
        extra={"output_path": str(output), "count": len(summary)},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
