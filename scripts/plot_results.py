from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.logging_utils import configure_logging, get_logger, write_stdout
from killchain_docker.batch.result_logs import iter_result_logs


LOGGER = get_logger(__name__)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning(
            "skipping unreadable result log",
            exc_info=True,
            extra={"path": str(path)},
        )
        return None
    return payload if isinstance(payload, dict) else None


def classify_result(payload: dict[str, Any]) -> str:
    if payload.get("success") or payload.get("solved"):
        return "1"
    if payload.get("error") or payload.get("api_error") or payload.get("llm_error"):
        return "error"
    return "0"


def summarize_logdir(logdir: Path) -> str:
    rows: list[str] = []
    counts = {"total": 0, "success": 0, "error": 0, "failed": 0}

    for path in iter_result_logs(logdir):
        payload = read_json(path)
        if payload is None:
            continue
        result = classify_result(payload)
        counts["total"] += 1
        if result == "1":
            counts["success"] += 1
        elif result == "error":
            counts["error"] += 1
        else:
            counts["failed"] += 1
        rows.append(f"{path.stem}\t{result}")

    rows.extend([
        f"total_count: {counts['total']}",
        f"success_count: {counts['success']}",
        f"error_count: {counts['error']}",
        f"failed_count: {counts['failed']}",
    ])
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        "Print compact result rows for a batch log directory"
    )
    parser.add_argument("--logdir", required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    configure_logging(debug=args.debug)

    logdir = Path(args.logdir).expanduser().resolve()
    if not logdir.is_dir():
        LOGGER.error("logdir is not a directory", extra={"logdir": str(logdir)})
        return 1
    write_stdout(summarize_logdir(logdir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
