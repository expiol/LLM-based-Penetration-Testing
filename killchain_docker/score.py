"""Score validation helpers for NYU multi-killchain benchmark runs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence

from killchain_docker.batch.result_logs import iter_result_logs
from killchain_docker.logging_utils import (
    configure_logging,
    get_logger,
    write_json_file,
    write_json_stdout,
)
from nyuctf.dataset import CTFDataset


LOGGER = get_logger(__name__)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_result_log(path: Path) -> dict[str, Any] | None:
    try:
        payload = load_json(path)
    except (OSError, json.JSONDecodeError):
        LOGGER.warning(
            "skipping unreadable score log",
            exc_info=True,
            extra={"path": str(path)},
        )
        return None
    if not isinstance(payload, dict):
        LOGGER.warning(
            "skipping non-object score log",
            extra={"path": str(path), "payload_type": type(payload).__name__},
        )
        return None
    return payload


def challenge_names(split: str, dataset_path: str | None = None) -> list[str]:
    if dataset_path:
        dataset = CTFDataset(dataset_json=dataset_path)
    else:
        dataset = CTFDataset(split=split)
    return list(dataset.dataset.keys())


def summarize_logdir(logdir: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for path in iter_result_logs(logdir):
        payload = read_result_log(path)
        if payload is None:
            continue
        challenge = (
            payload.get("challenge_metadata", {}).get("canonical_name")
            or path.stem
        )
        results[challenge] = {
            "solved": bool(payload.get("solved")),
            "validated_flag": payload.get("state", {}).get("validated_flag")
            or payload.get("summary", {}).get("validated_flag"),
            "status": payload.get("status"),
            "finish_reason": payload.get("finish_reason"),
            "logfile": str(path),
        }
    return results


def summarize_run_dir(run_dir: Path) -> dict[str, dict[str, Any]]:
    jsonl_path = run_dir / "results.jsonl"
    if not jsonl_path.exists():
        raise FileNotFoundError(f"results.jsonl not found in {run_dir}")

    results: dict[str, dict[str, Any]] = {}
    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        row = read_result_jsonl_row(line, path=jsonl_path, line_number=line_number)
        if row is None:
            continue
        challenge = str(row.get("challenge") or "")
        if not challenge:
            LOGGER.warning(
                "skipping score result row without challenge",
                extra={"path": str(jsonl_path), "line_number": line_number},
            )
            continue
        results[challenge] = {
            "solved": bool(row.get("solved")),
            "validated_flag": row.get("validated_flag"),
            "status": row.get("status"),
            "returncode": row.get("returncode"),
            "logfile": row.get("logfile"),
            "summary_file": row.get("summary_file"),
        }
    return results


def read_result_jsonl_row(
    line: str,
    *,
    path: Path,
    line_number: int,
) -> dict[str, Any] | None:
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        LOGGER.warning(
            "skipping malformed score result row",
            exc_info=True,
            extra={"path": str(path), "line_number": line_number},
        )
        return None
    if not isinstance(row, dict):
        LOGGER.warning(
            "skipping non-object score result row",
            extra={
                "path": str(path),
                "line_number": line_number,
                "payload_type": type(row).__name__,
            },
        )
        return None
    return row


def diagnose_logdir(logdir: Path) -> dict[str, Any]:
    """Classify per-challenge run logs into broad failure-mode buckets."""

    rows: list[dict[str, Any]] = []
    bucket_members: dict[str, list[str]] = defaultdict(list)
    for path in iter_result_logs(logdir):
        payload = read_result_log(path)
        if payload is None:
            continue
        state = payload.get("state") or {}
        metrics = payload.get("state_metrics") or {}
        challenge = payload.get("challenge_metadata") or {}
        canonical = challenge.get("canonical_name") or path.stem
        category = challenge.get("category") or ""
        solved = bool(payload.get("solved") or state.get("solved"))
        worker_counts = metrics.get("worker_counts") or {}
        status_counts = metrics.get("todo_status_counts") or {}
        token_usage = (
            payload.get("token_usage")
            or payload.get("summary", {}).get("token_usage")
            or {}
        )
        total_tokens = int(
            token_usage.get("total_tokens") or token_usage.get("total") or 0
        )
        execution_log = state.get("execution_log") or []
        memory_text = json.dumps(
            {
                "events": execution_log[-30:],
                "rounds": (state.get("rounds") or [])[-10:],
            },
            ensure_ascii=False,
        )[:500000]

        buckets: list[str] = []
        if solved:
            buckets.append("solved")
        else:
            web_work = int(worker_counts.get("web-worker", 0)) + int(
                worker_counts.get("exploit-worker", 0)
            )
            script_tool_runs = int(
                (metrics.get("evidence_tool_counts") or {}).get("script_exec", 0)
            )
            validations = int(worker_counts.get("flag-worker", 0))
            if payload.get("error"):
                buckets.append("environment_or_startup_error")
            if script_tool_runs >= 15:
                buckets.append("script_tool_spin")
            if validations > 0:
                buckets.append("candidate_validation_loop")
            if category == "web" and (web_work >= 40 or total_tokens >= 650000):
                buckets.append("web_probe_fanout")
            if re.search(r"\btimeout\b|timed out|time limit", memory_text, re.I):
                buckets.append("timeout_loop")
            if int(metrics.get("open_todo_count") or status_counts.get("pending") or 0):
                buckets.append("stopped_with_open_todos")
            if re.search(
                r"0 sources inspected|0 script\(s\) executed|none (appeared )?relevant",
                memory_text,
                re.I,
            ):
                buckets.append("worker_contract_false_negative")
            if "truncated" in memory_text.lower() and any(
                marker in memory_text.lower()
                for marker in ("disassembly", "objdump", "decompil")
            ):
                buckets.append("binary_evidence_truncation")

        if not buckets:
            buckets.append("uncategorized_failure")
        for bucket in buckets:
            bucket_members[bucket].append(canonical)
        rows.append(
            {
                "challenge": canonical,
                "category": category,
                "solved": solved,
                "status": payload.get("status"),
                "finish_reason": payload.get("finish_reason"),
                "total_tokens": total_tokens,
                "worker_counts": worker_counts,
                "open_todo_count": metrics.get("open_todo_count", 0),
                "buckets": buckets,
            }
        )

    bucket_counts = Counter(bucket for row in rows for bucket in row["buckets"])
    return {
        "logdir": str(logdir),
        "total": len(rows),
        "solved": sum(1 for row in rows if row["solved"]),
        "failed": sum(1 for row in rows if not row["solved"]),
        "bucket_counts": dict(bucket_counts.most_common()),
        "bucket_members": {
            key: sorted(value)
            for key, value in sorted(bucket_members.items())
        },
        "details": rows,
    }


def build_validation_payload(
    *,
    results: dict[str, dict[str, Any]],
    expected_challenges: list[str] | None,
    split: str,
) -> dict[str, Any]:
    bool_results = {
        challenge: bool(info.get("solved"))
        for challenge, info in sorted(results.items())
    }
    solved = sum(1 for solved_flag in bool_results.values() if solved_flag)
    total = len(bool_results)

    missing: list[str] = []
    unexpected: list[str] = []
    if expected_challenges is not None:
        expected_set = set(expected_challenges)
        observed_set = set(bool_results)
        missing = sorted(expected_set - observed_set)
        unexpected = sorted(observed_set - expected_set)

    return {
        "metadata": {
            "agent": "NYU Multi-Killchain",
            "split": split,
            "evaluated": total,
        },
        "score": {
            "solved": solved,
            "total": total,
            "solve_rate": round(solved / total, 4) if total else 0.0,
            "missing_count": len(missing),
            "unexpected_count": len(unexpected),
        },
        "coverage": {
            "missing": missing,
            "unexpected": unexpected,
        },
        "results": bool_results,
        "details": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate benchmark score for NYU multi-killchain logs"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--run-dir",
        help="Batch run directory containing results.jsonl",
    )
    source.add_argument("--logdir", help="Directory of per-challenge JSON logs")
    parser.add_argument(
        "--split",
        default="development",
        choices=["development", "test"],
    )
    parser.add_argument("--dataset", help="Optional dataset JSON path")
    parser.add_argument("--output", help="Optional output JSON path")
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="When --logdir is used, also write broad failure-mode diagnostics.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only emit warnings and errors",
    )
    args = parser.parse_args(argv)
    configure_logging(debug=args.debug, quiet=args.quiet)

    if args.run_dir:
        run_dir = Path(args.run_dir).expanduser().resolve()
        results = summarize_run_dir(run_dir)
        default_output = run_dir / "score_validation.json"
    else:
        logdir = Path(args.logdir).expanduser().resolve()
        results = summarize_logdir(logdir)
        default_output = logdir / "score_validation.json"

    expected = challenge_names(args.split, args.dataset)
    payload = build_validation_payload(
        results=results,
        expected_challenges=expected,
        split=args.split,
    )

    output_path = (
        Path(args.output).expanduser().resolve() if args.output else default_output
    )
    write_json_file(output_path, payload)
    write_json_stdout(payload["score"])
    LOGGER.info("score validation written", extra={"output_path": str(output_path)})
    if args.diagnose:
        if not args.logdir:
            raise ValueError("--diagnose requires --logdir")
        diagnostics = diagnose_logdir(Path(args.logdir).expanduser().resolve())
        diagnostics_path = output_path.with_name("log_diagnostics.json")
        write_json_file(diagnostics_path, diagnostics)
        LOGGER.info(
            "log diagnostics written",
            extra={"diagnostics_path": str(diagnostics_path)},
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
