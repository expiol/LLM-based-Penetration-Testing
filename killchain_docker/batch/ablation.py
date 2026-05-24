"""Reproducible multi-mode RAG experiment runner."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from killchain_docker.batch.monitor import utc_timestamp, write_json
from killchain_docker.logging_utils import configure_logging, get_logger, write_json_stdout
from killchain_docker.processes import run_bounded_process


LOGGER = get_logger(__name__)
DEFAULT_MODES = ("oracle", "strict")
QUALITY_GATE_FAILURE_EXIT_CODE = 4
QUALITY_GATE_RATE_MODES = {"all", "oracle", "strict", "disabled"}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STREAM_TAIL_CHARS = 12_000


def success_rate_requirement(value: str) -> tuple[str, float]:
    """Parse MODE=RATE or RATE success-rate gate values."""

    raw = value.strip()
    if not raw:
        raise argparse.ArgumentTypeError("success-rate requirement cannot be empty")
    if "=" in raw:
        mode, raw_rate = raw.split("=", 1)
        mode = mode.strip()
    else:
        mode, raw_rate = "all", raw
    if mode not in QUALITY_GATE_RATE_MODES:
        choices = ", ".join(sorted(QUALITY_GATE_RATE_MODES))
        raise argparse.ArgumentTypeError(f"unknown success-rate mode {mode!r}; expected one of: {choices}")
    try:
        rate = float(raw_rate)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid success-rate value {raw_rate!r}") from exc
    if rate < 0.0 or rate > 1.0:
        raise argparse.ArgumentTypeError("success-rate value must be between 0 and 1")
    return mode, rate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the same benchmark slice with multiple RAG modes and compare summaries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--challenge", default="__all__", help="Challenge name, __all__, or __random__")
    parser.add_argument("--challenges", nargs="+", help="Run a named subset of challenges in order")
    parser.add_argument("--run-all", action="store_true", help="Run all challenges in the selected split/category")
    parser.add_argument("--category")
    parser.add_argument("--dataset")
    parser.add_argument("--split", default="development", choices=["test", "development"])
    parser.add_argument("--modes", nargs="+", default=list(DEFAULT_MODES), choices=["oracle", "strict", "disabled"])
    parser.add_argument("--max-cycles", type=int, default=8)
    parser.add_argument(
        "--auto-max-cycles",
        action="store_true",
        help="Forward --auto-max-cycles to run.py so challenge shape may scale the cycle budget.",
    )
    parser.add_argument("--parallel-workers", type=int, default=1)
    parser.add_argument("--replicas", type=int, default=1)
    parser.add_argument("--sample-size", type=int)
    parser.add_argument("--sample-seed", type=int)
    parser.add_argument(
        "--sample-strategy",
        choices=["random", "category_round_robin"],
        default="random",
    )
    parser.add_argument("--container-image", default="ctfenv:latest")
    parser.add_argument("--container-network", default="ctfnet")
    parser.add_argument("--logdir", default=str(PROJECT_ROOT / "logs" / "rag_ablation"))
    parser.add_argument("--output-root")
    parser.add_argument("--name", default=f"rag_ablation_{int(time.time())}")
    parser.add_argument("--skip-exist", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Write the manifest without executing commands")
    parser.add_argument("--audit", action="store_true", help="Write an audit JSON after the ablation finishes")
    parser.add_argument("--audit-output", help="Optional path for the audit JSON payload")
    parser.add_argument("--audit-allow-unfinished", action="store_true")
    parser.add_argument("--audit-allow-empty", action="store_true")
    parser.add_argument("--audit-allow-missing-rag", action="store_true")
    parser.add_argument(
        "--min-success-rate",
        action="append",
        default=[],
        type=success_rate_requirement,
        metavar="MODE=RATE",
        help="Fail after the run if a mode success_rate is below RATE; use RATE or all=RATE for every completed mode.",
    )
    parser.add_argument(
        "--require-rag-ok",
        action="store_true",
        help="Fail after the run if any required RAG mode reports missing, unavailable, or mismatched RAG context.",
    )
    return parser


def mode_logdir(args: argparse.Namespace, mode: str) -> Path:
    return Path(args.logdir).expanduser().resolve() / f"{args.name}_{mode}"


def mode_output_root(args: argparse.Namespace, mode: str) -> str | None:
    if not args.output_root:
        return None
    return str(Path(args.output_root).expanduser().resolve() / mode)


def build_mode_command(args: argparse.Namespace, mode: str) -> list[str]:
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "run.py"),
        "--split",
        args.split,
        "--max-cycles",
        str(args.max_cycles),
        "--parallel-workers",
        str(args.parallel_workers),
        "--replicas",
        str(args.replicas),
        "--container-image",
        args.container_image,
        "--container-network",
        args.container_network,
        "--logdir",
        str(Path(args.logdir).expanduser().resolve()),
        "--name",
        f"{args.name}_{mode}",
        "--rag-mode",
        mode,
    ]
    if getattr(args, "challenges", None):
        cmd.append("--challenges")
        cmd.extend(str(name) for name in args.challenges)
    elif args.run_all or args.challenge == "__all__":
        cmd.append("--run-all")
    else:
        cmd.extend(["--challenge", args.challenge])
    if args.category:
        cmd.extend(["--category", args.category])
    if args.dataset:
        cmd.extend(["--dataset", args.dataset])
    output_root = mode_output_root(args, mode)
    if output_root:
        cmd.extend(["--output-root", output_root])
    if args.skip_exist:
        cmd.append("--skip-exist")
    if args.quiet:
        cmd.append("--quiet")
    cmd.append("--debug" if args.debug else "--no-debug")
    if getattr(args, "auto_max_cycles", False):
        cmd.append("--auto-max-cycles")
    if getattr(args, "sample_size", None) is not None:
        cmd.extend(["--sample-size", str(args.sample_size)])
    if getattr(args, "sample_seed", None) is not None:
        cmd.extend(["--sample-seed", str(args.sample_seed)])
    if getattr(args, "sample_strategy", None):
        cmd.extend(["--sample-strategy", str(args.sample_strategy)])
    return cmd


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        if not path.exists():
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("failed to read JSON payload", exc_info=True, extra={"path": str(path)})
        return {}
    return payload if isinstance(payload, dict) else {}


def load_mode_summary(args: argparse.Namespace, mode: str) -> dict[str, Any]:
    logdir = mode_logdir(args, mode)
    summary = read_json_object(logdir / "_batch_summary.json")
    monitor = read_json_object(logdir / "_batch_monitor.json")
    return {
        "logdir": str(logdir),
        "summary_path": str(logdir / "_batch_summary.json") if summary else None,
        "monitor_path": str(logdir / "_batch_monitor.html") if (logdir / "_batch_monitor.html").exists() else None,
        "monitor_json_path": str(logdir / "_batch_monitor.json") if monitor else None,
        "summary": summary,
        "monitor": monitor,
    }


def summarize_mode(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    monitor = payload.get("monitor") if isinstance(payload.get("monitor"), dict) else {}
    counts = monitor.get("counts") if isinstance(monitor.get("counts"), dict) else {}
    total_attempted = _count(summary.get("total_attempted"), _count(counts.get("completed")))
    skipped = _count(summary.get("skipped_count"), _count(counts.get("skipped")))
    evaluated = _int_or_none(summary.get("evaluated_count"))
    rag_health = _rag_health(
        summary,
        requested_mode=str(payload.get("mode") or "").strip(),
        attempted_default=total_attempted,
    )
    return {
        "attempted": evaluated if evaluated is not None else max(0, total_attempted - skipped),
        "total_attempted": total_attempted,
        "solved": _count(summary.get("solved_count"), _count(counts.get("solved"))),
        "failed": _count(summary.get("failed_count"), _count(counts.get("failed"))),
        "skipped": skipped,
        "success_rate": summary.get("success_rate"),
        "elapsed_sec": summary.get("elapsed_sec", monitor.get("elapsed_sec")),
        "token_usage": summary.get("token_usage", {}),
        "failure_buckets": summary.get("failure_buckets", {}),
        "rag": rag_health,
    }


def write_report(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)
    LOGGER.info("RAG ablation report written", extra={"report_path": str(path)})


def write_audit_report(report_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    from killchain_docker.batch.audit import audit_ablation_manifest, audit_dry_run_manifest

    raw_output = getattr(args, "audit_output", None)
    output_path = Path(raw_output).expanduser().resolve() if raw_output else report_path.with_name("_rag_ablation_audit.json")
    if getattr(args, "dry_run", False):
        payload = audit_dry_run_manifest(
            report_path,
            expected_modes=tuple(args.modes),
            require_finished=not getattr(args, "audit_allow_unfinished", False),
        )
    else:
        payload = audit_ablation_manifest(
            report_path,
            expected_modes=tuple(args.modes),
            require_finished=not getattr(args, "audit_allow_unfinished", False),
            require_attempts=not getattr(args, "audit_allow_empty", False),
            require_rag=not getattr(args, "audit_allow_missing_rag", False),
        )
    write_json(output_path, payload)
    LOGGER.info(
        "RAG ablation audit written",
        extra={"audit_path": str(output_path), "audit_ok": bool(payload.get("ok"))},
    )
    return {
        "path": str(output_path),
        "ok": bool(payload.get("ok")),
        "issue_count": int(payload.get("issue_count") or 0),
    }


def run_mode_command(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    argv = list(cmd)
    result = run_bounded_process(argv, timeout_s=None)
    return subprocess.CompletedProcess(
        argv,
        result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def stream_tail(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    if len(text) <= STREAM_TAIL_CHARS:
        return text
    return text[-STREAM_TAIL_CHARS:]


def _should_stop(returncode: int) -> bool:
    return returncode == 130 or returncode not in (0, 1)


def _exception_payload(exc: BaseException) -> dict[str, Any]:
    message = str(exc).strip() or type(exc).__name__
    return {
        "type": type(exc).__name__,
        "message": message,
    }


def _interrupted_returncode(exc: BaseException) -> int:
    if isinstance(exc, KeyboardInterrupt):
        return 130
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else 130


def run_ablation(
    args: argparse.Namespace,
    *,
    run_command: Callable[[Sequence[str]], subprocess.CompletedProcess[Any]] | None = None,
) -> dict[str, Any]:
    run_command = run_command or run_mode_command
    report_dir = Path(args.logdir).expanduser().resolve() / args.name
    report_path = report_dir / "_rag_ablation.json"
    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at": utc_timestamp(),
        "updated_at": utc_timestamp(),
        "finished": False,
        "stop_reason": None,
        "modes": {},
        "comparison": {},
    }
    write_report(report_path, report)

    for mode in args.modes:
        cmd = build_mode_command(args, mode)
        started = time.time()
        LOGGER.info("starting RAG ablation mode", extra={"rag_mode": mode, "command": cmd})
        returncode = 0
        completed: subprocess.CompletedProcess[Any] | None = None
        error_payload: dict[str, Any] | None = None
        if not args.dry_run:
            try:
                completed = run_command(cmd)
                returncode = int(completed.returncode)
            except (KeyboardInterrupt, SystemExit) as exc:
                returncode = _interrupted_returncode(exc)
                error_payload = _exception_payload(exc)
                LOGGER.warning(
                    "RAG ablation mode interrupted",
                    exc_info=True,
                    extra={"rag_mode": mode, "returncode": returncode},
                )
            except Exception as exc:
                returncode = 2
                error_payload = _exception_payload(exc)
                LOGGER.exception(
                    "RAG ablation mode crashed",
                    extra={"rag_mode": mode, "returncode": returncode},
                )
        mode_payload = load_mode_summary(args, mode)
        mode_payload["mode"] = mode
        mode_payload.update({
            "command": cmd,
            "returncode": returncode,
            "runtime_sec": round(time.time() - started, 3),
            "dry_run": bool(args.dry_run),
            "metrics": summarize_mode(mode_payload),
            "stdout_tail": stream_tail(getattr(completed, "stdout", None)),
            "stderr_tail": stream_tail(getattr(completed, "stderr", None)),
            "error": error_payload,
        })
        report["modes"][mode] = mode_payload
        report["updated_at"] = utc_timestamp()
        write_report(report_path, report)
        if _should_stop(returncode):
            LOGGER.error("RAG ablation mode failed", extra={"rag_mode": mode, "returncode": returncode})
            report["stop_reason"] = "interrupted" if returncode == 130 else "mode_failed"
            break

    report["finished"] = len(report["modes"]) == len(args.modes)
    report["updated_at"] = utc_timestamp()
    report["comparison"] = build_comparison(report["modes"])
    write_report(report_path, report)
    if getattr(args, "audit", False):
        report["audit"] = write_audit_report(report_path, args)
        report["updated_at"] = utc_timestamp()
        write_report(report_path, report)
    if quality_gate_configured(args):
        report["quality_gate"] = evaluate_quality_gate(report, args)
        report["updated_at"] = utc_timestamp()
        write_report(report_path, report)
    return report


def quality_gate_configured(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "min_success_rate", None) or getattr(args, "require_rag_ok", False))


def evaluate_quality_gate(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    thresholds = _success_rate_thresholds(getattr(args, "min_success_rate", None) or [])
    require_rag_ok = bool(getattr(args, "require_rag_ok", False))
    modes = report.get("modes") if isinstance(report.get("modes"), dict) else {}
    issues: list[dict[str, Any]] = []

    if not modes:
        issues.append(_quality_issue("quality_no_modes", "quality gate has no completed mode payloads to check"))

    all_threshold = thresholds.get("all")
    for mode, payload in modes.items():
        if not isinstance(payload, dict):
            continue
        threshold = thresholds.get(mode, all_threshold)
        if threshold is not None:
            issues.extend(_check_success_rate(mode, payload, threshold))
        if require_rag_ok:
            issues.extend(_check_rag_health(mode, payload))

    for mode, threshold in thresholds.items():
        if mode != "all" and mode not in modes:
            issues.append(
                _quality_issue(
                    "quality_mode_missing",
                    "required mode is missing from the ablation report",
                    mode=mode,
                    minimum_success_rate=threshold,
                )
            )

    return {
        "schema_version": 1,
        "ok": not issues,
        "issue_count": len(issues),
        "issues": issues,
        "requirements": {
            "min_success_rate": thresholds,
            "require_rag_ok": require_rag_ok,
        },
    }


def _success_rate_thresholds(requirements: Sequence[tuple[str, float]]) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    for mode, rate in requirements:
        thresholds[mode] = rate
    return thresholds


def _check_success_rate(mode: str, payload: dict[str, Any], threshold: float) -> list[dict[str, Any]]:
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    success_rate = metrics.get("success_rate")
    if not isinstance(success_rate, (int, float)):
        return [
            _quality_issue(
                "success_rate_missing",
                "mode metrics do not contain a numeric success_rate",
                mode=mode,
                minimum_success_rate=threshold,
            )
        ]
    if float(success_rate) + 1e-9 >= threshold:
        return []
    return [
        _quality_issue(
            "success_rate_below_threshold",
            "mode success_rate is below the configured minimum",
            mode=mode,
            success_rate=round(float(success_rate), 4),
            minimum_success_rate=threshold,
        )
    ]


def _check_rag_health(mode: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    rag = metrics.get("rag") if isinstance(metrics.get("rag"), dict) else {}
    if not rag.get("required") or rag.get("ok"):
        return []
    return [
        _quality_issue(
            "rag_health_failed",
            "required RAG context was missing, unavailable, or mismatched",
            mode=mode,
            rag={
                "mode": rag.get("mode"),
                "attempted": rag.get("attempted"),
                "enabled": rag.get("enabled"),
                "missing": rag.get("missing"),
                "unavailable": rag.get("unavailable"),
                "mode_mismatch": rag.get("mode_mismatch"),
            },
        )
    ]


def _quality_issue(code: str, message: str, **context: Any) -> dict[str, Any]:
    payload = {"code": code, "message": message}
    payload.update({key: value for key, value in context.items() if value is not None})
    return payload


def build_comparison(modes: dict[str, Any]) -> dict[str, Any]:
    metrics = {
        mode: payload.get("metrics", {})
        for mode, payload in modes.items()
        if isinstance(payload, dict)
    }
    oracle = metrics.get("oracle", {})
    if not oracle:
        return {"available": False, "metrics": metrics}
    comparable = {
        mode: payload
        for mode, payload in metrics.items()
        if mode != "oracle" and _has_attempts(payload)
    }
    if not _has_attempts(oracle) or not comparable:
        return {
            "available": False,
            "reason": "insufficient_results",
            "metrics": metrics,
        }
    rag_issues = _comparison_rag_issues({"oracle": oracle, **comparable})
    if rag_issues:
        return {
            "available": False,
            "reason": "rag_unavailable",
            "issues": rag_issues,
            "metrics": metrics,
        }
    deltas = {
        mode: _comparison_delta(payload, oracle)
        for mode, payload in comparable.items()
    }
    comparison = {
        "available": True,
        "metrics": metrics,
        "deltas_from_oracle": deltas,
    }
    if "strict" in deltas:
        comparison["strict_minus_oracle"] = deltas["strict"]
    if "disabled" in deltas:
        comparison["disabled_minus_oracle"] = deltas["disabled"]
    return comparison


def _has_attempts(payload: dict[str, Any]) -> bool:
    attempted = payload.get("attempted")
    return isinstance(attempted, (int, float)) and attempted > 0


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _count(value: Any, default: int = 0) -> int:
    resolved = _int_or_none(value)
    if resolved is None:
        return max(0, default)
    return max(0, resolved)


def _rag_health(
    summary: dict[str, Any],
    *,
    requested_mode: str = "",
    attempted_default: int | None = None,
) -> dict[str, Any]:
    configured_mode = (summary.get("experiment_config") or {}).get("rag_mode")
    requested_mode = str(configured_mode or requested_mode or "").strip()
    details = summary.get("details") if isinstance(summary.get("details"), list) else []
    default = len(details) if attempted_default is None else attempted_default
    attempted = _count(summary.get("total_attempted"), default)
    if requested_mode == "disabled":
        return {"mode": requested_mode, "required": False, "ok": True}
    if requested_mode not in {"oracle", "strict"}:
        return {"mode": requested_mode or None, "required": False, "ok": True}

    payloads = [
        entry.get("rag")
        for entry in details
        if isinstance(entry, dict) and isinstance(entry.get("rag"), dict)
    ]
    enabled = [
        rag for rag in payloads
        if rag.get("enabled")
    ]
    unavailable_statuses = {"unavailable", "disabled", "error", "miss", "empty_query", "metadata_only"}
    unavailable = [
        rag for rag in payloads
        if (
            not rag.get("enabled")
            or rag.get("status") in unavailable_statuses
            or _count(rag.get("hint_count")) <= 0
        )
    ]
    mismatched = [
        rag for rag in enabled
        if not _rag_payload_matches_mode(rag, requested_mode)
    ]
    missing = max(0, attempted - len(payloads))
    return {
        "mode": requested_mode,
        "required": True,
        "ok": (
            attempted > 0
            and missing == 0
            and len(unavailable) == 0
            and len(mismatched) == 0
            and len(enabled) == attempted
        ),
        "attempted": attempted,
        "payloads": len(payloads),
        "enabled": len(enabled),
        "missing": missing,
        "unavailable": len(unavailable),
        "mode_mismatch": len(mismatched),
    }


def _rag_payload_matches_mode(rag: dict[str, Any], requested_mode: str) -> bool:
    raw_mode = rag.get("mode")
    if raw_mode:
        return raw_mode == requested_mode
    expected_policy = {
        "oracle": "supplemental_context",
        "strict": "filtered_context",
    }.get(requested_mode)
    if not expected_policy:
        return True
    policy = rag.get("policy")
    return policy == expected_policy


def _comparison_rag_issues(metrics: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for mode, payload in metrics.items():
        rag = payload.get("rag") if isinstance(payload.get("rag"), dict) else {}
        if rag.get("required") and not rag.get("ok"):
            issues.append({
                "mode": mode,
                "missing": rag.get("missing", 0),
                "unavailable": rag.get("unavailable", 0),
                "enabled": rag.get("enabled", 0),
                "attempted": rag.get("attempted", 0),
                "mode_mismatch": rag.get("mode_mismatch", 0),
            })
    return issues


def _rate_delta(left: Any, right: Any) -> float | None:
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return None
    return round(float(left) - float(right), 4)


def _comparison_delta(left: dict[str, Any], oracle: dict[str, Any]) -> dict[str, Any]:
    return {
        "solved": _count(left.get("solved")) - _count(oracle.get("solved")),
        "success_rate": _rate_delta(left.get("success_rate"), oracle.get("success_rate")),
        "total_tokens": _token_delta(left, oracle, "total_tokens"),
    }


def _token_delta(left: dict[str, Any], right: dict[str, Any], key: str) -> int | None:
    left_total = (left.get("token_usage") or {}).get("total") or {}
    right_total = (right.get("token_usage") or {}).get("total") or {}
    if key not in left_total or key not in right_total:
        return None
    left_value = _int_or_none(left_total[key])
    right_value = _int_or_none(right_total[key])
    if left_value is None or right_value is None:
        return None
    return left_value - right_value


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(debug=args.debug, quiet=args.quiet)
    report = run_ablation(args)
    write_json_stdout({
        "finished": report["finished"],
        "comparison": report["comparison"],
        "audit": report.get("audit"),
        "quality_gate": report.get("quality_gate"),
        "report_path": str(Path(args.logdir).expanduser().resolve() / args.name / "_rag_ablation.json"),
    })
    returncodes = [
        int(payload.get("returncode") or 0)
        for payload in report["modes"].values()
        if isinstance(payload, dict)
    ]
    if any(code == 130 for code in returncodes):
        return 130
    if any(code not in (0, 1) for code in returncodes):
        return 2
    audit = report.get("audit")
    if isinstance(audit, dict) and not audit.get("ok"):
        return 3
    quality_gate = report.get("quality_gate")
    if isinstance(quality_gate, dict) and not quality_gate.get("ok"):
        return QUALITY_GATE_FAILURE_EXIT_CODE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
