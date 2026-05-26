"""Command-line entrypoints."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from killchain_docker.lab import DEFAULT_COMPOSE_REL, lab_down, lab_health_check, lab_up
from killchain_docker.logging_utils import (
    configure_logging,
    get_logger,
    write_json_stdout,
)
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.runtime.config import RunConfig
from killchain_docker.runtime.session import run_assessment
from killchain_docker.selftest import run_selftest


LOGGER = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autopentest", description="Safe multi-agent security assessment runner"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    run_parser = subcommands.add_parser("run", help="Run an assessment")
    run_parser.add_argument("--objective", help="Run objective")
    run_parser.add_argument(
        "--scope", action="append", dest="scope", help="Authorized scope entry"
    )
    run_parser.add_argument("--config", help="Path to a JSON config file")
    run_parser.add_argument(
        "--output-root", help="Directory where run artifacts are stored"
    )
    run_parser.add_argument("--status-path", help="Optional live status JSON path")
    run_parser.add_argument(
        "--max-cycles", type=int, help="Maximum orchestrator cycles"
    )
    run_parser.add_argument(
        "--rag-mode", choices=["enabled", "strict", "disabled"], help="RAG policy mode"
    )
    run_parser.add_argument(
        "--quiet", action="store_true", help="Suppress orchestrator event streaming"
    )

    demo_parser = subcommands.add_parser("demo", help="Run a built-in local demo")
    demo_parser.add_argument(
        "--output-root", default="runs", help="Directory where run artifacts are stored"
    )
    demo_parser.add_argument("--status-path", help="Optional live status JSON path")
    demo_parser.add_argument(
        "--rag-mode", choices=["enabled", "strict", "disabled"], help="RAG policy mode"
    )
    demo_parser.add_argument(
        "--quiet", action="store_true", help="Suppress orchestrator event streaming"
    )

    selftest_parser = subcommands.add_parser(
        "selftest", help="Run a local no-docker self-test"
    )
    selftest_parser.add_argument(
        "--output-root",
        default="selftest_output",
        help="Directory where self-test artifacts are written",
    )

    lab_parser = subcommands.add_parser(
        "lab", help="Docker Compose lab helpers (optional)"
    )
    lab_sub = lab_parser.add_subparsers(dest="lab_cmd", required=True)

    lab_up_p = lab_sub.add_parser("up", help="docker compose up (default: detached)")
    lab_up_p.add_argument(
        "--compose",
        default=str(DEFAULT_COMPOSE_REL),
        help=f"Compose file path (default: {DEFAULT_COMPOSE_REL})",
    )
    lab_up_p.add_argument(
        "--foreground",
        action="store_true",
        help="Run attached (no -d)",
    )

    lab_down_p = lab_sub.add_parser("down", help="docker compose down")
    lab_down_p.add_argument(
        "--compose",
        default=str(DEFAULT_COMPOSE_REL),
        help=f"Compose file path (default: {DEFAULT_COMPOSE_REL})",
    )
    lab_down_p.add_argument(
        "--volumes",
        action="store_true",
        help="Add docker compose down -v",
    )

    lab_health_p = lab_sub.add_parser("health", help="HTTP GET probe (readiness check)")
    lab_health_p.add_argument(
        "--url", required=True, help="Target URL, e.g. http://127.0.0.1:8080"
    )
    lab_health_p.add_argument("--timeout", type=float, default=15.0, help="Seconds")

    return parser


def _config_from_args(args: argparse.Namespace) -> RunConfig:
    if args.command == "demo":
        config_path = Path.cwd() / "configs" / "sample_run.json"
        if config_path.exists():
            base = RunConfig.from_json_file(config_path)
            return RunConfig(
                objective=base.objective,
                authorized_scope=base.authorized_scope,
                output_root=args.output_root,
                max_cycles=base.max_cycles,
                quiet=args.quiet,
                status_path=args.status_path or base.status_path,
                rag_mode=args.rag_mode or base.rag_mode,
                metadata=dict(base.metadata),
            )
        return RunConfig(
            objective="Map and review authorized web surface",
            authorized_scope=["http://127.0.0.1:8080"],
            output_root=args.output_root,
            max_cycles=4,
            quiet=args.quiet,
            status_path=args.status_path,
            rag_mode=args.rag_mode,
        )

    base = RunConfig.from_json_file(args.config) if args.config else None
    objective = args.objective or (base.objective if base is not None else None)
    scope = args.scope or (base.authorized_scope if base is not None else None)
    if not objective:
        raise ValueError("--objective is required when not provided via --config")
    if not scope:
        raise ValueError(
            "At least one --scope entry is required when not provided via --config"
        )

    return RunConfig(
        objective=objective,
        authorized_scope=scope,
        output_root=args.output_root
        if args.output_root is not None
        else (base.output_root if base is not None else "runs"),
        max_cycles=args.max_cycles
        if args.max_cycles is not None
        else (base.max_cycles if base is not None else 6),
        quiet=args.quiet or (base.quiet if base is not None else False),
        status_path=args.status_path
        if args.status_path is not None
        else (base.status_path if base is not None else None),
        rag_mode=args.rag_mode
        if args.rag_mode is not None
        else (base.rag_mode if base is not None else None),
        metadata=dict(base.metadata) if base is not None else {},
    )


def _lab_cli_main(args: argparse.Namespace) -> int:
    if args.lab_cmd == "up":
        code = lab_up(args.compose, detach=not args.foreground)
        write_json_stdout(
            {"compose": args.compose, "exit_code": code, "detach": not args.foreground}
        )
        return 0 if code == 0 else 1
    if args.lab_cmd == "down":
        code = lab_down(args.compose, remove_volumes=args.volumes)
        write_json_stdout(
            {"compose": args.compose, "exit_code": code, "remove_volumes": args.volumes}
        )
        return 0 if code == 0 else 1
    if args.lab_cmd == "health":
        ok = lab_health_check(args.url, timeout_s=args.timeout)
        write_json_stdout({"url": args.url, "ok": ok, "timeout_s": args.timeout})
        return 0 if ok else 1
    raise ValueError(f"unknown lab subcommand: {args.lab_cmd!r}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(quiet=bool(getattr(args, "quiet", False)))

    try:
        if args.command == "lab":
            return _lab_cli_main(args)
        if args.command == "selftest":
            payload = run_selftest(args.output_root)
            write_json_stdout(payload)
            return 0

        config = _config_from_args(args)
        artifacts = run_assessment(config)
    except (ValueError, LLMClientError) as exc:
        LOGGER.error(
            "run rejected",
            exc_info=True,
            extra={"command": args.command, "error_type": type(exc).__name__},
        )
        return 2
    except KeyboardInterrupt:
        LOGGER.warning("run interrupted by user", extra={"command": args.command})
        return 130
    except Exception:
        LOGGER.exception("run failed", extra={"command": args.command})
        return 1

    summary = {
        "run_id": artifacts.run_id,
        "status": artifacts.status,
        "run_dir": artifacts.run_dir,
        "summary_path": artifacts.summary_path,
        "report_path": artifacts.report_path,
    }
    write_json_stdout(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
