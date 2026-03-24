"""Command-line entrypoints."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Sequence

from nyuctf_mutil_killchain.controller import RunConfig, run_assessment
from nyuctf_mutil_killchain.lab import DEFAULT_COMPOSE_REL, lab_down, lab_health_check, lab_up
from nyuctf_mutil_killchain.llm import LLMClientError
from nyuctf_mutil_killchain.selftest import run_selftest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autopentest", description="Safe multi-agent security assessment runner")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run_parser = subcommands.add_parser("run", help="Run an assessment")
    run_parser.add_argument("--objective", help="Run objective")
    run_parser.add_argument("--scope", action="append", dest="scope", help="Authorized scope entry")
    run_parser.add_argument("--config", help="Path to a JSON config file")
    run_parser.add_argument("--output-root", help="Directory where run artifacts are stored")
    run_parser.add_argument("--max-cycles", type=int, help="Maximum orchestrator cycles")
    run_parser.add_argument("--no-llm", action="store_true", help="Disable LLM client usage")
    run_parser.add_argument(
        "--heuristic-planner",
        action="store_true",
        help="Force the heuristic planner even if an LLM client is configured",
    )
    run_parser.add_argument("--quiet", action="store_true", help="Suppress orchestrator event streaming")

    demo_parser = subcommands.add_parser("demo", help="Run a built-in local demo")
    demo_parser.add_argument("--output-root", default="runs", help="Directory where run artifacts are stored")
    demo_parser.add_argument("--quiet", action="store_true", help="Suppress orchestrator event streaming")

    selftest_parser = subcommands.add_parser("selftest", help="Run a local no-docker self-test")
    selftest_parser.add_argument(
        "--output-root",
        default="selftest_mutil_killchain",
        help="Directory where self-test artifacts are written",
    )

    lab_parser = subcommands.add_parser("lab", help="Docker Compose lab helpers (optional)")
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
    lab_health_p.add_argument("--url", required=True, help="Target URL, e.g. http://127.0.0.1:8080")
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
                enable_llm=base.enable_llm,
                enable_llm_planner=base.enable_llm_planner,
                quiet=args.quiet,
            )
        return RunConfig(
            objective="Map and review authorized web surface",
            authorized_scope=["http://127.0.0.1:8080"],
            output_root=args.output_root,
            max_cycles=4,
            enable_llm=False,
            enable_llm_planner=False,
            quiet=args.quiet,
        )

    base = RunConfig.from_json_file(args.config) if args.config else None
    objective = args.objective or (base.objective if base is not None else None)
    scope = args.scope or (base.authorized_scope if base is not None else None)
    if not objective:
        raise ValueError("--objective is required when not provided via --config")
    if not scope:
        raise ValueError("At least one --scope entry is required when not provided via --config")

    return RunConfig(
        objective=objective,
        authorized_scope=scope,
        output_root=args.output_root if args.output_root is not None else (base.output_root if base is not None else "runs"),
        max_cycles=args.max_cycles if args.max_cycles is not None else (base.max_cycles if base is not None else 6),
        enable_llm=False if args.no_llm else (base.enable_llm if base is not None else True),
        enable_llm_planner=False
        if args.heuristic_planner
        else (base.enable_llm_planner if base is not None else True),
        quiet=args.quiet or (base.quiet if base is not None else False),
    )


def _lab_cli_main(args: argparse.Namespace) -> int:
    if args.lab_cmd == "up":
        code = lab_up(args.compose, detach=not args.foreground)
        print(json.dumps({"compose": args.compose, "exit_code": code, "detach": not args.foreground}, indent=2))
        return 0 if code == 0 else 1
    if args.lab_cmd == "down":
        code = lab_down(args.compose, remove_volumes=args.volumes)
        print(json.dumps({"compose": args.compose, "exit_code": code, "remove_volumes": args.volumes}, indent=2))
        return 0 if code == 0 else 1
    if args.lab_cmd == "health":
        ok = lab_health_check(args.url, timeout_s=args.timeout)
        print(json.dumps({"url": args.url, "ok": ok, "timeout_s": args.timeout}, indent=2))
        return 0 if ok else 1
    raise ValueError(f"unknown lab subcommand: {args.lab_cmd!r}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "lab":
            return _lab_cli_main(args)
        if args.command == "selftest":
            payload = run_selftest(args.output_root)
            print(json.dumps(payload, indent=2, ensure_ascii=True))
            return 0

        config = _config_from_args(args)
        artifacts = run_assessment(config)
    except (ValueError, LLMClientError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nrun interrupted by user", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    summary = {
        "run_id": artifacts.run_id,
        "status": artifacts.status,
        "run_dir": artifacts.run_dir,
        "summary_path": artifacts.summary_path,
        "report_path": artifacts.report_path,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
