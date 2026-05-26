"""Configured entrypoint for NYUCTF batch runs.

Run with no arguments to use ``RUN_CONFIG`` below, or pass CLI flags to
override it for benchmark automation.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from types import SimpleNamespace
from typing import Sequence

from killchain_docker.batch.runner import (
    run_all_challenges,
    run_single_challenge_replicas,
)
from killchain_docker.logging_utils import configure_logging, get_logger


LOGGER = get_logger(__name__)

SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_LOGDIR = SCRIPT_DIR / "logs" / getpass.getuser()


RUN_CONFIG = {
    # Use "__all__" for all challenges, "__random__" for one random challenge,
    # or a concrete challenge name for a single challenge.
    "challenge": "__all__",
    # Set to a list of names to run a fixed subset in order, for example:
    # ["challenge-a", "challenge-b"]
    "challenges": None,
    "run_all": True,
    "category": None,
    "dataset": None,
    "split": "development",
    "container_image": "ctfenv:latest",
    "container_network": "ctfnet",
    "objective": None,
    "scope": None,
    "max_cycles": 25,
    "auto_max_cycles": False,
    "quiet": False,
    "debug": True,
    "skip_exist": False,
    "logdir": str(DEFAULT_LOGDIR),
    "name": "5.19_development_1",
    "index": None,
    "output_root": None,
    "parallel_workers": 5,
    "replicas": 1,
    "rag_mode": None,
    "sample_size": None,
    "sample_seed": None,
    "sample_strategy": "random",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run NYUCTF benchmark challenges through the autopentest framework."
    )
    parser.add_argument("--challenge", help="Challenge name, __all__, or __random__")
    parser.add_argument("--challenges", nargs="+", help="Run a fixed challenge subset in order")
    parser.add_argument("--run-all", action="store_true", default=None, help="Run all selected challenges")
    parser.add_argument("--category")
    parser.add_argument("--dataset")
    parser.add_argument("--split", choices=["test", "development"])
    parser.add_argument("--container-image")
    parser.add_argument("--container-network")
    parser.add_argument("--objective")
    parser.add_argument("--scope", action="append")
    parser.add_argument("--max-cycles", type=int)
    parser.add_argument("--auto-max-cycles", action="store_true", default=None)
    parser.add_argument("--quiet", action="store_true", default=None)
    parser.add_argument("--debug", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--skip-exist", action="store_true", default=None)
    parser.add_argument("--logdir")
    parser.add_argument("--name")
    parser.add_argument("--index", type=int)
    parser.add_argument("--output-root")
    parser.add_argument("--parallel-workers", type=int)
    parser.add_argument("--replicas", type=int)
    parser.add_argument("--rag-mode", choices=["enabled", "strict", "disabled"])
    parser.add_argument("--sample-size", type=int)
    parser.add_argument("--sample-seed", type=int)
    parser.add_argument(
        "--sample-strategy",
        choices=["random", "category_round_robin"],
    )
    return parser


def _args_from_config(argv: Sequence[str] | None = None) -> SimpleNamespace:
    config = dict(RUN_CONFIG)
    namespace = build_parser().parse_args(argv)
    overrides = {
        key: value
        for key, value in vars(namespace).items()
        if value is not None
    }
    challenge_selection_overridden = any(
        key in overrides for key in ("challenge", "challenges", "run_all")
    )
    config.update(overrides)
    config["logdir"] = config.get("logdir") or str(DEFAULT_LOGDIR)
    if challenge_selection_overridden:
        explicit_run_all = bool(overrides.get("run_all", False))
        config["run_all"] = bool(
            explicit_run_all
            or config.get("challenges")
            or config.get("challenge") == "__all__"
        )
    else:
        config["run_all"] = bool(
            config.get("run_all")
            or config.get("challenges")
            or config.get("challenge") == "__all__"
        )
    return SimpleNamespace(**config)


def main(argv: Sequence[str] | None = None) -> int:
    args = _args_from_config(argv)

    configure_logging(
        debug=bool(getattr(args, "debug", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )

    is_subset = bool(getattr(args, "challenges", None))
    is_run_all = is_subset or getattr(args, "run_all", False) or args.challenge == "__all__"

    if is_run_all:
        args.run_all = True
        return run_all_challenges(args)

    if not args.challenge:
        LOGGER.error("RUN_CONFIG['challenge'] is required, or set RUN_CONFIG['run_all'] to True")
        return 2

    return run_single_challenge_replicas(args)


if __name__ == "__main__":
    raise SystemExit(main())
