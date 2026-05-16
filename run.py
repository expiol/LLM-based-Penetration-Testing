"""Thin CLI entrypoint — delegates to killchain_docker.batch for implementation."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

# Backwards-compatible re-exports; implementation lives in killchain_docker.batch.
from killchain_docker.batch import (
    load_challenge,
    run_all_challenges,
    run_single_challenge,
    run_single_challenge_replicas,
)
from killchain_docker.batch.runner import (
    _load_llm_experiment_config,
    _run_single_challenge_inner,
    _save_batch_progress,
)

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    运行参数配置                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

CHALLENGE       = "__all__"
DATASET         = None
SPLIT           = "development"
CATEGORY        = None
CONTAINER_IMAGE = "ctfenv:latest"
CONTAINER_NETWORK = "ctfnet"
OBJECTIVE       = None
SCOPE           = None
MAX_CYCLES      = 25
QUIET           = False
DEBUG           = True
SKIP_EXIST      = False
LOGDIR          = None
NAME            = "5.16_development_1"
INDEX           = None
OUTPUT_ROOT     = None
PARALLEL_WORKERS = 5
REPLICAS        = 1

SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_LOGDIR = SCRIPT_DIR / "logs" / getpass.getuser()


def _args_from_config() -> argparse.Namespace:
    return argparse.Namespace(
        challenge=CHALLENGE,
        run_all=CHALLENGE == "__all__",
        category=CATEGORY,
        dataset=DATASET,
        split=SPLIT,
        container_image=CONTAINER_IMAGE,
        container_network=CONTAINER_NETWORK,
        objective=OBJECTIVE,
        scope=SCOPE,
        max_cycles=MAX_CYCLES,
        quiet=QUIET,
        debug=DEBUG,
        skip_exist=SKIP_EXIST,
        logdir=LOGDIR or str(DEFAULT_LOGDIR),
        name=NAME,
        index=INDEX,
        output_root=OUTPUT_ROOT,
        parallel_workers=PARALLEL_WORKERS,
        replicas=REPLICAS,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the structured LLM killchain on NYUCTF challenges",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--challenge", default=None)
    parser.add_argument("--run-all", action="store_true")
    parser.add_argument("--category")
    parser.add_argument("--dataset")
    parser.add_argument("-s", "--split", default="development", choices=["test", "development"])
    parser.add_argument("-C", "--container-image", default="ctfenv:latest")
    parser.add_argument("-N", "--container-network", default="ctfnet")
    parser.add_argument("--objective")
    parser.add_argument("--scope", action="append", dest="scope")
    parser.add_argument("--max-cycles", type=int, default=8)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--skip-exist", "--skip-existing", dest="skip_exist", action="store_true")
    parser.add_argument("-L", "--logdir", default=str(DEFAULT_LOGDIR))
    parser.add_argument("-n", "--name")
    parser.add_argument("-i", "--index")
    parser.add_argument("--output-root")
    parser.add_argument("--parallel-workers", type=int, default=1)
    parser.add_argument("--replicas", type=int, default=1)
    return parser


def main() -> int:
    if len(sys.argv) > 1:
        args = build_parser().parse_args()
    else:
        args = _args_from_config()

    is_run_all = getattr(args, "run_all", False) or args.challenge == "__all__"

    if is_run_all:
        args.run_all = True
        return run_all_challenges(args)

    if not args.challenge:
        print("Error: --challenge is required (or use --run-all)")
        return 2

    return run_single_challenge_replicas(args)


if __name__ == "__main__":
    raise SystemExit(main())
