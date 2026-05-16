"""Batch module: dataset loading, Docker lifecycle, and batch execution."""

from killchain_docker.batch.dataset import (
    challenge_metadata,
    derive_authorized_scope,
    derive_objective,
    estimate_max_cycles,
    load_challenge,
    load_dataset,
    challenge_names_for_category,
)
from killchain_docker.batch.docker import (
    compose_challenge_run_lock,
    start_challenge_with_retry,
)
from killchain_docker.batch.runner import (
    run_single_challenge,
    run_single_challenge_replicas,
    run_all_challenges,
)

__all__ = [
    "challenge_metadata",
    "challenge_names_for_category",
    "compose_challenge_run_lock",
    "derive_authorized_scope",
    "derive_objective",
    "estimate_max_cycles",
    "load_challenge",
    "load_dataset",
    "run_all_challenges",
    "run_single_challenge",
    "run_single_challenge_replicas",
    "start_challenge_with_retry",
]
