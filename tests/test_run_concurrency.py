"""Concurrency guard tests for the NYUCTF runner."""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from killchain_docker.batch.runner import run_all_challenges, run_single_challenge


class _DummyChallenge:
    canonical_name = "dummy-compose"


class _FakeDataset:
    basedir = "/tmp"

    def all(self) -> dict[str, dict[str, str]]:
        return {"alpha": {"name": "alpha"}, "beta": {"name": "beta"}}


def _args(logdir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        challenge="__all__",
        run_all=True,
        category=None,
        dataset=None,
        split="development",
        container_image="ctfenv:latest",
        container_network="ctfnet",
        objective=None,
        scope=None,
        max_cycles=8,
        quiet=True,
        debug=False,
        logdir=str(logdir),
        name=None,
        index=None,
        output_root=None,
        skip_exist=False,
        parallel_workers=1,
        replicas=1,
    )


class RunConcurrencyTests(unittest.TestCase):
    def test_single_challenge_enters_compose_lock_before_inner_run(self) -> None:
        events: list[str] = []

        @contextmanager
        def fake_lock(challenge):
            events.append(f"enter:{challenge.canonical_name}")
            yield
            events.append(f"exit:{challenge.canonical_name}")

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("killchain_docker.batch.runner.compose_challenge_run_lock", fake_lock),
                patch(
                    "killchain_docker.batch.runner._run_single_challenge_inner",
                    side_effect=lambda *_args: events.append("inner") or {"ok": True},
                ) as inner,
            ):
                result = run_single_challenge(_args(Path(tmp)), _DummyChallenge())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(events, ["enter:dummy-compose", "inner", "exit:dummy-compose"])
        self.assertEqual(inner.call_count, 1)

    def test_run_all_uses_process_pool_when_parallel_workers_gt_one(self) -> None:
        submissions: list[tuple[str, str]] = []
        observed_workers: list[int] = []

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                observed_workers.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, fn, _base_args, name: str):
                submissions.append((fn.__name__, name))
                future: futures.Future[dict[str, object]] = futures.Future()
                future.set_result(
                    {
                        "challenge": name,
                        "solved": name == "alpha",
                        "status": "solved" if name == "alpha" else "failed",
                        "api_error": False,
                        "llm_error": False,
                    }
                )
                return future

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.parallel_workers = 2
            with (
                patch("killchain_docker.batch.runner.load_dataset", return_value=_FakeDataset()),
                patch("killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor", FakeExecutor),
                patch("builtins.print"),
            ):
                rc = run_all_challenges(args)

        self.assertEqual(rc, 0)
        self.assertEqual(observed_workers, [2])
        self.assertEqual(
            submissions,
            [("_run_named_challenge_worker", "alpha"), ("_run_named_challenge_worker", "beta")],
        )


if __name__ == "__main__":
    unittest.main()
