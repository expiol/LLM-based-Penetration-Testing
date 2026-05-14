"""Concurrency guard tests for the NYUCTF runner."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from run import run_single_challenge


class _DummyChallenge:
    canonical_name = "dummy-compose"


def _args(logdir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        logdir=str(logdir),
        name=None,
        index=None,
        skip_exist=False,
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
                patch("run._compose_challenge_run_lock", fake_lock),
                patch(
                    "run._run_single_challenge_inner",
                    side_effect=lambda *_args: events.append("inner") or {"ok": True},
                ) as inner,
            ):
                result = run_single_challenge(_args(Path(tmp)), _DummyChallenge())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(events, ["enter:dummy-compose", "inner", "exit:dummy-compose"])
        self.assertEqual(inner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
