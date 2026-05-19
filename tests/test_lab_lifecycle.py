"""Tests for optional Docker Compose lab lifecycle helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.processes import BoundedProcessResult
from killchain_docker import lab


class LabLifecycleTests(unittest.TestCase):
    def test_lab_up_uses_bounded_process_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            compose = Path(tmpdir) / "docker-compose.lab.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            with (
                patch("killchain_docker.lab.shutil.which", return_value="/usr/bin/docker"),
                patch(
                    "killchain_docker.lab.run_bounded_process",
                    return_value=BoundedProcessResult(exit_code=7, stdout="", stderr=""),
                ) as run_bounded,
            ):
                exit_code = lab.lab_up(compose, detach=True, timeout_s=123)

        self.assertEqual(exit_code, 7)
        kwargs = run_bounded.call_args.kwargs
        argv = run_bounded.call_args.args[0]
        self.assertEqual(kwargs["timeout_s"], 123)
        self.assertEqual(kwargs["max_output_bytes"], 20_000)
        self.assertEqual(argv[-2:], ["up", "-d"])

    def test_lab_down_uses_bounded_process_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            compose = Path(tmpdir) / "docker-compose.lab.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            with (
                patch("killchain_docker.lab.shutil.which", return_value="/usr/bin/docker"),
                patch(
                    "killchain_docker.lab.run_bounded_process",
                    return_value=BoundedProcessResult(exit_code=0, stdout="", stderr=""),
                ) as run_bounded,
            ):
                exit_code = lab.lab_down(compose, remove_volumes=True, timeout_s=321)

        self.assertEqual(exit_code, 0)
        kwargs = run_bounded.call_args.kwargs
        argv = run_bounded.call_args.args[0]
        self.assertEqual(kwargs["timeout_s"], 321)
        self.assertEqual(kwargs["max_output_bytes"], 20_000)
        self.assertEqual(argv[-2:], ["down", "-v"])


if __name__ == "__main__":
    unittest.main()
