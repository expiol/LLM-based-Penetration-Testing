from __future__ import annotations

import unittest
from pathlib import Path

from killchain_docker import cli


class CliLoggingTests(unittest.TestCase):
    def test_validation_error_logs_context_and_traceback(self) -> None:
        with self.assertLogs("killchain_docker.cli", level="ERROR") as captured:
            code = cli.main(["run", "--scope", "http://example.test"])

        self.assertEqual(code, 2)
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.getMessage(), "run rejected")
        self.assertEqual(record.command, "run")
        self.assertEqual(record.error_type, "ValueError")
        self.assertTrue(any("Traceback" in line for line in captured.output))

    def test_run_config_accepts_status_path(self) -> None:
        args = cli.build_parser().parse_args([
            "run",
            "--objective",
            "demo",
            "--scope",
            "http://example.test",
            "--status-path",
            "runs/demo.status.json",
        ])

        config = cli._config_from_args(args)

        self.assertEqual(config.status_path, "runs/demo.status.json")

    def test_demo_config_accepts_status_path(self) -> None:
        args = cli.build_parser().parse_args([
            "demo",
            "--output-root",
            str(Path("runs")),
            "--status-path",
            "runs/demo.status.json",
        ])

        config = cli._config_from_args(args)

        self.assertEqual(config.status_path, "runs/demo.status.json")


if __name__ == "__main__":
    unittest.main()
