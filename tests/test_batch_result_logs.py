from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from killchain_docker.batch.result_logs import (
    BATCH_ARTIFACT_JSON_NAMES,
    is_result_log_path,
    iter_result_logs,
)


class BatchResultLogTests(unittest.TestCase):
    def test_metadata_and_status_json_are_not_result_logs(self) -> None:
        for name in BATCH_ARTIFACT_JSON_NAMES:
            self.assertFalse(is_result_log_path(Path(name)))
        self.assertFalse(is_result_log_path(Path("demo.status.json")))
        self.assertFalse(is_result_log_path(Path("demo.txt")))
        self.assertTrue(is_result_log_path(Path("demo.json")))

    def test_iter_result_logs_returns_only_challenge_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (
                "demo.json",
                "zeta.json",
                "_batch_summary.json",
                "_batch_monitor.json",
                "demo.status.json",
                "notes.txt",
            ):
                (root / name).write_text("{}", encoding="utf-8")

            names = [path.name for path in iter_result_logs(root)]

        self.assertEqual(names, ["demo.json", "zeta.json"])


if __name__ == "__main__":
    unittest.main()
