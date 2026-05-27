from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import plot_results  # noqa: E402


class PlotResultsTests(unittest.TestCase):
    def test_iter_result_logs_skips_batch_and_status_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (
                "demo.json",
                "_batch_summary.json",
                "_batch_monitor.json",
                "demo.status.json",
            ):
                (root / name).write_text("{}", encoding="utf-8")

            names = [path.name for path in plot_results.iter_result_logs(root)]

        self.assertEqual(names, ["demo.json"])

    def test_summarize_logdir_ignores_unrelated_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "demo.json").write_text(
                json.dumps({"solved": True}), encoding="utf-8"
            )
            (root / "_batch_summary.json").write_text(
                json.dumps({"finished": True}), encoding="utf-8"
            )

            summary = plot_results.summarize_logdir(root)

        self.assertIn("demo\t1", summary)
        self.assertIn("total_count: 1", summary)


if __name__ == "__main__":
    unittest.main()
