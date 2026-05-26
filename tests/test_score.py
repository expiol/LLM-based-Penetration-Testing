from __future__ import annotations

import contextlib
from io import StringIO
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker import score


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class ScoreTests(unittest.TestCase):
    def test_summarize_run_dir_skips_malformed_jsonl_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "results.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"challenge": "demo", "solved": True}),
                        "{",
                        "[]",
                        json.dumps({"solved": True}),
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertLogs(score.LOGGER.name, level="WARNING") as captured:
                results = score.summarize_run_dir(root)

        self.assertEqual(list(results), ["demo"])
        messages = "\n".join(captured.output)
        self.assertIn("skipping malformed score result row", messages)
        self.assertIn("skipping non-object score result row", messages)
        self.assertIn("skipping score result row without challenge", messages)

    def test_summarize_logdir_ignores_batch_and_status_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "demo.json",
                {
                    "challenge_metadata": {"canonical_name": "demo"},
                    "solved": True,
                    "status": "solved",
                    "state": {"validated_flag": "flag{demo}"},
                },
            )
            _write_json(root / "_batch_summary.json", {"solved_count": 999})
            _write_json(root / "_rag_ablation_audit.json", {"ok": False})
            _write_json(root / "demo.status.json", {"status": "running"})

            results = score.summarize_logdir(root)

        self.assertEqual(list(results), ["demo"])
        self.assertTrue(results["demo"]["solved"])

    def test_summarize_logdir_skips_malformed_result_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "demo.json",
                {"challenge_metadata": {"canonical_name": "demo"}, "solved": True},
            )
            (root / "bad.json").write_text("{", encoding="utf-8")
            (root / "list.json").write_text("[]", encoding="utf-8")

            with self.assertLogs(score.LOGGER.name, level="WARNING") as captured:
                results = score.summarize_logdir(root)

        self.assertEqual(list(results), ["demo"])
        messages = "\n".join(captured.output)
        self.assertIn("skipping unreadable score log", messages)
        self.assertIn("skipping non-object score log", messages)

    def test_diagnose_logdir_ignores_batch_and_status_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "failed.json",
                {
                    "challenge_metadata": {
                        "canonical_name": "failed",
                        "category": "web",
                    },
                    "solved": False,
                    "status": "stopped",
                    "state_metrics": {"worker_counts": {"web-worker": 50}},
                    "token_usage": {"total_tokens": 700000},
                    "state": {"rounds": []},
                },
            )
            _write_json(root / "failed.status.json", {"status": "running"})
            _write_json(root / "_batch_monitor.json", {"counts": {"active": 1}})

            diagnostics = score.diagnose_logdir(root)

        self.assertEqual(diagnostics["total"], 1)
        self.assertEqual(diagnostics["failed"], 1)
        self.assertEqual(diagnostics["details"][0]["challenge"], "failed")

    def test_diagnose_logdir_skips_malformed_result_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "failed.json",
                {
                    "challenge_metadata": {"canonical_name": "failed"},
                    "solved": False,
                    "state": {"rounds": []},
                },
            )
            (root / "bad.json").write_text("{", encoding="utf-8")

            with self.assertLogs(score.LOGGER.name, level="WARNING"):
                diagnostics = score.diagnose_logdir(root)

        self.assertEqual(diagnostics["total"], 1)
        self.assertEqual(diagnostics["details"][0]["challenge"], "failed")

    def test_main_accepts_argv_for_logdir_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "score.json"
            _write_json(
                root / "demo.json",
                {"challenge_metadata": {"canonical_name": "demo"}, "solved": True},
            )
            stdout = StringIO()

            with patch("killchain_docker.score.challenge_names", return_value=["demo"]):
                with contextlib.redirect_stdout(stdout):
                    code = score.main(
                        [
                            "--logdir",
                            str(root),
                            "--output",
                            str(output),
                            "--quiet",
                        ]
                    )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload["score"]["solved"], 1)
        self.assertIn('"solved": 1', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
