from __future__ import annotations

import contextlib
from io import StringIO
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import flag_in_output  # noqa: E402


class _Dataset:
    basedir = "/dataset"

    def __init__(self) -> None:
        self.names: list[str] = []

    def get(self, name: str) -> dict[str, str]:
        self.names.append(name)
        return {"name": name, "flag": "FLAG{demo}"}


class _Challenge:
    def __init__(self, payload: dict[str, str], _basedir: str) -> None:
        self.flag = payload["flag"]


class FlagInOutputTests(unittest.TestCase):
    def test_iter_result_logs_skips_batch_and_status_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (
                "demo.json",
                "_batch_summary.json",
                "_batch_monitor.json",
                "_rag_ablation.json",
                "_rag_ablation_audit.json",
                "demo.status.json",
            ):
                (root / name).write_text("{}", encoding="utf-8")

            names = [path.name for path in flag_in_output.iter_result_logs(root)]

        self.assertEqual(names, ["demo.json"])

    def test_log_contains_flag_handles_malformed_message_shapes(self) -> None:
        payload = {
            "planner": ["bad", {"content": "no flag"}],
            "executors": [
                "bad",
                [{"content": "found FLAG{demo}"}],
            ],
        }

        self.assertTrue(flag_in_output.log_contains_flag("", payload, "FLAG{demo}"))
        self.assertFalse(flag_in_output.log_contains_flag("", payload, ""))

    def test_main_skips_generated_batch_artifacts(self) -> None:
        dataset = _Dataset()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "_batch_summary.json").write_text(
                json.dumps({"details": []}), encoding="utf-8"
            )
            (root / "demo.status.json").write_text("{}", encoding="utf-8")
            (root / "demo.json").write_text(
                json.dumps(
                    {
                        "success": False,
                        "planner": [{"content": "candidate FLAG{demo}"}],
                    }
                ),
                encoding="utf-8",
            )
            stdout = StringIO()

            with patch("flag_in_output.CTFDataset", return_value=dataset):
                with patch("flag_in_output.CTFChallenge", _Challenge):
                    with contextlib.redirect_stdout(stdout):
                        code = flag_in_output.main(["--logdir", str(root)])

        self.assertEqual(code, 0)
        self.assertEqual(dataset.names, ["demo"])
        self.assertEqual(stdout.getvalue().strip(), "Flag found in messages: demo")


if __name__ == "__main__":
    unittest.main()
