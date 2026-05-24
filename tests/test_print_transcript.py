from __future__ import annotations

import contextlib
from io import StringIO
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import print_transcript  # noqa: E402


class PrintTranscriptTests(unittest.TestCase):
    def test_render_transcript_ignores_malformed_message_shapes(self) -> None:
        payload = {
            "planner": [
                {
                    "role": "assistant",
                    "content": "delegate work",
                    "tool_call": {"name": "delegate", "parsed_args": ["bad"]},
                },
                "bad",
            ],
            "executors": [
                [{"role": "tool", "content": "executor output"}],
                "bad",
            ],
        }

        rendered = print_transcript.render_transcript(payload)

        self.assertIn("delegate work", rendered)
        self.assertIn("executor output", rendered)

    def test_main_logs_unreadable_transcript_with_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{", encoding="utf-8")
            stdout = StringIO()

            with self.assertLogs(
                print_transcript.LOGGER.name, level="ERROR"
            ) as captured:
                with contextlib.redirect_stdout(stdout):
                    code = print_transcript.main(["--transcript", str(path)])

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        record = captured.records[0]
        self.assertEqual(record.getMessage(), "transcript unreadable")
        self.assertEqual(record.path, str(path.resolve()))
        self.assertIsNotNone(record.exc_info)

    def test_main_renders_valid_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "transcript.json"
            path.write_text(
                json.dumps({"planner": [{"role": "assistant", "content": "hello"}]}),
                encoding="utf-8",
            )
            stdout = StringIO()

            with contextlib.redirect_stdout(stdout):
                code = print_transcript.main(["--transcript", str(path)])

        self.assertEqual(code, 0)
        self.assertIn("hello", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
