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

import log_summary  # noqa: E402


def _challenge_dir(root: Path) -> Path:
    path = root / "2026" / "Final" / "crypto" / "demo"
    path.mkdir(parents=True)
    return path


class LogSummaryTests(unittest.TestCase):
    def test_summarize_challenge_skips_malformed_conversation_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            challenge = _challenge_dir(Path(tmp))
            (challenge / "valid.json").write_text(
                json.dumps(
                    {
                        "solved": True,
                        "messages": [["user", {"content": "nc None"}]],
                    }
                ),
                encoding="utf-8",
            )
            (challenge / "bad.json").write_text("{", encoding="utf-8")
            (challenge / "list.json").write_text("[]", encoding="utf-8")

            with self.assertLogs(log_summary.LOGGER.name, level="WARNING") as captured:
                summary = log_summary.summarize_challenge(challenge, model=None)

        self.assertIsNotNone(summary)
        row, solved = summary
        self.assertTrue(solved)
        self.assertEqual(row[1], "1/3")
        self.assertIn("ServerMissing", row[2])
        self.assertIn("invalid_json", row[3])
        messages = "\n".join(captured.output)
        self.assertIn("invalid json", messages)
        self.assertIn("invalid conversation payload", messages)

    def test_main_accepts_argv_and_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            challenge = _challenge_dir(root)
            (challenge / "gpt-3.5-turbo-1106.json").write_text(
                json.dumps({"solved": True, "messages": []}),
                encoding="utf-8",
            )
            stdout = StringIO()

            with contextlib.redirect_stdout(stdout):
                code = log_summary.main(["--log-dir", str(root)])

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("demo(2026f)", output)
        self.assertIn("Success: 1/1 100.00%", output)


if __name__ == "__main__":
    unittest.main()
