from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import database_summary  # noqa: E402


class DatabaseSummaryTests(unittest.TestCase):
    def test_build_summary_skips_non_object_challenge_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = root / "2026" / "Quals" / "crypto" / "demo"
            invalid = root / "2026" / "Quals" / "misc" / "bad"
            valid.mkdir(parents=True)
            invalid.mkdir(parents=True)
            (valid / "challenge.json").write_text(
                json.dumps({"description": "recover the flag"}),
                encoding="utf-8",
            )
            (invalid / "challenge.json").write_text("[]", encoding="utf-8")

            with self.assertLogs(database_summary.LOGGER.name, level="WARNING"):
                rows = database_summary.build_summary(root)

        self.assertEqual(rows, [{
            "year": "2026",
            "event": "Quals",
            "category": "crypto",
            "name": "demo",
            "description": "recover the flag",
        }])

    def test_main_writes_summary_from_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dataset"
            challenge = root / "2026" / "Finals" / "web" / "demo"
            output = Path(tmp) / "summary.json"
            challenge.mkdir(parents=True)
            (challenge / "challenge.json").write_text(
                json.dumps({"description": "inspect app"}),
                encoding="utf-8",
            )

            code = database_summary.main([
                "--dataset-root", str(root),
                "--output", str(output),
            ])
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(payload[0]["category"], "web")
        self.assertEqual(payload[0]["description"], "inspect app")


if __name__ == "__main__":
    unittest.main()
