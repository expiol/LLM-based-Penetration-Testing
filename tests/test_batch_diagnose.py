from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

SPEC = importlib.util.spec_from_file_location(
    "batch_diagnose", SCRIPT_DIR / "batch_diagnose.py"
)
assert SPEC is not None
batch_diagnose = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(batch_diagnose)


class BatchDiagnoseClassificationTests(unittest.TestCase):
    def test_partial_todos_unsolved_after_max_cycles_is_llm_limit(self) -> None:
        result = {
            "status": "failed",
            "effective_max_cycles": 25,
            "state_metrics": {
                "stop_reason": "partial_todos_unsolved",
                "round_count": 25,
            },
        }
        state = {
            "stop_reason": "partial_todos_unsolved",
            "rounds": [
                {
                    "results": [
                        {
                            "result_quality": "partial_no_candidate",
                            "output_context": {"failure_kind": "no_candidate"},
                        },
                        {"result_quality": "near_miss"},
                    ]
                }
            ],
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "likely_llm_limit")
        self.assertIn("near_miss", reason)
        self.assertIn("no_candidate", reason)

    def test_partial_todos_unsolved_preserves_framework_signal(self) -> None:
        result = {
            "status": "failed",
            "effective_max_cycles": 25,
            "state_metrics": {
                "stop_reason": "partial_todos_unsolved",
                "round_count": 25,
            },
        }
        state = {
            "stop_reason": "partial_todos_unsolved",
            "rounds": [
                {
                    "results": [
                        {
                            "output_context": {
                                "failure_kind": "tool_missing_target_files"
                            }
                        }
                    ]
                }
            ],
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "framework_signal")
        self.assertEqual(reason, "tool_missing_target_files")


if __name__ == "__main__":
    unittest.main()
