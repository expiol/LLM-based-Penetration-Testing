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

    def test_transient_llm_error_requires_retry(self) -> None:
        result = {
            "status": "failed",
            "state_metrics": {"stop_reason": "llm_transient_error"},
        }
        state = {
            "metadata": {
                "last_llm_error": {
                    "kind": "timeout",
                    "transient": True,
                    "schema": "ToolUseDecision",
                }
            }
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "needs_retry")
        self.assertIn("rerun required", reason)

    def test_unsolved_no_work_remaining_without_framework_signal_is_llm_limit(
        self,
    ) -> None:
        result = {
            "status": "unsolved_exhausted",
            "state_metrics": {
                "stop_reason": "unsolved_no_work_remaining",
                "round_count": 8,
            },
        }
        state = {
            "stop_reason": "unsolved_no_work_remaining",
            "rounds": [
                {
                    "results": [
                        {
                            "result_quality": "partial_no_candidate",
                            "output_context": {"failure_kind": "no_candidate"},
                        }
                    ]
                }
            ],
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "likely_llm_limit")
        self.assertIn("no_candidate", reason)

    def test_todo_failed_from_probe_miss_is_llm_limit(self) -> None:
        result = {
            "status": "failed",
            "state_metrics": {
                "stop_reason": "todo_failed",
                "todo_status_counts": {"failed": 1, "completed": 4},
            },
        }
        state = {
            "stop_reason": "todo_failed",
            "rounds": [
                {
                    "results": [
                        {
                            "result_quality": "partial_probe_miss",
                            "output_context": {
                                "failure_kind": "partial_probe_miss",
                                "result_quality": "partial_probe_miss",
                            },
                        },
                        {
                            "result_quality": "partial_no_candidate",
                            "output_context": {"failure_kind": "no_candidate"},
                        },
                    ]
                }
            ],
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "likely_llm_limit")
        self.assertIn("partial_probe_miss", reason)

    def test_todo_failed_preserves_model_output_signal(self) -> None:
        result = {
            "status": "failed",
            "state_metrics": {"stop_reason": "todo_failed"},
        }
        state = {
            "rounds": [
                {
                    "results": [
                        {"output_context": {"failure_kind": "masked_shell_error"}}
                    ]
                }
            ],
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, state, []
        )

        self.assertEqual(classification, "model_output_quality")
        self.assertEqual(reason, "masked_shell_error")

    def test_challenge_timeout_is_framework_signal(self) -> None:
        result = {
            "status": "challenge_timeout",
            "runtime_error": {"type": "ChallengeWatchdogTimeout"},
            "state_metrics": {"stop_reason": "challenge_timeout"},
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, {}, []
        )

        self.assertEqual(classification, "framework_signal")
        self.assertEqual(reason, "challenge_timeout")

    def test_docker_compose_error_payload_is_docker_start_signal(self) -> None:
        result = {
            "status": "failed",
            "error": {
                "type": "CalledProcessError",
                "message": "docker compose up failed\nDockerfile:13\nfailed to solve",
            },
        }

        classification, reason = batch_diagnose.classify_result(
            result, {}, {}, []
        )

        self.assertEqual(classification, "framework_signal")
        self.assertEqual(reason, "docker_start_error")


if __name__ == "__main__":
    unittest.main()
