"""Regression tests for batch summary experiment metrics."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.score import diagnose_logdir
from run import _save_batch_progress


def _args(logdir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        challenge="__all__",
        run_all=True,
        category="crypto",
        dataset=None,
        split="development",
        container_image="ctfenv:latest",
        container_network="ctfnet",
        objective=None,
        scope=None,
        max_cycles=20,
        quiet=True,
        debug=False,
        skip_exist=False,
        logdir=str(logdir),
        name="paper_run",
        index=None,
        output_root=None,
        parallel_workers=2,
        replicas=1,
    )


class BatchSummaryTests(unittest.TestCase):
    def test_summary_includes_token_usage_and_paper_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            result = {
                "challenge": "2013f-cry-example",
                "run_id": "run-direct",
                "solved": True,
                "status": "solved",
                "runtime_sec": 12.5,
                "logfile": None,
                "max_cycles": 20,
                "authorized_scope": ["tcp://example:31337"],
                "challenge_metadata": {
                    "category": "crypto",
                    "files": ["chall.py", "flag.enc"],
                    "server_name": "example",
                    "port": 31337,
                    "server_type": "tcp",
                },
                "token_usage": {
                    "llm_calls": 2,
                    "prompt_tokens": 100,
                    "completion_tokens": 30,
                    "total_tokens": 130,
                },
                "state_metrics": {
                    "task_count": 4,
                    "open_task_count": 0,
                    "task_status_counts": {"completed": 4},
                    "task_type_counts": {"artifact.source_review": 1},
                    "evidence_tool_counts": {"script_execution": 1},
                },
            }

            with patch(
                "run._load_llm_experiment_config",
                return_value={"available": True, "default_model": "test-model"},
            ):
                path = _save_batch_progress(args, [result], time.time() - 10, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 2)
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 130)
            self.assertEqual(payload["token_usage"]["mean_per_attempt"]["prompt_tokens"], 100.0)
            self.assertEqual(payload["paper_metrics"]["success_rate"], 1.0)
            self.assertEqual(payload["paper_metrics"]["task_count_total"], 4)
            self.assertEqual(payload["paper_metrics"]["task_type_totals"]["artifact.source_review"], 1)
            self.assertEqual(payload["paper_metrics"]["evidence_tool_totals"]["script_execution"], 1)
            self.assertEqual(payload["paper_metrics"]["category_counts"]["crypto"], 1)
            self.assertEqual(payload["experiment_config"]["max_cycles_arg"], 20)
            self.assertEqual(payload["experiment_config"]["parallel_workers"], 2)
            self.assertEqual(payload["experiment_config"]["llm_gateway"]["default_model"], "test-model")
            detail = payload["details"][0]
            self.assertEqual(detail["run_id"], "run-direct")
            self.assertEqual(detail["files_count"], 2)
            self.assertTrue(detail["has_server"])
            self.assertEqual(detail["authorized_scope_count"], 1)

    def test_summary_recovers_metrics_from_challenge_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "single_run.json"
            log_path.write_text(
                json.dumps(
                    {
                        "summary": {
                            "run_id": "run-from-log",
                            "token_usage": {
                                "llm_calls": 3,
                                "prompt_tokens": 210,
                                "completion_tokens": 45,
                                "total_tokens": 255,
                            },
                        },
                        "challenge_metadata": {
                            "category": "web",
                            "files": [],
                            "server_name": "webhost",
                            "port": 8080,
                            "server_type": "web",
                        },
                        "authorized_scope": ["http://webhost:8080"],
                        "effective_max_cycles": 16,
                        "state": {
                            "run_id": "run-from-log",
                            "status": "failed",
                            "assets": {"asset-1": {}},
                            "findings": {},
                            "credentials": {},
                            "execution_log": [{"task_id": "task-1"}],
                            "task_chain": {
                                "tasks": [
                                    {"status": "completed", "task_type": "recon.scan"},
                                    {"status": "pending", "task_type": "web.form_probe"},
                                    {"status": "failed", "task_type": "flag.validate"},
                                ]
                            },
                            "evidence": {
                                "e1": {"tool_name": "http_probe"},
                                "e2": {"tool_name": "http_form_probe"},
                            },
                            "task_type_memory": {"artifact.source_review": [{"attempt": 1}]},
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = {
                "challenge": "2013f-web-example",
                "solved": False,
                "status": "failed",
                "runtime_sec": 30,
                "logfile": str(log_path),
            }

            with patch(
                "run._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(args, [result], time.time() - 60, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 255)
            self.assertEqual(payload["paper_metrics"]["token_usage_mean_failed"]["llm_calls"], 3.0)
            self.assertEqual(payload["paper_metrics"]["open_task_count_total"], 1)
            self.assertEqual(payload["paper_metrics"]["task_status_totals"]["pending"], 1)
            self.assertEqual(payload["paper_metrics"]["task_type_totals"]["web.form_probe"], 1)
            self.assertEqual(payload["paper_metrics"]["evidence_tool_totals"]["http_form_probe"], 1)
            detail = payload["details"][0]
            self.assertEqual(detail["run_id"], "run-from-log")
            self.assertEqual(detail["category"], "web")
            self.assertEqual(detail["server_type"], "web")
            self.assertEqual(detail["max_cycles"], 16)
            self.assertEqual(detail["state_metrics"]["asset_count"], 1)
            self.assertEqual(detail["state_metrics"]["execution_count"], 1)
            self.assertEqual(detail["state_metrics"]["task_type_memory_counts"]["artifact.source_review"], 1)

    def test_logdir_diagnostics_bucket_failure_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "failed.json").write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "stopped",
                        "finish_reason": "stopped",
                        "token_usage": {"total_tokens": 700000},
                        "challenge_metadata": {
                            "canonical_name": "failed-web",
                            "category": "web",
                        },
                        "state_metrics": {
                            "task_type_counts": {
                                "artifact.source_review": 18,
                                "flag.validate": 5,
                                "web.path_probe": 50,
                            },
                            "evidence_tool_counts": {"script_execution": 18},
                            "open_task_count": 4,
                        },
                        "state": {"task_type_memory": {}},
                    }
                ),
                encoding="utf-8",
            )
            payload = diagnose_logdir(root)

        self.assertEqual(payload["failed"], 1)
        self.assertEqual(payload["bucket_counts"]["script_tool_spin"], 1)
        self.assertEqual(payload["bucket_counts"]["web_probe_fanout"], 1)
        self.assertEqual(payload["bucket_counts"]["candidate_validation_loop"], 1)


if __name__ == "__main__":
    unittest.main()
