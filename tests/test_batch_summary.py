"""Regression tests for batch summary experiment metrics."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from killchain_docker.llm import LLMClientError
from killchain_docker.batch.runner import (
    _run_single_challenge_inner,
    _save_batch_progress,
    run_single_challenge_replicas,
)
from killchain_docker.controller import RunArtifacts, RunConfig, run_assessment
from killchain_docker.llm.gateway import TokenLedger
from killchain_docker.score import diagnose_logdir
from killchain_docker.state import RunState, RunStatus


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


class _FakeChallenge:
    canonical_name = "fake-interrupt"
    name = "fake"
    category = "crypto"
    description = "fake"
    flag = "flag{fake}"
    flag_format = "flag{...}"
    files: list[str] = []
    server_name = ""
    port = None
    server_type = None
    server_description = None
    container = False
    challenge_info = {"name": "fake", "category": "crypto"}
    challenge = {"name": "fake", "category": "crypto"}

    def stop_challenge_container(self) -> None:
        return None


class _FakeEnvironment:
    container = None

    def __init__(self, *_args, **_kwargs) -> None:
        return None

    def setup(self) -> None:
        return None

    def teardown(self) -> None:
        return None


class _StartedFakeEnvironment(_FakeEnvironment):
    container = "fake-container"


class _RaisingOrchestrator:
    def __init__(self, state: RunState) -> None:
        self.state = state
        self.checkpoint_callback = None

    def run(self, max_cycles: int) -> None:
        del max_cycles
        self.state.status = RunStatus.FAILED
        raise LLMClientError("worker LLM failure")


def _write_artifacts(root: Path, status: str = "failed") -> RunArtifacts:
    run_dir = root / "artifacts" / _FakeChallenge.canonical_name / "run-attached"
    run_dir.mkdir(parents=True)
    state_path = run_dir / "state.json"
    summary_path = run_dir / "summary.json"
    report_path = run_dir / "report.md"
    events_path = run_dir / "events.log"
    config_path = run_dir / "config.json"
    evidence_path = run_dir / "evidence.json"
    compact_json_path = run_dir / "compact_log.json"
    compact_markdown_path = run_dir / "compact_log.md"
    summary_path.write_text(
        json.dumps(
            {
                "run_id": "run-attached",
                "status": status,
                "solved": False,
                "token_usage": {
                    "llm_calls": 1,
                    "prompt_tokens": 7,
                    "completion_tokens": 2,
                    "total_tokens": 9,
                },
            }
        ),
        encoding="utf-8",
    )
    state_path.write_text(
        json.dumps(
            {
                "run_id": "run-attached",
                "status": status,
                "todos": [{"status": "failed", "assigned_worker": "artifact-worker"}],
                "rounds": [{"cycle": 1}],
                "evidence": {},
            }
        ),
        encoding="utf-8",
    )
    report_path.write_text("# report\n", encoding="utf-8")
    events_path.write_text("[token usage] calls=1 prompt=7 completion=2 total=9\n", encoding="utf-8")
    config_path.write_text("{}", encoding="utf-8")
    evidence_path.write_text("{}", encoding="utf-8")
    compact_json_path.write_text("{}", encoding="utf-8")
    compact_markdown_path.write_text("# compact\n", encoding="utf-8")
    return RunArtifacts(
        run_id="run-attached",
        run_dir=str(run_dir),
        state_path=str(state_path),
        summary_path=str(summary_path),
        report_path=str(report_path),
        events_path=str(events_path),
        config_path=str(config_path),
        evidence_path=str(evidence_path),
        compact_json_path=str(compact_json_path),
        compact_markdown_path=str(compact_markdown_path),
        status=status,
    )


class BatchSummaryTests(unittest.TestCase):
    def test_single_challenge_interrupt_writes_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.name = None
            logfile = Path(tmp) / "fake-interrupt.json"

            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _FakeEnvironment),
                patch("killchain_docker.batch.runner.build_llm_client_from_env", side_effect=KeyboardInterrupt()),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)  # type: ignore[arg-type]

            payload = json.loads(logfile.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "interrupted")
            self.assertTrue(result["interrupted"])
            self.assertEqual(payload["status"], "interrupted")
            self.assertEqual(payload["error"]["type"], "KeyboardInterrupt")

    def test_single_challenge_llm_error_is_fatal_batch_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.name = None
            logfile = Path(tmp) / "fake-llm-error.json"

            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _FakeEnvironment),
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env",
                    side_effect=LLMClientError("preflight connection failed", transient=True),
                ),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)  # type: ignore[arg-type]

            payload = json.loads(logfile.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["api_error"])
            self.assertTrue(result["llm_error"])
            self.assertEqual(payload["error"]["type"], "LLMClientError")
            self.assertTrue(payload["llm_error"])

    def test_run_assessment_attaches_artifacts_to_runtime_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(objective="fake objective", authorized_scope=[])
            orchestrator = _RaisingOrchestrator(state)
            ledger = TokenLedger()
            ledger.record(11, 4)
            client = SimpleNamespace(token_ledger=ledger)
            config = RunConfig(
                objective="fake objective",
                authorized_scope=[],
                output_root=tmp,
                quiet=True,
            )

            with patch(
                "killchain_docker.controller.build_runtime",
                return_value=(state, orchestrator, client),
            ):
                with self.assertRaises(LLMClientError) as ctx:
                    run_assessment(config)

            artifacts = getattr(ctx.exception, "run_artifacts", None)
            self.assertIsInstance(artifacts, RunArtifacts)
            assert isinstance(artifacts, RunArtifacts)
            self.assertEqual(artifacts.status, "failed")
            summary = json.loads(Path(artifacts.summary_path).read_text(encoding="utf-8"))
            self.assertEqual(summary["token_usage"]["total_tokens"], 15)

    def test_single_challenge_recovers_attached_artifacts_after_llm_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            args.name = None
            logfile = root / "fake-attached-artifacts.json"
            artifacts = _write_artifacts(root)
            exc = LLMClientError("worker LLM failure")
            setattr(exc, "run_artifacts", artifacts)

            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _StartedFakeEnvironment),
                patch("killchain_docker.batch.runner.build_llm_client_from_env", return_value=object()),
                patch("killchain_docker.batch.runner.start_challenge_with_retry"),
                patch("killchain_docker.batch.runner.build_execution_plane", return_value=object()),
                patch("killchain_docker.batch.runner.run_assessment", side_effect=exc),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)  # type: ignore[arg-type]

            payload = json.loads(logfile.read_text(encoding="utf-8"))
            self.assertEqual(result["run_id"], "run-attached")
            self.assertEqual(result["token_usage"]["total_tokens"], 9)
            self.assertEqual(payload["artifacts"]["run_id"], "run-attached")
            self.assertEqual(payload["state_metrics"]["todo_count"], 1)

    def test_single_challenge_docker_execution_plane_keeps_stdin_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            args.name = None
            logfile = root / "fake-success.json"
            artifacts = _write_artifacts(root, status="completed")

            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _StartedFakeEnvironment),
                patch("killchain_docker.batch.runner.build_llm_client_from_env", return_value=object()),
                patch("killchain_docker.batch.runner.start_challenge_with_retry"),
                patch("killchain_docker.batch.runner.build_execution_plane", return_value=object()) as build_plane,
                patch("killchain_docker.batch.runner.run_assessment", return_value=artifacts),
            ):
                _run_single_challenge_inner(args, _FakeChallenge(), logfile)  # type: ignore[arg-type]

            build_plane.assert_called_once_with(
                argv_prefix=["docker", "exec", "-i", "fake-container"],
                python_executable="python3",
            )

    def test_single_replica_interrupted_result_returns_130(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.run_all = False
            args.challenge = "fake-interrupt"
            args.replicas = 1

            with (
                patch("killchain_docker.batch.runner.load_challenge", return_value=_FakeChallenge()),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    return_value={
                        "challenge": "fake-interrupt",
                        "status": "interrupted",
                        "solved": False,
                        "error": {"type": "KeyboardInterrupt", "message": "Run interrupted"},
                        "logfile": str(Path(tmp) / "fake-interrupt.json"),
                    },
                ),
                patch("builtins.print"),
            ):
                rc = run_single_challenge_replicas(args)

            self.assertEqual(rc, 130)

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
                    "todo_count": 4,
                    "open_todo_count": 0,
                    "todo_status_counts": {"completed": 4},
                    "worker_counts": {"artifact-worker": 1},
                    "evidence_tool_counts": {"script_exec": 1},
                },
            }

            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": True, "default_model": "test-model"},
            ):
                path = _save_batch_progress(args, [result], time.time() - 10, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 2)
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 130)
            self.assertEqual(payload["token_usage"]["mean_per_attempt"]["prompt_tokens"], 100.0)
            self.assertEqual(payload["paper_metrics"]["success_rate"], 1.0)
            self.assertEqual(payload["paper_metrics"]["todo_count_total"], 4)
            self.assertEqual(payload["paper_metrics"]["worker_totals"]["artifact-worker"], 1)
            self.assertEqual(payload["paper_metrics"]["evidence_tool_totals"]["script_exec"], 1)
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
                            "execution_log": [{"task_id": "todo-1"}],
                            "todos": [
                                {"status": "completed", "assigned_worker": "recon-worker"},
                                {"status": "pending", "assigned_worker": "web-worker"},
                                {"status": "failed", "assigned_worker": "flag-worker"},
                            ],
                            "rounds": [{"cycle": 1}],
                            "evidence": {
                                "e1": {"tool_name": "http_probe"},
                                "e2": {"tool_name": "http_form_probe"},
                            },
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
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(args, [result], time.time() - 60, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 255)
            self.assertEqual(payload["paper_metrics"]["token_usage_mean_failed"]["llm_calls"], 3.0)
            self.assertEqual(payload["paper_metrics"]["open_todo_count_total"], 1)
            self.assertEqual(payload["paper_metrics"]["todo_status_totals"]["pending"], 1)
            self.assertEqual(payload["paper_metrics"]["worker_totals"]["web-worker"], 1)
            self.assertEqual(payload["paper_metrics"]["evidence_tool_totals"]["http_form_probe"], 1)
            detail = payload["details"][0]
            self.assertEqual(detail["run_id"], "run-from-log")
            self.assertEqual(detail["category"], "web")
            self.assertEqual(detail["server_type"], "web")
            self.assertEqual(detail["max_cycles"], 16)
            self.assertEqual(detail["state_metrics"]["asset_count"], 1)
            self.assertEqual(detail["state_metrics"]["execution_count"], 1)
            self.assertEqual(detail["state_metrics"]["round_count"], 1)

    def test_summary_includes_failure_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "failed_run.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "failed",
                        "error": {
                            "type": "CalledProcessError",
                            "message": "docker compose up failed: bind: address already in use",
                        },
                        "state": {
                            "metadata": {
                                "last_llm_error": {
                                    "kind": "schema_validation",
                                    "schema_name": "ToolUseDecision",
                                }
                            },
                            "todos": [
                                {"status": "failed", "error": "candidate mismatch"},
                                {"status": "failed", "error": "script.execute missing required metadata.script_code"},
                            ],
                            "evidence": {
                                "e1": {"tool_name": "pcap_review", "summary": "PCAP review completed for 0 file(s): 0 URL(s)"},
                                "e2": {"tool_name": "source_review", "summary": "Source review failed: no requested source files could be read."},
                                "e3": {"tool_name": "script_exec", "summary": "Script execution failed (exit 2): exit code 2, 0 flag candidate(s)."},
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "failed-example",
                "solved": False,
                "status": "failed",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }

            with patch("killchain_docker.batch.runner._load_llm_experiment_config", return_value={"available": False}):
                path = _save_batch_progress(args, [result], time.time() - 5, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["script_missing_code"], 1)
            self.assertEqual(payload["failure_buckets"]["script_nonzero_exit"], 1)
            self.assertEqual(payload["failure_buckets"]["tool_missing_target_files"], 1)
            self.assertEqual(payload["failure_buckets"]["source_target_unresolved"], 1)
            self.assertEqual(payload["failure_buckets"]["candidate_mismatch"], 1)
            self.assertEqual(payload["failure_buckets"]["docker_start_error"], 1)
            self.assertEqual(payload["failure_buckets"]["llm_schema_validation"], 1)
            self.assertIn("script_missing_code", payload["details"][0]["failure_buckets"])

    def test_summary_buckets_unsolved_exhausted_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "completed_unsolved.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "completed",
                        "finish_reason": "completed",
                        "state": {
                            "todos": [{"status": "completed", "assigned_worker": "artifact-worker"}],
                            "rounds": [{"cycle": 1}],
                            "evidence": {},
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "unsolved-example",
                "solved": False,
                "status": "completed",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }

            with patch("killchain_docker.batch.runner._load_llm_experiment_config", return_value={"available": False}):
                path = _save_batch_progress(args, [result], time.time() - 5, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["unsolved_exhausted"], 1)

    def test_summary_counts_partial_and_interrupted_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "interrupted_run.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "interrupted",
                        "finish_reason": "interrupted",
                        "state": {
                            "status": "interrupted",
                            "todos": [
                                {"status": "partial", "assigned_worker": "exploit-worker"},
                                {"status": "interrupted", "assigned_worker": "exploit-worker"},
                            ],
                            "rounds": [{"cycle": 1}],
                            "evidence": {},
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "interrupted-example",
                "solved": False,
                "status": "interrupted",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }

            with patch("killchain_docker.batch.runner._load_llm_experiment_config", return_value={"available": False}):
                path = _save_batch_progress(args, [result], time.time() - 5, finished=True)

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["interrupted_count"], 1)
            self.assertEqual(payload["paper_metrics"]["interrupted"], 1)
            self.assertEqual(payload["paper_metrics"]["partial_todo_count_total"], 1)
            self.assertEqual(payload["paper_metrics"]["interrupted_todo_count_total"], 1)
            self.assertEqual(payload["failure_buckets"]["interrupted"], 1)
            self.assertEqual(payload["failure_buckets"]["partial_no_candidate"], 1)

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
                            "worker_counts": {
                                "artifact-worker": 18,
                                "flag-worker": 5,
                                "web-worker": 50,
                            },
                            "evidence_tool_counts": {"script_exec": 18},
                            "open_todo_count": 4,
                        },
                        "state": {"rounds": []},
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
