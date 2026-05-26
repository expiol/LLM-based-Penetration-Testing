"""Regression tests for batch summary experiment metrics."""

from __future__ import annotations
import argparse
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.batch.runner import (
    _effective_max_cycles,
    _artifact_solved,
    _log_challenge_result,
    _run_single_challenge_inner,
    _save_batch_progress,
    _update_result_counters,
    run_single_challenge_replicas,
)
from killchain_docker.llm.gateway import TokenLedger
from killchain_docker.runtime.config import RunArtifacts, RunConfig
from killchain_docker.runtime.session import run_assessment
from killchain_docker.score import diagnose_logdir
from killchain_docker.state.run_state import RunState, RunStatus


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
        auto_max_cycles=False,
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


class _UnmarkedRuntimeErrorOrchestrator:
    def __init__(self, state: RunState) -> None:
        self.state = state
        self.checkpoint_callback = None

    def run(self, max_cycles: int) -> None:
        del max_cycles
        raise RuntimeError("router crashed before finalizing state")


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
                "rag": {"mode": "strict", "status": "hit"},
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
    events_path.write_text(
        "[token usage] calls=1 prompt=7 completion=2 total=9\n", encoding="utf-8"
    )
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
    def test_artifact_solved_ignores_rag_hint_literals(self) -> None:
        state_payload = {
            "solved": False,
            "metadata": {
                "rag": {
                    "knowledge_hints": [
                        {"solution_sketch": "This text may contain flag{fake}."}
                    ]
                }
            },
        }
        self.assertFalse(
            _artifact_solved(None, state_payload, expected_flag="flag{fake}")
        )

    def test_artifact_solved_accepts_validated_flag_without_summary(self) -> None:
        self.assertTrue(
            _artifact_solved(
                None,
                {"solved": False, "validated_flag": "flag{fake}"},
                expected_flag="flag{fake}",
            )
        )

    def test_effective_max_cycles_respects_explicit_limit_by_default(self) -> None:
        args = _args(Path("/tmp/logs"))
        args.max_cycles = 8
        challenge = SimpleNamespace(
            files=["capture.pcap"],
            server_name="target",
            port=31337,
            challenge={"port": 31337},
        )
        self.assertEqual(
            _effective_max_cycles(args, challenge, ["tcp://target:31337"]), 8
        )

    def test_effective_max_cycles_scales_only_when_auto_enabled(self) -> None:
        args = _args(Path("/tmp/logs"))
        args.max_cycles = 8
        args.auto_max_cycles = True
        challenge = SimpleNamespace(
            files=["capture.pcap"],
            server_name="target",
            port=31337,
            challenge={"port": 31337},
        )
        self.assertEqual(
            _effective_max_cycles(args, challenge, ["tcp://target:31337"]), 16
        )

    def test_single_challenge_interrupt_writes_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.name = None
            logfile = Path(tmp) / "fake-interrupt.json"
            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _FakeEnvironment),
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env",
                    side_effect=KeyboardInterrupt(),
                ),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)
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
                    side_effect=LLMClientError(
                        "preflight connection failed", transient=True
                    ),
                ),
            ):
                with self.assertLogs(
                    "killchain_docker.batch.runner", level="ERROR"
                ) as captured:
                    result = _run_single_challenge_inner(
                        args, _FakeChallenge(), logfile
                    )
            payload = json.loads(logfile.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["api_error"])
            self.assertTrue(result["llm_error"])
            self.assertEqual(payload["error"]["type"], "LLMClientError")
            self.assertTrue(payload["llm_error"])
            status_payload = json.loads(
                (Path(tmp) / "fake-llm-error.status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(status_payload["error"]["type"], "LLMClientError")
            self.assertTrue(status_payload["api_error"])
            self.assertTrue(status_payload["llm_error"])
            self.assertTrue(
                any(
                    (
                        "single challenge run failed" in message
                        for message in captured.output
                    )
                )
            )
            self.assertTrue(
                any(("Traceback" in message for message in captured.output))
            )

    def test_pre_assessment_failure_preserves_preflight_token_usage_and_status_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            args.name = None
            logfile = root / "fake-docker-error.json"
            ledger = TokenLedger()
            ledger.record(10, 3)
            llm_client = SimpleNamespace(token_ledger=ledger)
            exc = subprocess.CalledProcessError(
                returncode=1,
                cmd=["docker", "compose", "up"],
                stderr="port is already allocated",
            )
            with (
                patch("killchain_docker.batch.runner.CTFEnvironment", _FakeEnvironment),
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env",
                    return_value=llm_client,
                ),
                patch(
                    "killchain_docker.batch.runner.start_challenge_with_retry",
                    side_effect=exc,
                ),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)
            status_payload = json.loads(
                (root / "fake-docker-error.status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["error"]["type"], "CalledProcessError")
            self.assertEqual(result["token_usage"]["total_tokens"], 13)
            self.assertEqual(status_payload["error"]["type"], "CalledProcessError")
            self.assertEqual(status_payload["token_usage"]["total_tokens"], 13)

    def test_oracle_preflight_skips_metadata_only_context_before_llm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            args.name = None
            args.rag_mode = "oracle"
            logfile = root / "fake-oracle-skip.json"
            with (
                patch(
                    "killchain_docker.batch.runner.oracle_context_status",
                    return_value={
                        "mode": "oracle",
                        "enabled": True,
                        "status": "metadata_only",
                        "policy": "supplemental_context",
                        "hint_count": 0,
                    },
                ),
                patch("killchain_docker.batch.runner.CTFEnvironment") as environment,
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env"
                ) as build_llm,
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)
            payload = json.loads(logfile.read_text(encoding="utf-8"))
            status = json.loads(
                (root / "fake-oracle-skip.status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(result["skip_reason"], "rag_oracle_unavailable")
            self.assertEqual(result["rag"]["status"], "metadata_only")
            self.assertEqual(result["rag"]["hint_count"], 0)
            self.assertEqual(payload["status"], "skipped")
            self.assertEqual(status["stage"], "rag_preflight")
            self.assertEqual(status["rag"]["status"], "metadata_only")
            environment.assert_not_called()
            build_llm.assert_not_called()

    def test_run_assessment_attaches_artifacts_to_runtime_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(objective="fake objective", authorized_scope=[])
            orchestrator = _RaisingOrchestrator(state)
            ledger = TokenLedger()
            ledger.record(11, 4)
            client = SimpleNamespace(token_ledger=ledger)
            status_path = Path(tmp) / "runtime.status.json"
            config = RunConfig(
                objective="fake objective",
                authorized_scope=[],
                output_root=tmp,
                quiet=True,
                status_path=str(status_path),
            )
            with patch(
                "killchain_docker.runtime.session.build_runtime",
                return_value=(state, orchestrator, client),
            ):
                with self.assertLogs(
                    "killchain_docker.runtime.session", level="ERROR"
                ) as captured:
                    with self.assertRaises(LLMClientError) as ctx:
                        run_assessment(config)
            artifacts = getattr(ctx.exception, "run_artifacts", None)
            self.assertIsInstance(artifacts, RunArtifacts)
            assert isinstance(artifacts, RunArtifacts)
            self.assertEqual(artifacts.status, "failed")
            self.assertTrue(
                any(
                    (
                        "run failed; finalizing artifacts" in message
                        for message in captured.output
                    )
                )
            )
            self.assertTrue(
                any(("Traceback" in message for message in captured.output))
            )
            summary = json.loads(
                Path(artifacts.summary_path).read_text(encoding="utf-8")
            )
            self.assertEqual(summary["token_usage"]["total_tokens"], 15)
            events = [
                json.loads(line)
                for line in Path(artifacts.events_path)
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            ]
            token_events = [
                event for event in events if event.get("event_type") == "token_usage"
            ]
            self.assertEqual(len(token_events), 1)
            self.assertEqual(token_events[0]["context"]["llm_calls"], 1)
            self.assertEqual(token_events[0]["context"]["prompt_tokens"], 11)
            self.assertEqual(token_events[0]["context"]["completion_tokens"], 4)
            self.assertEqual(token_events[0]["context"]["total_tokens"], 15)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["run_id"], state.run_id)
            self.assertEqual(status["stage"], "complete")

    def test_run_assessment_marks_unfinalized_runtime_errors_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = RunState(objective="fake objective", authorized_scope=[])
            orchestrator = _UnmarkedRuntimeErrorOrchestrator(state)
            client = SimpleNamespace(token_ledger=TokenLedger())
            status_path = Path(tmp) / "runtime.status.json"
            config = RunConfig(
                objective="fake objective",
                authorized_scope=[],
                output_root=tmp,
                quiet=True,
                status_path=str(status_path),
            )
            with patch(
                "killchain_docker.runtime.session.build_runtime",
                return_value=(state, orchestrator, client),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    run_assessment(config)
            artifacts = getattr(ctx.exception, "run_artifacts", None)
            self.assertIsInstance(artifacts, RunArtifacts)
            assert isinstance(artifacts, RunArtifacts)
            self.assertEqual(artifacts.status, "failed")
            summary = json.loads(
                Path(artifacts.summary_path).read_text(encoding="utf-8")
            )
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(summary["stop_reason"], "runtime_error")
            self.assertEqual(summary["runtime_error"]["type"], "RuntimeError")
            report = Path(artifacts.report_path).read_text(encoding="utf-8")
            self.assertIn("Runtime Error", report)
            self.assertIn("router crashed before finalizing state", report)
            state_payload = json.loads(
                Path(artifacts.state_path).read_text(encoding="utf-8")
            )
            self.assertEqual(state_payload["status"], "failed")
            self.assertEqual(state_payload["stop_reason"], "runtime_error")
            self.assertEqual(
                state_payload["metadata"]["runtime_error"]["type"], "RuntimeError"
            )
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "failed")
            self.assertEqual(status["stop_reason"], "runtime_error")
            self.assertEqual(status["runtime_error"]["type"], "RuntimeError")

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
                patch(
                    "killchain_docker.batch.runner.CTFEnvironment",
                    _StartedFakeEnvironment,
                ),
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env",
                    return_value=object(),
                ),
                patch("killchain_docker.batch.runner.start_challenge_with_retry"),
                patch(
                    "killchain_docker.batch.runner.build_execution_plane",
                    return_value=object(),
                ),
                patch("killchain_docker.batch.runner.run_assessment", side_effect=exc),
            ):
                result = _run_single_challenge_inner(args, _FakeChallenge(), logfile)
            payload = json.loads(logfile.read_text(encoding="utf-8"))
            self.assertEqual(result["run_id"], "run-attached")
            self.assertFalse(result["api_error"])
            self.assertTrue(result["llm_error"])
            self.assertEqual(result["token_usage"]["total_tokens"], 9)
            self.assertEqual(payload["artifacts"]["run_id"], "run-attached")
            self.assertFalse(payload["api_error"])
            self.assertTrue(payload["llm_error"])
            self.assertEqual(payload["state_metrics"]["todo_count"], 1)
            self.assertEqual(payload["rag"]["mode"], "strict")
            self.assertEqual(result["rag"]["policy"], "filtered_context")
            self.assertNotIn("mode", result["rag"])
            status_payload = json.loads(
                (root / "fake-attached-artifacts.status.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(status_payload["api_error"])
            self.assertTrue(status_payload["llm_error"])
            self.assertEqual(status_payload["rag"]["policy"], "filtered_context")
            self.assertEqual(status_payload["token_usage"]["total_tokens"], 9)
            self.assertNotIn("mode", status_payload["rag"])

    def test_single_challenge_docker_execution_plane_keeps_stdin_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            args.name = None
            logfile = root / "fake-success.json"
            artifacts = _write_artifacts(root, status="completed")
            with (
                patch(
                    "killchain_docker.batch.runner.CTFEnvironment",
                    _StartedFakeEnvironment,
                ),
                patch(
                    "killchain_docker.batch.runner.build_llm_client_from_env",
                    return_value=object(),
                ),
                patch("killchain_docker.batch.runner.start_challenge_with_retry"),
                patch(
                    "killchain_docker.batch.runner.build_execution_plane",
                    return_value=object(),
                ) as build_plane,
                patch(
                    "killchain_docker.batch.runner.run_assessment",
                    return_value=artifacts,
                ),
            ):
                _run_single_challenge_inner(args, _FakeChallenge(), logfile)
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
                patch(
                    "killchain_docker.batch.runner.load_challenge",
                    return_value=_FakeChallenge(),
                ),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    return_value={
                        "challenge": "fake-interrupt",
                        "status": "interrupted",
                        "solved": False,
                        "error": {
                            "type": "KeyboardInterrupt",
                            "message": "Run interrupted",
                        },
                        "logfile": str(Path(tmp) / "fake-interrupt.json"),
                    },
                ),
            ):
                rc = run_single_challenge_replicas(args)
            self.assertEqual(rc, 130)
            monitor_path = Path(tmp) / "paper_run" / "_batch_monitor.html"
            snapshot_path = Path(tmp) / "paper_run" / "_batch_monitor.json"
            summary_path = Path(tmp) / "paper_run" / "_batch_summary.json"
            self.assertTrue(monitor_path.exists())
            self.assertTrue(summary_path.exists())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["total_attempted"], 1)
            self.assertEqual(summary["evaluated_count"], 0)
            self.assertEqual(summary["failed_count"], 0)
            self.assertEqual(summary["interrupted_count"], 1)
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertTrue(snapshot["finished"])
            self.assertEqual(snapshot["entries"][0]["challenge"], "fake-interrupt")

    def test_single_replica_unsolved_result_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.run_all = False
            args.challenge = "fake-unsolved"
            args.replicas = 1
            with (
                patch(
                    "killchain_docker.batch.runner.load_challenge",
                    return_value=_FakeChallenge(),
                ),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    return_value={
                        "challenge": "fake-unsolved",
                        "status": "failed",
                        "solved": False,
                        "error": None,
                        "logfile": str(Path(tmp) / "fake-unsolved.json"),
                    },
                ),
            ):
                rc = run_single_challenge_replicas(args)
            self.assertEqual(rc, 1)

    def test_summary_includes_token_usage_and_paper_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.rag_mode = "strict"
            result = {
                "challenge": "2013f-cry-example",
                "run_id": "run-direct",
                "solved": True,
                "status": "solved",
                "rag_mode": "strict",
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
                "runtime_error": {
                    "type": "RuntimeError",
                    "message": "final status retained for monitor",
                },
            }
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": True, "default_model": "test-model"},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 10, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 2)
            self.assertEqual(payload["evaluated_count"], 1)
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 130)
            self.assertEqual(
                payload["token_usage"]["mean_per_attempt"]["prompt_tokens"], 100.0
            )
            self.assertEqual(payload["paper_metrics"]["success_rate"], 1.0)
            self.assertEqual(payload["paper_metrics"]["todo_count_total"], 4)
            self.assertEqual(
                payload["paper_metrics"]["worker_totals"]["artifact-worker"], 1
            )
            self.assertEqual(
                payload["paper_metrics"]["evidence_tool_totals"]["script_exec"], 1
            )
            self.assertEqual(payload["paper_metrics"]["category_counts"]["crypto"], 1)
            self.assertEqual(payload["experiment_config"]["max_cycles_arg"], 20)
            self.assertEqual(payload["experiment_config"]["parallel_workers"], 2)
            self.assertEqual(payload["experiment_config"]["rag_mode"], "strict")
            self.assertEqual(
                payload["experiment_config"]["llm_gateway"]["default_model"],
                "test-model",
            )
            detail = payload["details"][0]
            self.assertEqual(detail["run_id"], "run-direct")
            self.assertEqual(detail["rag_mode"], "strict")
            self.assertEqual(detail["files_count"], 2)
            self.assertTrue(detail["has_server"])
            self.assertEqual(detail["authorized_scope_count"], 1)
            self.assertEqual(detail["runtime_error"]["type"], "RuntimeError")
            monitor = json.loads(
                (Path(tmp) / "paper_run" / "_batch_monitor.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                monitor["entries"][0]["result"]["runtime_error"]["message"],
                "final status retained for monitor",
            )

    def test_summary_and_monitor_preserve_skip_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            result = {
                "challenge": "metadata-only-sample",
                "solved": False,
                "status": "skipped",
                "skip_reason": "rag_oracle_unavailable",
                "runtime_sec": 0.01,
                "rag_mode": "oracle",
                "rag": {
                    "enabled": True,
                    "status": "metadata_only",
                    "policy": "supplemental_context",
                    "hint_count": 0,
                },
                "token_usage": {
                    "llm_calls": 0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
            }
            path = _save_batch_progress(
                args,
                [result],
                time.time(),
                finished=True,
                challenge_names=["metadata-only-sample"],
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            monitor = json.loads(
                (Path(tmp) / "paper_run" / "_batch_monitor.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                payload["details"][0]["skip_reason"], "rag_oracle_unavailable"
            )
            self.assertEqual(
                monitor["entries"][0]["result"]["skip_reason"], "rag_oracle_unavailable"
            )

    def test_success_rate_excludes_skipped_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            results = [
                {"challenge": "solved", "solved": True, "status": "solved"},
                {
                    "challenge": "metadata-only",
                    "solved": False,
                    "status": "skipped",
                    "skip_reason": "rag_oracle_unavailable",
                },
            ]
            path = _save_batch_progress(
                args,
                results,
                time.time(),
                finished=True,
                challenge_names=["solved", "metadata-only"],
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_attempted"], 2)
            self.assertEqual(payload["evaluated_count"], 1)
            self.assertEqual(payload["skipped_count"], 1)
            self.assertEqual(payload["success_rate"], 1.0)
            self.assertEqual(payload["paper_metrics"]["attempted"], 1)
            self.assertEqual(payload["paper_metrics"]["total_attempted"], 2)

    def test_summary_separates_interrupted_from_failed_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            results = [
                {"challenge": "solved", "solved": True, "status": "solved"},
                {"challenge": "failed", "solved": False, "status": "failed"},
                {"challenge": "cancelled", "solved": False, "status": "interrupted"},
            ]
            path = _save_batch_progress(
                args,
                results,
                time.time(),
                finished=True,
                challenge_names=["solved", "failed", "cancelled"],
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_attempted"], 3)
            self.assertEqual(payload["evaluated_count"], 2)
            self.assertEqual(payload["failed_count"], 1)
            self.assertEqual(payload["interrupted_count"], 1)
            self.assertEqual(payload["success_rate"], 0.5)
            self.assertEqual(payload["failed_challenges"], ["failed"])
            self.assertEqual(payload["interrupted_challenges"], ["cancelled"])

    def test_running_counters_do_not_count_interrupted_as_failed(self) -> None:
        self.assertEqual(
            _update_result_counters(
                {"challenge": "cancelled", "solved": False, "status": "interrupted"},
                0,
                0,
                0,
            ),
            (0, 0, 0),
        )

    def test_interrupted_parallel_result_is_not_logged_as_failure(self) -> None:
        with self.assertLogs(
            "killchain_docker.batch.runner", level="WARNING"
        ) as captured:
            _log_challenge_result(
                "cancelled",
                {
                    "challenge": "cancelled",
                    "solved": False,
                    "status": "interrupted",
                    "error": {
                        "type": "KeyboardInterrupt",
                        "message": "Run interrupted",
                    },
                },
            )
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.levelname, "WARNING")
        self.assertEqual(record.getMessage(), "challenge interrupted")
        self.assertEqual(record.challenge, "cancelled")

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
                                {
                                    "status": "completed",
                                    "assigned_worker": "recon-worker",
                                },
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
                path = _save_batch_progress(
                    args, [result], time.time() - 60, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["token_usage"]["total"]["total_tokens"], 255)
            self.assertEqual(
                payload["paper_metrics"]["token_usage_mean_failed"]["llm_calls"], 3.0
            )
            self.assertEqual(payload["paper_metrics"]["open_todo_count_total"], 1)
            self.assertEqual(
                payload["paper_metrics"]["todo_status_totals"]["pending"], 1
            )
            self.assertEqual(payload["paper_metrics"]["worker_totals"]["web-worker"], 1)
            self.assertEqual(
                payload["paper_metrics"]["evidence_tool_totals"]["http_form_probe"], 1
            )
            detail = payload["details"][0]
            self.assertEqual(detail["run_id"], "run-from-log")
            self.assertEqual(detail["category"], "web")
            self.assertEqual(detail["server_type"], "web")
            self.assertEqual(detail["max_cycles"], 16)
            self.assertEqual(detail["state_metrics"]["asset_count"], 1)
            self.assertEqual(detail["state_metrics"]["execution_count"], 1)
            self.assertEqual(detail["state_metrics"]["round_count"], 1)

    def test_summary_and_monitor_preserve_threads_from_status_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            logdir = root / "paper_run"
            logdir.mkdir()
            status_path = logdir / "threaded-example.status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "challenge": "threaded-example",
                        "stage": "complete",
                        "status": "failed",
                        "threads": {
                            "observed": {"id": 101, "name": "worker-thread"},
                            "status_writer": {"id": 202, "name": "main-thread"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "threaded-example",
                "solved": False,
                "status": "failed",
                "runtime_sec": 3,
                "status_file": str(status_path),
            }
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            threads = payload["details"][0]["threads"]
            self.assertEqual(threads["observed"]["id"], 101)
            self.assertEqual(threads["status_writer"]["name"], "main-thread")
            monitor = json.loads(
                (logdir / "_batch_monitor.json").read_text(encoding="utf-8")
            )
            monitor_threads = monitor["entries"][0]["result"]["threads"]
            self.assertEqual(monitor_threads["observed"]["name"], "worker-thread")

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
                            "stop_reason": "router_no_assignments",
                            "metadata": {
                                "runtime_error": {
                                    "type": "RuntimeError",
                                    "message": "router crashed before finalizing state",
                                },
                                "last_llm_error": {
                                    "kind": "schema_validation",
                                    "schema_name": "ToolUseDecision",
                                },
                            },
                            "todos": [
                                {"status": "failed", "error": "candidate mismatch"},
                                {
                                    "status": "failed",
                                    "error": "script.execute missing required metadata.script_code",
                                },
                            ],
                            "evidence": {
                                "e1": {
                                    "tool_name": "pcap_review",
                                    "summary": "PCAP review completed for 0 file(s): 0 URL(s)",
                                },
                                "e2": {
                                    "tool_name": "source_review",
                                    "summary": "Source review failed: no requested source files could be read.",
                                },
                                "e3": {
                                    "tool_name": "script_exec",
                                    "summary": "Script execution failed (exit 2): exit code 2, 0 flag candidate(s).",
                                },
                                "e4": {
                                    "tool_name": "script_exec",
                                    "summary": "script failed: timeout",
                                    "extracted": {
                                        "output_context": {
                                            "failure_kind": "timeout",
                                            "failure_detail": "script exceeded its execution or socket timeout",
                                        }
                                    },
                                },
                                "e5": {
                                    "tool_name": "shell_exec",
                                    "summary": "shell failed (exit 126): apt-get install -y qemu-user-static",
                                    "extracted": {
                                        "output_context": {
                                            "failure_kind": "package_install_blocked",
                                            "failure_detail": "use installed tools or pivot",
                                        }
                                    },
                                },
                                "e6": {
                                    "tool_name": "script_exec",
                                    "summary": "script failed: [-] Only completed 0 rounds",
                                    "extracted": {
                                        "output_context": {
                                            "failure_kind": "connection_refused",
                                            "failure_detail": "remote endpoint refused the connection",
                                        }
                                    },
                                },
                                "e7": {
                                    "tool_name": "tshark",
                                    "summary": "tshark capture.pcap: 0 packet(s) [filter: tcp]",
                                    "extracted": {
                                        "output_context": {
                                            "failure_kind": "empty_result",
                                            "result_quality": "empty_result",
                                        }
                                    },
                                },
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
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["script_missing_code"], 1)
            self.assertEqual(payload["failure_buckets"]["script_nonzero_exit"], 1)
            self.assertEqual(payload["failure_buckets"]["tool_missing_target_files"], 1)
            self.assertEqual(payload["failure_buckets"]["source_target_unresolved"], 1)
            self.assertEqual(payload["failure_buckets"]["candidate_mismatch"], 1)
            self.assertEqual(payload["failure_buckets"]["docker_start_error"], 1)
            self.assertEqual(payload["failure_buckets"]["llm_schema_validation"], 1)
            self.assertEqual(payload["failure_buckets"]["script_timeout"], 1)
            self.assertEqual(payload["failure_buckets"]["package_install_blocked"], 1)
            self.assertEqual(
                payload["failure_buckets"]["network_interaction_failed"], 1
            )
            self.assertEqual(payload["failure_buckets"]["router_no_assignments"], 1)
            self.assertEqual(payload["failure_buckets"]["empty_tool_result"], 1)
            self.assertEqual(payload["failure_buckets"]["runtime_error"], 1)
            self.assertIn(
                "script_missing_code", payload["details"][0]["failure_buckets"]
            )
            self.assertIn("runtime_error", payload["details"][0]["failure_buckets"])

    def test_summary_ignores_policy_rejections_that_are_expected_filtering(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "filtered_candidate.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "failed",
                        "state": {
                            "orchestration_notes": [
                                "Rejected flag candidate from script: bare_token_for_prefix_challenge"
                            ],
                            "rejected_flag_candidates": [
                                {
                                    "value": "CHANGELOG.md",
                                    "reason": "bare_token_for_prefix_challenge",
                                    "source": "script",
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "filtered-candidate",
                "solved": False,
                "status": "failed",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("candidate_rejected", payload["failure_buckets"])
            self.assertNotIn("candidate_mismatch", payload["failure_buckets"])
            self.assertEqual(payload["details"][0]["failure_buckets"], [])

    def test_summary_uses_structured_event_types_for_failure_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            events_path = root / "artifacts" / "failed-event" / "run-1" / "events.log"
            events_path.parent.mkdir(parents=True)
            events_path.write_text(
                "\n".join(
                    [
                        "legacy token usage line",
                        json.dumps(
                            {
                                "event_type": "llm_transient_error",
                                "message": "retryable gateway failure",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            log_path = root / "failed_event.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "failed",
                        "artifacts": {"events_path": str(events_path)},
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "failed-event",
                "solved": False,
                "status": "failed",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["llm_transient_error"], 1)
            self.assertIn(
                "llm_transient_error", payload["details"][0]["failure_buckets"]
            )

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
                            "todos": [
                                {
                                    "status": "completed",
                                    "assigned_worker": "artifact-worker",
                                }
                            ],
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
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["unsolved_exhausted"], 1)

    def test_script_no_candidate_evidence_does_not_imply_partial_todo_bucket(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root)
            log_path = root / "completed_no_candidate_evidence.json"
            log_path.write_text(
                json.dumps(
                    {
                        "solved": False,
                        "status": "completed",
                        "finish_reason": "completed",
                        "state": {
                            "todos": [
                                {
                                    "status": "completed",
                                    "assigned_worker": "artifact-worker",
                                }
                            ],
                            "rounds": [{"cycle": 1}],
                            "evidence": {
                                "e1": {
                                    "tool_name": "script_exec",
                                    "summary": "script (python)",
                                    "extracted": {
                                        "output_context": {
                                            "result_quality": "partial_no_candidate",
                                            "failure_kind": "no_candidate",
                                        }
                                    },
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = {
                "challenge": "no-partial-todo-example",
                "solved": False,
                "status": "completed",
                "runtime_sec": 3,
                "logfile": str(log_path),
            }
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["failure_buckets"]["unsolved_exhausted"], 1)
            self.assertNotIn("partial_no_candidate", payload["failure_buckets"])

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
                                {
                                    "status": "partial",
                                    "assigned_worker": "exploit-worker",
                                },
                                {
                                    "status": "interrupted",
                                    "assigned_worker": "exploit-worker",
                                },
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
            with patch(
                "killchain_docker.batch.runner._load_llm_experiment_config",
                return_value={"available": False},
            ):
                path = _save_batch_progress(
                    args, [result], time.time() - 5, finished=True
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["interrupted_count"], 1)
            self.assertEqual(payload["paper_metrics"]["interrupted"], 1)
            self.assertEqual(payload["paper_metrics"]["partial_todo_count_total"], 1)
            self.assertEqual(
                payload["paper_metrics"]["interrupted_todo_count_total"], 1
            )
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
