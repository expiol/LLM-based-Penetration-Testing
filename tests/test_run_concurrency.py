"""Concurrency guard tests for the NYUCTF runner."""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.batch.runner import (
    _BatchMonitorHeartbeat,
    _active_run_entry,
    _challenge_timeout_payload,
    _prioritize_resume_challenge_names,
    _run_single_challenge_supervised,
    _selected_challenge_names,
    run_all_challenges,
    run_single_challenge,
    run_single_challenge_replicas,
)


class _DummyChallenge:
    canonical_name = "dummy-compose"


class _FakeDataset:
    basedir = "/tmp"

    def all(self) -> dict[str, dict[str, str]]:
        return {"alpha": {"name": "alpha"}, "beta": {"name": "beta"}}

    def get(self, name: str) -> dict[str, str]:
        return {"name": name, "category": "crypto"}


class _FakeComposeDataset:
    def __init__(self, basedir: str = "/tmp") -> None:
        self.basedir = basedir

    def all(self) -> dict[str, dict[str, object]]:
        return {
            "compose-a": {"name": "compose-a", "path": "compose-a"},
            "compose-b": {"name": "compose-b", "path": "compose-b"},
            "plain-a": {"name": "plain-a", "path": "plain-a"},
            "plain-b": {"name": "plain-b", "path": "plain-b"},
        }

    def get(self, name: str) -> dict[str, object]:
        return dict(self.all()[name], category="crypto")


def _args(logdir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        challenge="__all__",
        challenges=None,
        run_all=True,
        category=None,
        dataset=None,
        split="development",
        container_image="ctfenv:latest",
        container_network="ctfnet",
        objective=None,
        scope=None,
        max_cycles=8,
        quiet=True,
        debug=False,
        logdir=str(logdir),
        name=None,
        index=None,
        output_root=None,
        skip_exist=False,
        parallel_workers=1,
        replicas=1,
        knowledge_mode=None,
    )


class RunConcurrencyTests(unittest.TestCase):
    def test_selected_challenge_names_preserves_requested_order_and_dedupes(
        self,
    ) -> None:
        args = _args(Path("/tmp/logs"))
        args.challenges = ["beta", "alpha", "beta"]

        selected, category = _selected_challenge_names(_FakeDataset(), args)

        self.assertEqual(selected, ["beta", "alpha"])
        self.assertIsNone(category)

    def test_selected_challenge_names_rejects_unknown_subset_member(self) -> None:
        args = _args(Path("/tmp/logs"))
        args.challenges = ["missing"]

        with self.assertRaisesRegex(ValueError, "Unknown challenge"):
            _selected_challenge_names(_FakeDataset(), args)

    def test_active_run_entry_exposes_scheduler_thread(self) -> None:
        entry = _active_run_entry("alpha", 1)

        self.assertEqual(entry["challenge"], "alpha")
        self.assertEqual(entry["status"], "active")
        self.assertEqual(entry["stage"], "scheduled")
        self.assertNotIn("pid", entry)
        self.assertNotIn("thread_id", entry)
        self.assertNotIn("thread_name", entry)
        self.assertIsInstance(entry["scheduler_pid"], int)
        self.assertIsInstance(entry["scheduler_thread_id"], int)
        self.assertIsInstance(entry["scheduler_thread_name"], str)
        self.assertEqual(
            entry["threads"]["scheduler"]["id"], entry["scheduler_thread_id"]
        )
        self.assertEqual(entry["threads"]["registry"][0]["challenge"], "alpha")
        self.assertEqual(entry["threads"]["registry"][0]["roles"], ["scheduler"])

    def test_batch_monitor_heartbeat_writes_current_snapshot(self) -> None:
        calls = 0

        def write_snapshot() -> None:
            nonlocal calls
            calls += 1

        heartbeat = _BatchMonitorHeartbeat(write_snapshot)
        heartbeat.write_once()
        heartbeat.write_once()

        self.assertEqual(calls, 2)

    def test_single_challenge_enters_compose_lock_before_inner_run(self) -> None:
        events: list[str] = []

        @contextmanager
        def fake_lock(challenge):
            events.append(f"enter:{challenge.canonical_name}")
            yield
            events.append(f"exit:{challenge.canonical_name}")

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch(
                    "killchain_docker.batch.runner.compose_challenge_run_lock",
                    fake_lock,
                ),
                patch(
                    "killchain_docker.batch.runner._run_single_challenge_inner",
                    side_effect=lambda *_args: events.append("inner") or {"ok": True},
                ) as inner,
            ):
                result = run_single_challenge(_args(Path(tmp)), _DummyChallenge())

        self.assertEqual(result, {"ok": True})
        self.assertEqual(events, ["enter:dummy-compose", "inner", "exit:dummy-compose"])
        self.assertEqual(inner.call_count, 1)

    def test_single_challenge_reuses_terminal_existing_log(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "unsolved_exhausted",
                        "solved": False,
                        "effective_max_cycles": 8,
                        "state_metrics": {
                            "todo_count": 1,
                            "open_todo_count": 0,
                        },
                        "token_usage": {
                            "llm_calls": 2,
                            "prompt_tokens": 11,
                            "completion_tokens": 3,
                            "total_tokens": 14,
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "killchain_docker.batch.runner._run_single_challenge_inner"
            ) as inner:
                result = run_single_challenge(args, challenge)

            status = json.loads(
                (Path(tmp) / "dummy-compose.status.json").read_text(encoding="utf-8")
            )

        inner.assert_not_called()
        self.assertTrue(result["resumed_from_existing_log"])
        self.assertEqual(result["status"], "unsolved_exhausted")
        self.assertEqual(result["skip_reason"], "preexisting_log")
        self.assertEqual(result["token_usage"]["total_tokens"], 14)
        self.assertEqual(status["status"], "skipped")
        self.assertEqual(status["original_status"], "unsolved_exhausted")

    def test_single_challenge_reruns_existing_log_over_max_cycles(self) -> None:
        challenge = _DummyChallenge()

        @contextmanager
        def fake_lock(_challenge):
            yield

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "effective_max_cycles": 1,
                        "state": {
                            "rounds": [
                                {
                                    "cycle": 2,
                                    "planner_summary": "normal retry cycle",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "killchain_docker.batch.runner.compose_challenge_run_lock",
                    fake_lock,
                ),
                patch(
                    "killchain_docker.batch.runner._run_single_challenge_inner",
                    return_value={
                        "challenge": "dummy-compose",
                        "status": "rerun",
                    },
                ) as inner,
            ):
                result = run_single_challenge(args, challenge)

        self.assertEqual(result["status"], "rerun")
        inner.assert_called_once()

    def test_single_challenge_reuses_final_closure_over_max_cycle_log(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "effective_max_cycles": 1,
                        "state": {
                            "rounds": [
                                {
                                    "cycle": 2,
                                    "planner_summary": "final flag validation pass",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "killchain_docker.batch.runner._run_single_challenge_inner"
            ) as inner:
                result = run_single_challenge(args, challenge)

        inner.assert_not_called()
        self.assertTrue(result["resumed_from_existing_log"])
        self.assertEqual(result["status"], "failed")

    def test_single_challenge_reuses_unsolved_exhausted_after_followup_cycles(
        self,
    ) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "unsolved_exhausted",
                        "solved": False,
                        "effective_max_cycles": 8,
                        "state_metrics": {
                            "todo_count": 2,
                            "open_todo_count": 0,
                        },
                        "state": {
                            "rounds": [
                                {"cycle": 8, "planner_summary": "bounded run"},
                                {
                                    "cycle": 10,
                                    "planner_summary": "deterministic artifact follow-up",
                                },
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "killchain_docker.batch.runner._run_single_challenge_inner"
            ) as inner:
                result = run_single_challenge(args, challenge)

        inner.assert_not_called()
        self.assertTrue(result["resumed_from_existing_log"])
        self.assertEqual(result["status"], "unsolved_exhausted")

    def test_single_challenge_reuses_failed_llm_limit_after_transient_cycles(
        self,
    ) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "effective_max_cycles": 8,
                        "state_metrics": {
                            "stop_reason": "partial_todos_unsolved",
                            "todo_count": 3,
                            "open_todo_count": 0,
                        },
                        "state": {
                            "rounds": [
                                {"cycle": 8, "planner_summary": "bounded run"},
                                {"cycle": 13, "planner_summary": "transient retry"},
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "killchain_docker.batch.runner._run_single_challenge_inner"
            ) as inner:
                result = run_single_challenge(args, challenge)

        inner.assert_not_called()
        self.assertTrue(result["resumed_from_existing_log"])
        self.assertEqual(result["status"], "failed")

    def test_single_challenge_reruns_transient_llm_error_existing_log(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        @contextmanager
        def fake_lock(_challenge):
            yield

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "state_metrics": {"stop_reason": "llm_transient_error"},
                        "state": {"stop_reason": "llm_transient_error"},
                        "artifacts": {"run_id": "run-transient"},
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "killchain_docker.batch.runner.compose_challenge_run_lock",
                    fake_lock,
                ),
                patch(
                    "killchain_docker.batch.runner._run_single_challenge_inner",
                    return_value={
                        "challenge": "dummy-compose",
                        "status": "rerun",
                    },
                ) as inner,
            ):
                result = run_single_challenge(args, challenge)

        self.assertEqual(result["status"], "rerun")
        inner.assert_called_once()

    def test_resume_queue_prioritizes_missing_and_transient_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            args = _args(logdir)
            args.skip_exist = True
            (logdir / "runtime_error.json").write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "error": {"type": "RuntimeError", "message": "boom"},
                    }
                ),
                encoding="utf-8",
            )
            (logdir / "terminal.json").write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "state_metrics": {"stop_reason": "max_cycles_exhausted"},
                    }
                ),
                encoding="utf-8",
            )
            (logdir / "transient.json").write_text(
                json.dumps(
                    {
                        "status": "failed",
                        "solved": False,
                        "state_metrics": {"stop_reason": "llm_transient_error"},
                    }
                ),
                encoding="utf-8",
            )

            ordered = _prioritize_resume_challenge_names(
                logdir,
                ["terminal", "missing", "transient", "runtime_error"],
                args,
            )

        self.assertEqual(ordered[:3], ["missing", "runtime_error", "transient"])
        self.assertEqual(ordered[-1], "terminal")

    def test_single_challenge_reruns_interrupted_existing_log(self) -> None:
        challenge = _DummyChallenge()

        @contextmanager
        def fake_lock(_challenge):
            yield

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.skip_exist = True
            logfile = Path(tmp) / "dummy-compose.json"
            logfile.write_text(
                json.dumps({"status": "interrupted", "interrupted": True}),
                encoding="utf-8",
            )
            with (
                patch(
                    "killchain_docker.batch.runner.compose_challenge_run_lock",
                    fake_lock,
                ),
                patch(
                    "killchain_docker.batch.runner._run_single_challenge_inner",
                    return_value={"challenge": "dummy-compose", "status": "rerun"},
                ) as inner,
            ):
                result = run_single_challenge(args, challenge)

        self.assertEqual(result["status"], "rerun")
        inner.assert_called_once()

    def test_challenge_timeout_payload_is_terminal_and_resumable(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            logfile = Path(tmp) / "dummy-compose.json"
            status_file = Path(tmp) / "dummy-compose.status.json"
            result = _challenge_timeout_payload(
                args,
                challenge,
                logfile=logfile,
                status_file=status_file,
                started_at=0.0,
                timeout_s=10,
                worker_pid=12345,
            )
            args.skip_exist = True
            with patch(
                "killchain_docker.batch.runner._run_single_challenge_inner"
            ) as inner:
                result = run_single_challenge(args, challenge)
            status = json.loads(status_file.read_text(encoding="utf-8"))

        inner.assert_not_called()
        self.assertEqual(result["challenge"], "dummy-compose")
        self.assertEqual(result["status"], "challenge_timeout")
        self.assertEqual(status["status"], "skipped")
        self.assertEqual(status["original_status"], "challenge_timeout")

    def test_challenge_timeout_payload_recovers_partial_run_artifacts(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            logfile = Path(tmp) / "dummy-compose.json"
            status_file = Path(tmp) / "dummy-compose.status.json"
            run_dir = Path(tmp) / "artifacts" / "dummy-compose" / "run-timeout123"
            run_dir.mkdir(parents=True)
            (run_dir / "state.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-timeout123",
                        "status": "running",
                        "stop_reason": None,
                        "todos": [
                            {
                                "todo_id": "todo-1",
                                "status": "running",
                                "assigned_worker": "exploit-worker",
                            }
                        ],
                        "rounds": [{"cycle": 1}],
                        "evidence": {},
                        "execution_log": [],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-timeout123",
                        "status": "running",
                        "token_usage": {
                            "llm_calls": 3,
                            "prompt_tokens": 10,
                            "completion_tokens": 2,
                            "total_tokens": 12,
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = _challenge_timeout_payload(
                args,
                challenge,
                logfile=logfile,
                status_file=status_file,
                started_at=0.0,
                timeout_s=10,
                worker_pid=12345,
            )
            log_payload = json.loads(logfile.read_text(encoding="utf-8"))
            status = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertEqual(result["run_id"], "run-timeout123")
        self.assertEqual(result["artifacts"]["run_id"], "run-timeout123")
        self.assertEqual(log_payload["artifacts"]["run_id"], "run-timeout123")
        self.assertEqual(log_payload["state"]["run_id"], "run-timeout123")
        self.assertEqual(log_payload["state"]["status"], "failed")
        self.assertEqual(log_payload["state"]["stop_reason"], "challenge_timeout")
        self.assertEqual(
            log_payload["state"]["metadata"]["runtime_error"]["kind"],
            "challenge_timeout",
        )
        self.assertEqual(log_payload["token_usage"]["total_tokens"], 12)
        self.assertEqual(
            log_payload["state_metrics"]["stop_reason"], "challenge_timeout"
        )
        self.assertEqual(status["artifacts"]["run_id"], "run-timeout123")

    def test_supervised_challenge_reads_queue_before_worker_exit(self) -> None:
        challenge = _DummyChallenge()
        challenge.name = "dummy"
        challenge.category = "crypto"
        challenge.description = "dummy"
        challenge.flag = "flag{dummy}"
        challenge.flag_format = "flag{...}"
        challenge.files = []
        challenge.server_name = ""
        challenge.port = None
        challenge.server_type = None
        challenge.server_description = None
        challenge.challenge = {"name": "dummy", "category": "crypto"}
        challenge.challenge_info = {"name": "dummy", "category": "crypto"}

        class FakeQueue:
            def __init__(self, maxsize: int = 1) -> None:
                del maxsize
                self.calls = 0

            def get(self, timeout=None):
                del timeout
                self.calls += 1
                return {"challenge": "dummy-compose", "status": "done"}

            def get_nowait(self):
                return {"challenge": "dummy-compose", "status": "late"}

        class FakeProcess:
            def __init__(self, **_kwargs) -> None:
                self.pid = 123
                self.exitcode = None
                self.terminated = False
                self.killed = False

            def start(self) -> None:
                return None

            def is_alive(self) -> bool:
                return not self.terminated and not self.killed

            def join(self, _timeout=None) -> None:
                return None

            def terminate(self) -> None:
                self.terminated = True
                self.exitcode = -15

            def kill(self) -> None:
                self.killed = True
                self.exitcode = -9

        class FakeContext:
            Queue = FakeQueue
            Process = FakeProcess

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            logfile = Path(tmp) / "dummy-compose.json"
            with patch(
                "killchain_docker.batch.runner.multiprocessing.get_context",
                return_value=FakeContext(),
            ):
                result = _run_single_challenge_supervised(
                    args, challenge, logfile, timeout_s=10
                )

        self.assertEqual(result["status"], "done")

    def test_run_all_uses_process_pool_when_parallel_workers_gt_one(self) -> None:
        submissions: list[tuple[str, str]] = []
        observed_workers: list[int] = []
        active_snapshots: list[list[str]] = []

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                observed_workers.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, fn, _base_args, name: str):
                submissions.append((fn.__name__, name))
                future: futures.Future[dict[str, object]] = futures.Future()
                future.set_result(
                    {
                        "challenge": name,
                        "solved": name == "alpha",
                        "status": "solved" if name == "alpha" else "failed",
                        "api_error": False,
                        "llm_error": False,
                    }
                )
                return future

        def fake_write_batch_monitor(**kwargs):
            active_snapshots.append(
                [item["challenge"] for item in kwargs.get("active_runs") or []]
            )
            return Path(kwargs["logdir"]) / "_batch_monitor.html"

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.parallel_workers = 2
            with (
                patch(
                    "killchain_docker.batch.runner.load_dataset",
                    return_value=_FakeDataset(),
                ),
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor",
                    FakeExecutor,
                ),
                patch(
                    "killchain_docker.batch.runner.write_batch_monitor",
                    fake_write_batch_monitor,
                ),
            ):
                rc = run_all_challenges(args)

        self.assertEqual(rc, 0)
        self.assertEqual(observed_workers, [2])
        self.assertEqual(
            submissions,
            [
                ("_run_named_challenge_worker", "alpha"),
                ("_run_named_challenge_worker", "beta"),
            ],
        )
        self.assertIn(["alpha", "beta"], active_snapshots)

    def test_parallel_scheduler_does_not_fill_workers_with_compose_lock_waiters(
        self,
    ) -> None:
        submissions: list[str] = []
        pending_futures: dict[str, futures.Future[dict[str, object]]] = {}

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                self.max_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, _fn, _base_args, name: str):
                future: futures.Future[dict[str, object]] = futures.Future()
                pending_futures[name] = future
                submissions.append(name)
                return future

        wait_calls = 0

        def fake_wait(future_set, return_when=None):
            nonlocal wait_calls
            del return_when
            future_set = set(future_set)
            wait_calls += 1
            if wait_calls == 1:
                self.assertEqual(
                    submissions,
                    ["compose-a", "plain-a", "plain-b"],
                )
                pending_futures["plain-a"].set_result(
                    {
                        "challenge": "plain-a",
                        "solved": False,
                        "status": "failed",
                        "api_error": False,
                        "llm_error": False,
                    }
                )
                return {pending_futures["plain-a"]}, future_set - {
                    pending_futures["plain-a"]
                }
            for name in ("compose-a", "plain-b", "compose-b"):
                future = pending_futures.get(name)
                if future is not None and not future.done():
                    future.set_result(
                        {
                            "challenge": name,
                            "solved": False,
                            "status": "failed",
                            "api_error": False,
                            "llm_error": False,
                        }
                    )
                    return {future}, future_set - {future}
            return set(future_set), set()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dataset"
            for name, compose in (
                ("compose-a", True),
                ("compose-b", True),
                ("plain-a", False),
                ("plain-b", False),
            ):
                challenge_dir = root / name
                challenge_dir.mkdir(parents=True)
                (challenge_dir / "challenge.json").write_text(
                    json.dumps({"name": name, "compose": compose}),
                    encoding="utf-8",
                )
            args = _args(Path(tmp))
            args.parallel_workers = 3
            with (
                patch(
                    "killchain_docker.batch.runner.load_dataset",
                    return_value=_FakeComposeDataset(str(root)),
                ),
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor",
                    FakeExecutor,
                ),
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.wait",
                    side_effect=fake_wait,
                ),
            ):
                rc = run_all_challenges(args)

        self.assertEqual(rc, 1)
        self.assertEqual(submissions[:3], ["compose-a", "plain-a", "plain-b"])
        self.assertEqual(submissions[3], "compose-b")

    def test_parallel_stop_path_clears_cancelled_active_runs(self) -> None:
        active_snapshots: list[list[str]] = []

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                del max_workers

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, fn, _base_args, name: str):
                del fn
                future: futures.Future[dict[str, object]] = futures.Future()
                if name == "alpha":
                    future.set_result(
                        {
                            "challenge": name,
                            "solved": False,
                            "status": "failed",
                            "api_error": True,
                            "llm_error": True,
                        }
                    )
                return future

        def fake_write_batch_monitor(**kwargs):
            active_snapshots.append(
                [item["challenge"] for item in kwargs.get("active_runs") or []]
            )
            return Path(kwargs["logdir"]) / "_batch_monitor.html"

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.parallel_workers = 2
            with (
                patch(
                    "killchain_docker.batch.runner.load_dataset",
                    return_value=_FakeDataset(),
                ),
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor",
                    FakeExecutor,
                ),
                patch(
                    "killchain_docker.batch.runner.write_batch_monitor",
                    fake_write_batch_monitor,
                ),
            ):
                rc = run_all_challenges(args)

        self.assertEqual(rc, 1)
        self.assertIn([], active_snapshots)

    def test_run_all_continues_after_transient_preflight_llm_error(self) -> None:
        calls: list[str] = []

        @contextmanager
        def fake_lock(_challenge):
            yield

        class FakeChallenge:
            def __init__(self, payload, _basedir) -> None:
                self.canonical_name = str(payload["name"])

        def fake_run_single(_args, challenge):
            calls.append(challenge.canonical_name)
            if challenge.canonical_name == "alpha":
                return {
                    "challenge": "alpha",
                    "solved": False,
                    "status": "failed",
                    "api_error": False,
                    "llm_error": True,
                    "error": {
                        "type": "LLMClientError",
                        "message": "temporary outage",
                        "transient": True,
                    },
                }
            return {
                "challenge": "beta",
                "solved": True,
                "status": "solved",
                "api_error": False,
                "llm_error": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.parallel_workers = 1
            with (
                patch(
                    "killchain_docker.batch.runner.load_dataset",
                    return_value=_FakeDataset(),
                ),
                patch("killchain_docker.batch.runner.CTFChallenge", FakeChallenge),
                patch("killchain_docker.batch.runner.compose_challenge_run_lock", fake_lock),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    side_effect=fake_run_single,
                ),
            ):
                rc = run_all_challenges(args)

        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["alpha", "beta"])

    def test_batch_fatal_api_error_detects_nontransient_llm_error(self) -> None:
        from killchain_docker.batch.runner import _is_batch_fatal_api_error

        transient = LLMClientError("temporary", transient=True)
        permanent = LLMClientError("bad schema", transient=False)

        self.assertFalse(_is_batch_fatal_api_error(transient))
        self.assertTrue(_is_batch_fatal_api_error(permanent))

    def test_batch_interrupt_writes_active_status_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            with (
                patch(
                    "killchain_docker.batch.runner.load_dataset",
                    return_value=_FakeDataset(),
                ),
                patch(
                    "killchain_docker.batch.runner.CTFChallenge", return_value=object()
                ),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    side_effect=KeyboardInterrupt(),
                ),
            ):
                with self.assertLogs(
                    "killchain_docker.batch.runner", level="WARNING"
                ) as captured:
                    rc = run_all_challenges(args)

            status_path = Path(tmp) / "alpha.status.json"
            summary_path = Path(tmp) / "_batch_summary.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(rc, 130)
        self.assertEqual(status["stage"], "batch_interrupted")
        self.assertEqual(status["status"], "interrupted")
        self.assertEqual(status["error"]["type"], "KeyboardInterrupt")
        self.assertEqual(summary["interrupted_count"], 1)
        self.assertEqual(summary["details"][0]["status_file"], "alpha.status.json")
        self.assertTrue(
            any(
                "batch interrupted; saving progress" in message
                for message in captured.output
            )
        )
        self.assertTrue(any("Traceback" in message for message in captured.output))

    def test_single_replica_path_starts_monitor_heartbeat(self) -> None:
        heartbeat_events: list[str] = []

        class FakeHeartbeat:
            def __init__(self, _write_snapshot) -> None:
                pass

            def start(self) -> None:
                heartbeat_events.append("start")

            def stop(self) -> None:
                heartbeat_events.append("stop")

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.challenge = "alpha"
            args.run_all = False
            with (
                patch(
                    "killchain_docker.batch.runner.load_challenge",
                    return_value=_DummyChallenge(),
                ),
                patch(
                    "killchain_docker.batch.runner.run_single_challenge",
                    return_value={
                        "challenge": "alpha",
                        "solved": True,
                        "status": "solved",
                        "api_error": False,
                        "llm_error": False,
                    },
                ),
                patch(
                    "killchain_docker.batch.runner._BatchMonitorHeartbeat",
                    FakeHeartbeat,
                ),
            ):
                rc = run_single_challenge_replicas(args)

        self.assertEqual(rc, 0)
        self.assertEqual(heartbeat_events, ["start", "stop"])

    def test_multi_replica_run_writes_monitor_and_summary(self) -> None:
        observed_workers: list[int] = []
        heartbeat_events: list[str] = []

        class FakeHeartbeat:
            def __init__(self, _write_snapshot) -> None:
                pass

            def start(self) -> None:
                heartbeat_events.append("start")

            def stop(self) -> None:
                heartbeat_events.append("stop")

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                observed_workers.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, _fn, _base_args, replica_idx: int, _label_prefix: str):
                future: futures.Future[dict[str, object]] = futures.Future()
                future.set_result(
                    {
                        "challenge": "alpha",
                        "replica": replica_idx,
                        "solved": replica_idx == 1,
                        "status": "solved" if replica_idx == 1 else "failed",
                        "api_error": False,
                        "llm_error": False,
                    }
                )
                return future

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.challenge = "alpha"
            args.run_all = False
            args.replicas = 2
            args.parallel_workers = 2
            args.name = "replicas"
            with (
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor",
                    FakeExecutor,
                ),
                patch(
                    "killchain_docker.batch.runner._BatchMonitorHeartbeat",
                    FakeHeartbeat,
                ),
            ):
                rc = run_single_challenge_replicas(args)

            summary = json.loads(
                (Path(tmp) / "replicas" / "_batch_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            monitor = json.loads(
                (Path(tmp) / "replicas" / "_batch_monitor.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(rc, 0)
        self.assertEqual(observed_workers, [2])
        self.assertEqual(heartbeat_events, ["start", "stop"])
        self.assertEqual(summary["total_attempted"], 2)
        self.assertEqual(monitor["counts"]["completed"], 2)
        self.assertEqual(
            {entry["challenge"] for entry in monitor["entries"]},
            {"alpha#replica-1", "alpha#replica-2"},
        )

    def test_multi_replica_worker_exception_logs_traceback_result(self) -> None:
        class FakeHeartbeat:
            def __init__(self, _write_snapshot) -> None:
                pass

            def start(self) -> None:
                return None

            def stop(self) -> None:
                return None

        class FakeExecutor:
            def __init__(self, max_workers: int) -> None:
                del max_workers

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                return None

            def submit(self, _fn, _base_args, replica_idx: int, _label_prefix: str):
                future: futures.Future[dict[str, object]] = futures.Future()
                future.set_exception(RuntimeError(f"replica {replica_idx} crashed"))
                return future

        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.challenge = "alpha"
            args.run_all = False
            args.replicas = 2
            args.parallel_workers = 2
            args.name = "replica-errors"
            with (
                patch(
                    "killchain_docker.batch.runner.concurrent.futures.ProcessPoolExecutor",
                    FakeExecutor,
                ),
                patch(
                    "killchain_docker.batch.runner._BatchMonitorHeartbeat",
                    FakeHeartbeat,
                ),
                self.assertLogs(
                    "killchain_docker.batch.runner", level="ERROR"
                ) as captured,
            ):
                rc = run_single_challenge_replicas(args)

            summary = json.loads(
                (Path(tmp) / "replica-errors" / "_batch_summary.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(rc, 1)
        self.assertEqual(summary["failed_count"], 2)
        self.assertTrue(
            all(item["error_type"] == "RuntimeError" for item in summary["details"])
        )
        self.assertTrue(
            all(
                str(item["status_file"]).endswith(".status.json")
                for item in summary["details"]
            )
        )
        self.assertTrue(
            any("replica worker failed" in message for message in captured.output)
        )
        self.assertTrue(any("Traceback" in message for message in captured.output))


if __name__ == "__main__":
    unittest.main()
