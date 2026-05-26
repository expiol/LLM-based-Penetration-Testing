from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, Sequence
from unittest.mock import patch

from killchain_docker.batch.ablation import (
    QUALITY_GATE_FAILURE_EXIT_CODE,
    build_comparison,
    build_mode_command,
    main,
    mode_logdir,
    run_ablation,
    run_mode_command,
    summarize_mode,
    success_rate_requirement,
)
from killchain_docker.batch.monitor import render_monitor_html, write_json


def _args(logdir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        challenge="demo-challenge",
        challenges=None,
        run_all=False,
        category=None,
        dataset=None,
        split="development",
        modes=["oracle", "strict"],
        max_cycles=3,
        parallel_workers=2,
        replicas=1,
        container_image="ctfenv:latest",
        container_network="ctfnet",
        logdir=str(logdir),
        output_root=str(logdir / "artifacts"),
        name="rag_exp",
        skip_exist=False,
        quiet=True,
        debug=False,
        dry_run=False,
        audit=False,
        audit_output=None,
        audit_allow_unfinished=False,
        audit_allow_empty=False,
        audit_allow_missing_rag=False,
        min_success_rate=[],
        require_rag_ok=False,
        auto_max_cycles=False,
        sample_size=None,
        sample_seed=None,
        sample_strategy="random",
    )


def _arg_value(command: Sequence[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def _public_rag(mode: str) -> dict[str, Any]:
    policy = {
        "oracle": "supplemental_context",
        "strict": "filtered_context",
        "disabled": "disabled",
    }[mode]
    enabled = mode != "disabled"
    return {
        "enabled": enabled,
        "status": "hit" if enabled else "disabled",
        "policy": policy,
        "hint_count": 1 if enabled else 0,
    }


def _write_finished_mode(args: argparse.Namespace, mode: str, *, solved: bool) -> None:
    logdir = mode_logdir(args, mode)
    challenge = "demo-challenge"
    status = "solved" if solved else "unsolved_exhausted"
    rag = _public_rag(mode)
    detail = {
        "challenge": challenge,
        "run_id": f"run-{mode}",
        "solved": solved,
        "status": status,
        "rag_mode": mode,
        "rag": rag,
        "status_file": f"{challenge}.status.json",
    }
    write_json(
        logdir / f"{challenge}.status.json",
        {
            "schema_version": 1,
            "challenge": challenge,
            "pid": 1,
            "thread_id": 1,
            "thread_name": "MainThread",
            "status_writer_thread_id": 1,
            "status_writer_thread_name": "MainThread",
            "threads": {
                "observed": {"id": 1, "name": "MainThread"},
                "status_writer": {"id": 1, "name": "MainThread"},
                "registry": [
                    {
                        "id": 1,
                        "name": "MainThread",
                        "pid": 1,
                        "challenge": challenge,
                        "stage": "complete",
                        "status": status,
                        "roles": ["observed", "status_writer"],
                    }
                ],
            },
            "run_id": f"run-{mode}",
            "status": status,
            "solved": solved,
            "updated_at": "2026-01-01T00:00:00Z",
            "runtime_sec": 1.0,
            "rag": rag,
        },
    )
    write_json(
        logdir / "_batch_summary.json",
        {
            "schema_version": 2,
            "finished": True,
            "total_attempted": 1,
            "solved_count": int(solved),
            "failed_count": int(not solved),
            "skipped_count": 0,
            "interrupted_count": 0,
            "success_rate": 1.0 if solved else 0.0,
            "experiment_config": {"rag_mode": mode},
            "token_usage": {"total": {"total_tokens": 100 if solved else 50}},
            "details": [detail],
        },
    )
    write_json(
        logdir / "_batch_monitor.json",
        {
            "schema_version": 1,
            "finished": True,
            "counts": {
                "total": 1,
                "completed": 1,
                "active": 0,
                "solved": int(solved),
                "failed": int(not solved),
                "skipped": 0,
                "interrupted": 0,
            },
            "entries": [
                {
                    "challenge": challenge,
                    "state": "completed",
                    "status_file": f"{challenge}.status.json",
                    "result": {
                        "challenge": challenge,
                        "status": status,
                        "solved": solved,
                        "rag": rag,
                    },
                }
            ],
        },
    )
    (logdir / "_batch_monitor.html").write_text(render_monitor_html(), encoding="utf-8")


class RagAblationTests(unittest.TestCase):
    def test_build_mode_command_uses_explicit_single_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            command = build_mode_command(args, "strict")

        self.assertIn("--challenge", command)
        self.assertNotIn("--run-all", command)
        self.assertEqual(_arg_value(command, "--challenge"), "demo-challenge")
        self.assertEqual(_arg_value(command, "--rag-mode"), "strict")
        self.assertTrue(
            _arg_value(command, "--output-root").endswith("/artifacts/strict")
        )
        self.assertIn("--quiet", command)

    def test_build_mode_command_omits_challenge_for_run_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.run_all = True
            command = build_mode_command(args, "oracle")

        self.assertIn("--run-all", command)
        self.assertNotIn("--challenge", command)

    def test_build_mode_command_passes_explicit_challenge_subset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.challenges = ["alpha", "beta"]
            command = build_mode_command(args, "oracle")

        self.assertIn("--challenges", command)
        index = command.index("--challenges")
        self.assertEqual(command[index + 1 : index + 3], ["alpha", "beta"])
        self.assertNotIn("--challenge", command)
        self.assertNotIn("--run-all", command)

    def test_build_mode_command_forwards_auto_max_cycles_only_when_enabled(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            command = build_mode_command(args, "oracle")
            args.auto_max_cycles = True
            auto_command = build_mode_command(args, "oracle")

        self.assertNotIn("--auto-max-cycles", command)
        self.assertIn("--auto-max-cycles", auto_command)

    def test_build_mode_command_forwards_sample_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.run_all = True
            args.sample_size = 3
            args.sample_seed = 11
            args.sample_strategy = "category_round_robin"
            command = build_mode_command(args, "oracle")

        self.assertEqual(_arg_value(command, "--sample-size"), "3")
        self.assertEqual(_arg_value(command, "--sample-seed"), "11")
        self.assertEqual(
            _arg_value(command, "--sample-strategy"),
            "category_round_robin",
        )

    def test_success_rate_requirement_accepts_mode_or_global_rate(self) -> None:
        self.assertEqual(success_rate_requirement("0.75"), ("all", 0.75))
        self.assertEqual(success_rate_requirement("oracle=1"), ("oracle", 1.0))
        with self.assertRaises(argparse.ArgumentTypeError):
            success_rate_requirement("demo=0.5")
        with self.assertRaises(argparse.ArgumentTypeError):
            success_rate_requirement("strict=1.5")

    def test_run_mode_command_uses_bounded_capture(self) -> None:
        result = run_mode_command(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "sys.stdout.write('A' * 1200000); "
                    "sys.stderr.write('B' * 1200000)"
                ),
            ]
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("[output truncated:", result.stdout)
        self.assertIn("[output truncated:", result.stderr)

    def test_run_ablation_collects_mode_summaries_and_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            seen_modes: list[str] = []

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                seen_modes.append(mode)
                solved = 2 if mode == "oracle" else 1
                success_rate = 1.0 if mode == "oracle" else 0.5
                logdir = mode_logdir(args, mode)
                policy = (
                    "supplemental_context" if mode == "oracle" else "filtered_context"
                )
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 2,
                        "solved_count": solved,
                        "failed_count": 2 - solved,
                        "skipped_count": 0,
                        "success_rate": success_rate,
                        "elapsed_sec": 10,
                        "token_usage": {"total": {"total_tokens": solved * 100}},
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "a",
                                "rag": {
                                    "mode": mode,
                                    "enabled": True,
                                    "status": "hit",
                                    "policy": policy,
                                    "hint_count": 1,
                                },
                            },
                            {
                                "challenge": "b",
                                "rag": {
                                    "mode": mode,
                                    "enabled": True,
                                    "status": "hit",
                                    "policy": policy,
                                    "hint_count": 1,
                                },
                            },
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 2}})
                return subprocess.CompletedProcess(
                    list(command),
                    1 if mode == "strict" else 0,
                    stdout=f"{mode} child stdout",
                    stderr=f"{mode} child stderr",
                )

            report = run_ablation(args, run_command=fake_run)

            self.assertEqual(seen_modes, ["oracle", "strict"])
            self.assertTrue(report["finished"])
            self.assertEqual(report["modes"]["oracle"]["metrics"]["solved"], 2)
            self.assertEqual(report["modes"]["strict"]["metrics"]["solved"], 1)
            self.assertEqual(
                report["modes"]["oracle"]["stdout_tail"], "oracle child stdout"
            )
            self.assertEqual(
                report["modes"]["strict"]["stderr_tail"], "strict child stderr"
            )
            self.assertEqual(report["comparison"]["strict_minus_oracle"]["solved"], -1)
            self.assertEqual(
                report["comparison"]["strict_minus_oracle"]["success_rate"], -0.5
            )
            self.assertEqual(
                report["comparison"]["strict_minus_oracle"]["total_tokens"], -100
            )
            report_path = Path(tmp) / "rag_exp" / "_rag_ablation.json"
            self.assertEqual(
                json.loads(report_path.read_text(encoding="utf-8"))["schema_version"], 1
            )

    def test_run_ablation_writes_audit_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.audit = True

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                _write_finished_mode(args, mode, solved=mode == "oracle")
                return subprocess.CompletedProcess(
                    list(command), 0 if mode == "oracle" else 1
                )

            report = run_ablation(args, run_command=fake_run)
            report_path = Path(tmp) / "rag_exp" / "_rag_ablation.json"
            manifest = json.loads(report_path.read_text(encoding="utf-8"))
            audit = manifest["audit"]
            audit_payload = json.loads(Path(audit["path"]).read_text(encoding="utf-8"))

            self.assertTrue(report["audit"]["ok"], audit_payload["issues"])
            self.assertTrue(audit["ok"], audit_payload["issues"])
            self.assertEqual(audit_payload["report_path"], str(report_path.resolve()))

    def test_quality_gate_accepts_success_and_rag_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.min_success_rate = [("oracle", 1.0), ("strict", 0.0)]
            args.require_rag_ok = True

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                _write_finished_mode(args, mode, solved=mode == "oracle")
                return subprocess.CompletedProcess(
                    list(command), 0 if mode == "oracle" else 1
                )

            report = run_ablation(args, run_command=fake_run)
            manifest = json.loads(
                (Path(tmp) / "rag_exp" / "_rag_ablation.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertTrue(
                report["quality_gate"]["ok"], report["quality_gate"]["issues"]
            )
            self.assertEqual(report["quality_gate"]["issue_count"], 0)
            self.assertTrue(manifest["quality_gate"]["ok"])

    def test_quality_gate_rejects_low_success_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.modes = ["oracle"]
            args.min_success_rate = [("oracle", 1.0)]

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                _write_finished_mode(
                    args, _arg_value(command, "--rag-mode"), solved=False
                )
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)
            codes = {item["code"] for item in report["quality_gate"]["issues"]}

            self.assertFalse(report["quality_gate"]["ok"])
            self.assertIn("success_rate_below_threshold", codes)

    def test_quality_gate_rejects_unhealthy_rag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.modes = ["oracle"]
            args.require_rag_ok = True

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "mode": mode,
                                    "enabled": False,
                                    "status": "unavailable",
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)
            issue = report["quality_gate"]["issues"][0]

            self.assertFalse(report["quality_gate"]["ok"])
            self.assertEqual(issue["code"], "rag_health_failed")
            self.assertEqual(issue["mode"], "oracle")

    def test_quality_gate_rejects_missing_rag_summary_for_required_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.modes = ["oracle"]
            args.require_rag_ok = True

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                write_json(
                    mode_logdir(args, mode) / "_batch_monitor.json",
                    {"counts": {"completed": 1}},
                )
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)
            issue = report["quality_gate"]["issues"][0]

            self.assertFalse(report["quality_gate"]["ok"])
            self.assertEqual(issue["code"], "rag_health_failed")
            self.assertEqual(issue["mode"], "oracle")
            self.assertEqual(issue["rag"]["attempted"], 1)

    def test_summarize_mode_tolerates_malformed_counts_and_rag_hint_count(self) -> None:
        metrics = summarize_mode(
            {
                "mode": "oracle",
                "summary": {
                    "total_attempted": "bad",
                    "solved_count": "bad",
                    "failed_count": "bad",
                    "skipped_count": "bad",
                    "experiment_config": {"rag_mode": "oracle"},
                    "details": [
                        {
                            "rag": {
                                "mode": "oracle",
                                "enabled": True,
                                "status": "hit",
                                "policy": "supplemental_context",
                                "hint_count": "bad",
                            }
                        }
                    ],
                },
                "monitor": {
                    "counts": {
                        "completed": "2",
                        "solved": "1",
                        "failed": "bad",
                        "skipped": "bad",
                    }
                },
            }
        )

        self.assertEqual(metrics["attempted"], 2)
        self.assertEqual(metrics["total_attempted"], 2)
        self.assertEqual(metrics["solved"], 1)
        self.assertEqual(metrics["failed"], 0)
        self.assertFalse(metrics["rag"]["ok"])
        self.assertEqual(metrics["rag"]["unavailable"], 1)
        self.assertEqual(metrics["rag"]["missing"], 1)

    def test_comparison_tolerates_malformed_numeric_deltas(self) -> None:
        comparison = build_comparison(
            {
                "oracle": {
                    "metrics": {
                        "attempted": 1,
                        "solved": "bad",
                        "success_rate": 1.0,
                        "token_usage": {"total": {"total_tokens": "bad"}},
                        "rag": {"required": False, "ok": True},
                    }
                },
                "strict": {
                    "metrics": {
                        "attempted": 1,
                        "solved": 1,
                        "success_rate": 0.5,
                        "token_usage": {"total": {"total_tokens": 10}},
                        "rag": {"required": False, "ok": True},
                    }
                },
            }
        )

        self.assertTrue(comparison["available"], comparison)
        self.assertEqual(comparison["strict_minus_oracle"]["solved"], 1)
        self.assertIsNone(comparison["strict_minus_oracle"]["total_tokens"])

    def test_comparison_reports_each_mode_delta_from_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.modes = ["oracle", "strict", "disabled"]
            solved_by_mode = {"oracle": 3, "strict": 2, "disabled": 1}
            rates_by_mode = {"oracle": 1.0, "strict": 0.667, "disabled": 0.333}

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                solved = solved_by_mode[mode]
                policy = {
                    "oracle": "supplemental_context",
                    "strict": "filtered_context",
                    "disabled": "disabled",
                }[mode]
                enabled = mode != "disabled"
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 3,
                        "solved_count": solved,
                        "failed_count": 3 - solved,
                        "success_rate": rates_by_mode[mode],
                        "experiment_config": {"rag_mode": mode},
                        "token_usage": {"total": {"total_tokens": solved * 100}},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "enabled": enabled,
                                    "status": "hit" if enabled else "disabled",
                                    "policy": policy,
                                    "hint_count": 1 if enabled else 0,
                                },
                            }
                            for _index in range(3)
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 3}})
                return subprocess.CompletedProcess(list(command), 0 if solved else 1)

            report = run_ablation(args, run_command=fake_run)
            deltas = report["comparison"]["deltas_from_oracle"]

            self.assertTrue(report["comparison"]["available"], report["comparison"])
            self.assertEqual(deltas["strict"]["solved"], -1)
            self.assertEqual(deltas["disabled"]["solved"], -2)
            self.assertEqual(
                report["comparison"]["strict_minus_oracle"], deltas["strict"]
            )
            self.assertEqual(
                report["comparison"]["disabled_minus_oracle"], deltas["disabled"]
            )

    def test_comparison_unavailable_when_required_rag_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "mode": mode,
                                    "enabled": False,
                                    "status": "unavailable",
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)

            self.assertFalse(report["comparison"]["available"])
            self.assertEqual(report["comparison"]["reason"], "rag_unavailable")

    def test_comparison_accepts_public_rag_status_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                policy = (
                    "supplemental_context" if mode == "oracle" else "filtered_context"
                )
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 1,
                        "failed_count": 0,
                        "success_rate": 1.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "enabled": True,
                                    "status": "hit",
                                    "policy": policy,
                                    "hint_count": 2,
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 0)

            report = run_ablation(args, run_command=fake_run)

            self.assertTrue(report["comparison"]["available"], report["comparison"])
            self.assertTrue(report["modes"]["oracle"]["metrics"]["rag"]["ok"])
            self.assertTrue(report["modes"]["strict"]["metrics"]["rag"]["ok"])

    def test_comparison_rejects_public_rag_policy_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "enabled": True,
                                    "status": "hit",
                                    "policy": "filtered_context",
                                    "hint_count": 1,
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)

            self.assertFalse(report["comparison"]["available"])
            self.assertEqual(report["comparison"]["reason"], "rag_unavailable")
            self.assertEqual(report["comparison"]["issues"][0]["mode_mismatch"], 1)

    def test_comparison_rejects_metadata_only_rag_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "enabled": True,
                                    "status": "metadata_only",
                                    "policy": "supplemental_context",
                                    "hint_count": 0,
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)

            self.assertFalse(report["comparison"]["available"])
            self.assertEqual(report["comparison"]["reason"], "rag_unavailable")
            self.assertEqual(report["comparison"]["issues"][0]["unavailable"], 1)

    def test_comparison_rejects_public_rag_status_without_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "rag": {
                                    "enabled": True,
                                    "status": "hit",
                                    "hint_count": 1,
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                return subprocess.CompletedProcess(list(command), 1)

            report = run_ablation(args, run_command=fake_run)

            self.assertFalse(report["comparison"]["available"])
            self.assertEqual(report["comparison"]["reason"], "rag_unavailable")
            self.assertEqual(report["comparison"]["issues"][0]["mode_mismatch"], 1)

    def test_dry_run_comparison_unavailable_without_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.dry_run = True

            report = run_ablation(args)

            self.assertTrue(report["finished"])
            self.assertFalse(report["comparison"]["available"])
            self.assertEqual(report["comparison"]["reason"], "insufficient_results")

    def test_dry_run_audit_validates_manifest_without_batch_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            args.dry_run = True
            args.audit = True

            report = run_ablation(args)
            report_path = Path(tmp) / "rag_exp" / "_rag_ablation.json"
            manifest = json.loads(report_path.read_text(encoding="utf-8"))
            audit = manifest["audit"]
            audit_payload = json.loads(Path(audit["path"]).read_text(encoding="utf-8"))

            self.assertTrue(report["audit"]["ok"], audit_payload["issues"])
            self.assertTrue(audit_payload["dry_run"])
            self.assertEqual(audit_payload["issue_count"], 0)
            self.assertEqual(set(audit_payload["modes"]), {"oracle", "strict"})
            self.assertTrue(audit_payload["modes"]["oracle"]["dry_run"])
            self.assertIsInstance(audit_payload["modes"]["oracle"]["command"], list)

    def test_run_ablation_stops_after_infrastructure_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))
            seen_modes: list[str] = []

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                seen_modes.append(_arg_value(command, "--rag-mode"))
                return subprocess.CompletedProcess(list(command), 2)

            report = run_ablation(args, run_command=fake_run)

            self.assertEqual(seen_modes, ["oracle"])
            self.assertFalse(report["finished"])
            self.assertEqual(report["stop_reason"], "mode_failed")
            self.assertNotIn("strict", report["modes"])

    def test_run_ablation_persists_interrupted_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                mode = _arg_value(command, "--rag-mode")
                logdir = mode_logdir(args, mode)
                write_json(
                    logdir / "_batch_summary.json",
                    {
                        "finished": False,
                        "total_attempted": 1,
                        "solved_count": 0,
                        "failed_count": 1,
                        "success_rate": 0.0,
                        "experiment_config": {"rag_mode": mode},
                        "details": [
                            {
                                "challenge": "demo",
                                "status": "interrupted",
                                "solved": False,
                                "rag": {
                                    "enabled": True,
                                    "status": "hit",
                                    "policy": "supplemental_context",
                                    "hint_count": 1,
                                },
                            }
                        ],
                    },
                )
                write_json(logdir / "_batch_monitor.json", {"counts": {"completed": 1}})
                raise KeyboardInterrupt

            with self.assertLogs(
                "killchain_docker.batch.ablation", level="WARNING"
            ) as captured:
                report = run_ablation(args, run_command=fake_run)
            report_path = Path(tmp) / "rag_exp" / "_rag_ablation.json"
            manifest = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertFalse(report["finished"])
            self.assertEqual(report["stop_reason"], "interrupted")
            self.assertIn("oracle", report["modes"])
            self.assertNotIn("strict", report["modes"])
            self.assertEqual(report["modes"]["oracle"]["returncode"], 130)
            self.assertEqual(
                report["modes"]["oracle"]["error"]["type"], "KeyboardInterrupt"
            )
            self.assertEqual(report["modes"]["oracle"]["metrics"]["attempted"], 1)
            self.assertEqual(manifest["stop_reason"], "interrupted")
            self.assertEqual(manifest["modes"]["oracle"]["returncode"], 130)
            self.assertTrue(
                any(
                    "RAG ablation mode interrupted" in message
                    for message in captured.output
                )
            )
            self.assertTrue(any("Traceback" in message for message in captured.output))

    def test_run_ablation_persists_crashed_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = _args(Path(tmp))

            def fake_run(command: Sequence[str]) -> subprocess.CompletedProcess[Any]:
                raise RuntimeError("runner crashed")

            report = run_ablation(args, run_command=fake_run)

            self.assertFalse(report["finished"])
            self.assertEqual(report["stop_reason"], "mode_failed")
            self.assertEqual(report["modes"]["oracle"]["returncode"], 2)
            self.assertEqual(report["modes"]["oracle"]["error"]["type"], "RuntimeError")
            self.assertEqual(
                report["modes"]["oracle"]["error"]["message"], "runner crashed"
            )
            self.assertNotIn("strict", report["modes"])

    def test_main_returns_quality_gate_failure_code(self) -> None:
        report = {
            "finished": True,
            "comparison": {"available": False},
            "modes": {"oracle": {"returncode": 0}},
            "quality_gate": {
                "ok": False,
                "issue_count": 1,
                "issues": [{"code": "success_rate_below_threshold"}],
            },
        }

        with patch("killchain_docker.batch.ablation.run_ablation", return_value=report):
            with redirect_stdout(StringIO()):
                rc = main(["--min-success-rate", "oracle=1", "--quiet"])

        self.assertEqual(rc, QUALITY_GATE_FAILURE_EXIT_CODE)


if __name__ == "__main__":
    unittest.main()
