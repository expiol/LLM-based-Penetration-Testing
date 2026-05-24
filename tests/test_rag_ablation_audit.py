from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from killchain_docker.batch.audit import (
    audit_ablation_manifest,
    main as audit_main,
    read_json_lines,
)
from killchain_docker.batch.monitor import render_monitor_html, write_json


def _write_events(path: Path, run_id: str, challenge: str) -> None:
    records = [
        {
            "schema_version": 1,
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "level": "INFO",
            "event_type": "runtime",
            "message": "started",
            "pid": 1,
            "thread_id": 1,
            "thread_name": "MainThread",
            "context": {"run_id": run_id, "challenge": challenge},
        }
    ]
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")


def _mode_payload(
    root: Path,
    mode: str,
    *,
    challenge_identity_hit: bool = False,
    same_event_hit: bool = False,
) -> dict[str, object]:
    challenge = "demo-challenge"
    logdir = root / f"rag_{mode}"
    run_dir = root / "artifacts" / mode / "run-demo"
    logdir.mkdir(parents=True)
    run_dir.mkdir(parents=True)
    rag_enabled = mode != "disabled"
    rag_status = "hit" if rag_enabled else "disabled"
    public_policy = {
        "oracle": "supplemental_context",
        "strict": "filtered_context",
        "disabled": "disabled",
    }[mode]
    hint_count = 2 if rag_enabled else 0

    artifacts = {
        "run_id": "run-demo",
        "run_dir": str(run_dir),
        "state_path": str(run_dir / "state.json"),
        "summary_path": str(run_dir / "summary.json"),
        "report_path": str(run_dir / "report.md"),
        "events_path": str(run_dir / "events.log"),
        "config_path": str(run_dir / "config.json"),
        "evidence_path": str(run_dir / "evidence.json"),
        "compact_json_path": str(run_dir / "compact_log.json"),
        "compact_markdown_path": str(run_dir / "compact_log.md"),
        "status": "completed",
    }
    rag = {
        "mode": mode,
        "enabled": rag_enabled,
        "strict_exclude": mode == "strict",
        "status": rag_status,
        "top_score": 0.9,
        "top_challenge_id": challenge if challenge_identity_hit else "other-challenge",
        "top_year": "2013",
        "top_event": "Other-Event",
        "top_event_key": "2013:other-event",
        "challenge_event_key": "2013:demo-event",
        "excluded_challenge_ids": [challenge] if mode == "strict" else [],
        "excluded_event_keys": ["2013:demo-event"] if mode == "strict" else [],
        "hit_provenance": [
            {
                "challenge_id": challenge if challenge_identity_hit else "other-challenge",
                "year": "2013",
                "event": "Demo-Event" if same_event_hit else "Other-Event",
                "event_key": "2013:demo-event" if same_event_hit else "2013:other-event",
                "score": 0.9,
            }
        ],
        "hit_count": 2 if rag_enabled else 0,
        "challenge_identity_hit": challenge_identity_hit,
    }
    if mode == "oracle":
        rag["top_challenge_id"] = challenge
        rag["challenge_identity_hit"] = True

    for key, raw_path in artifacts.items():
        if key.endswith("_path"):
            Path(str(raw_path)).write_text("{}\n", encoding="utf-8")
    _write_events(Path(str(artifacts["events_path"])), "run-demo", challenge)
    write_json(
        Path(str(artifacts["state_path"])),
        {
            "run_id": "run-demo",
            "status": "completed",
            "metadata": {"rag": rag},
        },
    )
    write_json(
        Path(str(artifacts["summary_path"])),
        {
            "run_id": "run-demo",
            "status": "completed",
            "rag": {
                "enabled": rag_enabled,
                "status": rag_status,
                "policy": public_policy,
                "hint_count": hint_count,
            },
        },
    )

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
                        "status": "unsolved_exhausted",
                        "roles": ["observed", "status_writer"],
                    }
                ],
            },
            "run_id": "run-demo",
            "stage": "complete",
            "status": "unsolved_exhausted",
            "solved": False,
            "updated_at": "2026-01-01T00:00:00Z",
            "runtime_sec": 1.5,
            "rag": {
                "enabled": rag_enabled,
                "status": rag_status,
                "policy": public_policy,
                "hint_count": hint_count,
            },
        },
    )
    detail = {
        "challenge": challenge,
        "run_id": "run-demo",
        "solved": False,
        "status": "unsolved_exhausted",
        "rag_mode": mode,
        "token_usage": {"llm_calls": 1, "prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        "artifacts": artifacts,
        "status_file": f"{challenge}.status.json",
        "failure_buckets": ["unsolved_exhausted"],
    }
    write_json(
        logdir / "_batch_summary.json",
        {
            "schema_version": 2,
            "finished": True,
            "total_attempted": 1,
            "solved_count": 0,
            "failed_count": 1,
            "skipped_count": 0,
            "interrupted_count": 0,
            "success_rate": 0.0,
            "experiment_config": {"rag_mode": mode},
            "token_usage": {"total": {"total_tokens": 5}},
            "failure_buckets": {"unsolved_exhausted": 1},
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
                "solved": 0,
                "failed": 1,
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
                        "status": "unsolved_exhausted",
                        "rag": {
                            "enabled": rag_enabled,
                            "status": rag_status,
                            "policy": public_policy,
                            "hint_count": hint_count,
                        },
                    },
                }
            ],
        },
    )
    (logdir / "_batch_monitor.html").write_text(render_monitor_html(), encoding="utf-8")
    return {
        "mode": mode,
        "returncode": 1,
        "logdir": str(logdir),
        "summary_path": str(logdir / "_batch_summary.json"),
        "monitor_json_path": str(logdir / "_batch_monitor.json"),
        "monitor_path": str(logdir / "_batch_monitor.html"),
        "metrics": {"attempted": 1, "solved": 0, "failed": 1},
    }


class RagAblationAuditTests(unittest.TestCase):
    def test_read_json_lines_logs_malformed_record_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.log"
            path.write_text('{"ok": true}\n{\n', encoding="utf-8")

            with self.assertLogs(
                "killchain_docker.batch.audit",
                level="WARNING",
            ) as captured:
                records = read_json_lines(path)

        self.assertEqual(records, [])
        self.assertEqual(
            captured.records[0].getMessage(),
            "failed to decode JSONL record",
        )
        self.assertEqual(captured.records[0].line_number, 2)
        self.assertIsNotNone(captured.records[0].exc_info)

    def test_read_json_lines_logs_non_object_record_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.log"
            path.write_text('{"ok": true}\n[]\n', encoding="utf-8")

            with self.assertLogs(
                "killchain_docker.batch.audit",
                level="WARNING",
            ) as captured:
                records = read_json_lines(path)

        self.assertEqual(records, [])
        self.assertEqual(
            captured.records[0].getMessage(),
            "JSONL record is not an object",
        )
        self.assertEqual(captured.records[0].line_number, 2)
        self.assertEqual(captured.records[0].payload_type, "list")

    def test_audit_accepts_valid_oracle_strict_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": _mode_payload(root, "oracle"),
                        "strict": _mode_payload(root, "strict"),
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertTrue(payload["ok"], payload["issues"])
            self.assertEqual(payload["modes"]["oracle"]["details_checked"], 1)
            self.assertEqual(payload["modes"]["strict"]["events_checked"], 1)

    def test_audit_accepts_disabled_mode_without_required_rag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "disabled": _mode_payload(root, "disabled"),
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("disabled",))

            self.assertTrue(payload["ok"], payload["issues"])
            self.assertEqual(payload["modes"]["disabled"]["details_checked"], 1)

    def test_audit_rejects_monitor_summary_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            monitor_path = Path(str(oracle_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["counts"]["failed"] = 0
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_summary_count_mismatch", codes)

    def test_audit_reports_invalid_counts_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            summary_path = Path(str(oracle_payload["summary_path"]))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["total_attempted"] = "bad"
            write_json(summary_path, summary)
            monitor_path = Path(str(oracle_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["counts"]["failed"] = "bad"
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("summary_count_invalid", codes)
            self.assertIn("monitor_summary_count_invalid", codes)

    def test_audit_reports_invalid_runtime_returncode_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            oracle_payload["returncode"] = "bad"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("mode_returncode_invalid", codes)

    def test_audit_rejects_monitor_result_status_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            monitor_path = Path(str(oracle_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["entries"][0]["result"]["status"] = "solved"
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_result_status_mismatch", codes)

    def test_audit_cli_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            output_path = root / "rag" / "_rag_ablation_audit.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "disabled": _mode_payload(root, "disabled"),
                    },
                    "comparison": {"available": False},
                },
            )

            with redirect_stdout(StringIO()):
                rc = audit_main([
                    str(report_path),
                    "--expected-modes",
                    "disabled",
                    "--output",
                    str(output_path),
                    "--quiet",
                ])

            payload = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual(rc, 0)
            self.assertTrue(payload["ok"], payload["issues"])
            self.assertEqual(payload["report_path"], str(report_path))

    def test_audit_cli_accepts_dry_run_manifest_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": {
                            "mode": "oracle",
                            "dry_run": True,
                            "returncode": 0,
                            "command": ["python", "run.py", "--rag-mode", "oracle"],
                            "logdir": str(root / "oracle"),
                        },
                        "strict": {
                            "mode": "strict",
                            "dry_run": True,
                            "returncode": 0,
                            "command": ["python", "run.py", "--rag-mode", "strict"],
                            "logdir": str(root / "strict"),
                        },
                    },
                    "comparison": {"available": False, "reason": "insufficient_results"},
                },
            )

            stream = StringIO()
            with redirect_stdout(stream):
                rc = audit_main([str(report_path), "--quiet"])

            payload = json.loads(stream.getvalue())

            self.assertEqual(rc, 0)
            self.assertTrue(payload["ok"], payload["issues"])
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["modes"]["oracle"]["returncode"], 0)

    def test_audit_reports_invalid_dry_run_returncode_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": {
                            "mode": "oracle",
                            "dry_run": True,
                            "returncode": "bad",
                            "command": ["python", "run.py", "--rag-mode", "oracle"],
                            "logdir": str(root / "oracle"),
                        },
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("mode_returncode_invalid", codes)

    def test_audit_rejects_disabled_mode_reporting_public_rag_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            disabled_payload = _mode_payload(root, "disabled")
            status_path = Path(str(disabled_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["rag"] = {
                "enabled": True,
                "status": "hit",
                "policy": "supplemental_context",
                "hint_count": 2,
            }
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "disabled": disabled_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("disabled",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_enabled", codes)
            self.assertIn("public_rag_policy", codes)

    def test_audit_rejects_metadata_only_public_rag_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            status_path = Path(str(oracle_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["rag"] = {
                "enabled": True,
                "status": "metadata_only",
                "policy": "supplemental_context",
                "hint_count": 0,
            }
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_unavailable", codes)
            self.assertIn("public_rag_empty", codes)

    def test_audit_reports_invalid_public_rag_hint_count_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            status_path = Path(str(oracle_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["rag"]["hint_count"] = "bad"
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("oracle",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_count_invalid", codes)

    def test_audit_rejects_strict_challenge_identity_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": _mode_payload(root, "oracle"),
                        "strict": _mode_payload(root, "strict", challenge_identity_hit=True),
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("rag_strict_identity_hit", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_strict_same_event_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": _mode_payload(root, "oracle"),
                        "strict": _mode_payload(root, "strict", same_event_hit=True),
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("rag_strict_same_event_hit", {item["code"] for item in payload["issues"]})

    def test_audit_reports_invalid_artifact_rag_hit_count_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            state_path = root / "artifacts" / "strict" / "run-demo" / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["metadata"]["rag"]["hit_count"] = "bad"
            write_json(state_path, state)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("rag_hit_count_invalid", codes)

    def test_audit_rejects_raw_rag_payload_in_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            monitor_path = Path(str(strict_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["entries"][0]["result"]["rag"] = {
                "enabled": True,
                "mode": "strict",
                "status": "hit",
                "knowledge_hints": [{"solution_sketch": "raw"}],
            }
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_raw_payload", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_raw_rag_payload_in_artifact_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            artifact_summary_path = root / "artifacts" / "strict" / "run-demo" / "summary.json"
            artifact_summary = json.loads(artifact_summary_path.read_text(encoding="utf-8"))
            artifact_summary["rag"]["mode"] = "strict"
            artifact_summary["rag"]["knowledge_hints"] = [{"solution_sketch": "raw"}]
            write_json(artifact_summary_path, artifact_summary)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_raw_payload", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_inconsistent_runtime_error_observability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            summary_path = Path(str(strict_payload["summary_path"]))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["details"][0]["runtime_error"] = {
                "type": "RuntimeError",
                "message": "router crashed before finalizing state",
            }
            write_json(summary_path, summary)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            codes = {item["code"] for item in payload["issues"]}
            self.assertFalse(payload["ok"])
            self.assertIn("runtime_error_bucket_missing", codes)
            self.assertIn("runtime_error_missing", codes)
            self.assertIn("runtime_error_compact_missing", codes)
            self.assertIn("runtime_error_text_missing", codes)

    def test_audit_accepts_consistent_runtime_error_observability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            logdir = Path(str(strict_payload["logdir"]))
            artifact_dir = root / "artifacts" / "strict" / "run-demo"
            runtime_error = {
                "type": "RuntimeError",
                "message": "router crashed before finalizing state",
            }

            summary_path = logdir / "_batch_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["failure_buckets"] = {"runtime_error": 1}
            summary["details"][0]["runtime_error"] = runtime_error
            summary["details"][0]["failure_buckets"] = ["runtime_error"]
            write_json(summary_path, summary)

            status_path = logdir / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["runtime_error"] = runtime_error
            write_json(status_path, status)

            monitor_path = logdir / "_batch_monitor.json"
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["entries"][0]["result"]["runtime_error"] = runtime_error
            write_json(monitor_path, monitor)

            artifact_summary_path = artifact_dir / "summary.json"
            artifact_summary = json.loads(artifact_summary_path.read_text(encoding="utf-8"))
            artifact_summary["runtime_error"] = runtime_error
            write_json(artifact_summary_path, artifact_summary)
            write_json(artifact_dir / "compact_log.json", {"run": {"runtime_error": runtime_error}})
            (artifact_dir / "report.md").write_text("Runtime Error: RuntimeError\n", encoding="utf-8")
            (artifact_dir / "compact_log.md").write_text("Runtime error: RuntimeError\n", encoding="utf-8")

            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            self.assertTrue(payload["ok"], payload["issues"])

    def test_audit_rejects_missing_monitor_detail_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            monitor_path = Path(str(strict_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["entries"] = []
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_detail_missing", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_finished_monitor_active_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            monitor_path = Path(str(strict_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["entries"][0]["state"] = "active"
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_entry_not_completed", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_finished_summary_with_unfinished_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            monitor_path = Path(str(strict_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["finished"] = False
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_unfinished", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_unsafe_monitor_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            monitor_path = Path(str(strict_payload["monitor_json_path"]))
            monitor = json.loads(monitor_path.read_text(encoding="utf-8"))
            monitor["logdir"] = str(root)
            monitor["entries"][0]["status_file"] = "../escape.status.json"
            monitor["entries"][0]["result"]["artifacts"] = {
                "report_path": "javascript:alert(1)",
                "artifact_paths": ["ok.txt", "/tmp/outside.txt"],
            }
            write_json(monitor_path, monitor)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            path_issues = [item for item in payload["issues"] if item["code"] == "monitor_path_unsafe"]

            self.assertFalse(payload["ok"])
            self.assertGreaterEqual(len(path_issues), 4)
            self.assertTrue(any(item["field"] == "monitor.logdir" for item in path_issues))
            self.assertTrue(any(item["field"].endswith("status_file") for item in path_issues))

    def test_audit_rejects_unsafe_status_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["logfile"] = "/tmp/outside.json"
            status["artifacts"] = {
                "report_path": "../report.md",
                "artifact_paths": ["ok.txt", "javascript:alert(1)"],
            }
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            path_issues = [item for item in payload["issues"] if item["code"] == "status_path_unsafe"]
            fields = {item["field"] for item in path_issues}

            self.assertFalse(payload["ok"])
            self.assertEqual(len(path_issues), 3)
            self.assertIn("status.logfile", fields)
            self.assertIn("status.artifacts.report_path", fields)
            self.assertIn("status.artifacts.artifact_paths[1]", fields)

    def test_audit_rejects_stale_monitor_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html_path.write_text("<html></html>\n", encoding="utf-8")
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("monitor_html_stale", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_monitor_without_status_error_liveness_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace('      if (row.statusError) return "stale";\n', ""),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("status polling failure liveness downgrade", stale_issues[0]["missing"])

    def test_audit_rejects_monitor_without_terminal_status_badge_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace('"unsolved_exhausted"', '"legacy_exhausted"'),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("unsolved terminal status badge mapping", stale_issues[0]["missing"])

    def test_audit_rejects_monitor_without_thread_registry_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace("function threadRegistrySummary", "function legacyThreadSummary"),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("thread registry rendering", stale_issues[0]["missing"])

    def test_audit_rejects_monitor_without_thread_event_message_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace("event.message", "event.detail"),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("per-thread latest event message rendering", stale_issues[0]["missing"])

    def test_audit_rejects_monitor_without_thread_worker_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace("todo.worker", "todo.assignee"),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("per-thread worker rendering", stale_issues[0]["missing"])

    def test_audit_rejects_monitor_without_browser_refresh_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            html_path = Path(str(strict_payload["monitor_path"]))
            html = html_path.read_text(encoding="utf-8")
            html_path.write_text(
                html.replace("function pollStatusText", "function oldPollStatusText"),
                encoding="utf-8",
            )
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            stale_issues = [item for item in payload["issues"] if item["code"] == "monitor_html_stale"]

            self.assertFalse(payload["ok"])
            self.assertTrue(stale_issues)
            self.assertIn("browser refresh status rendering", stale_issues[0]["missing"])

    def test_audit_rejects_raw_rag_payload_in_status_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["rag"] = {
                "enabled": True,
                "mode": "strict",
                "status": "hit",
                "strict_exclude": True,
                "hit_provenance": [{"challenge_id": "other"}],
            }
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("public_rag_raw_payload", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_status_summary_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["status"] = "solved"
            status["run_id"] = "other-run"
            status["solved"] = True
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("status_result_mismatch", codes)
            self.assertIn("status_run_id_mismatch", codes)
            self.assertIn("status_solved_mismatch", codes)

    def test_audit_rejects_status_missing_observability_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            for key in (
                "pid",
                "thread_id",
                "thread_name",
                "status_writer_thread_id",
                "status_writer_thread_name",
                "runtime_sec",
            ):
                status.pop(key, None)
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)
            codes = {item["code"] for item in payload["issues"]}

            self.assertFalse(payload["ok"])
            self.assertIn("status_observability_missing", codes)
            self.assertIn("status_runtime_missing", codes)

    def test_audit_rejects_status_missing_thread_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("threads", None)
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            self.assertFalse(payload["ok"])
            self.assertIn("status_thread_registry_missing", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_registry_missing_latest_event_thread(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            status_path = Path(str(strict_payload["logdir"])) / "demo-challenge.status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["latest_event"] = {
                "event_type": "worker_progress",
                "thread_id": 99,
                "thread_name": "missing-worker-thread",
                "message": "worker event",
            }
            write_json(status_path, status)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            self.assertFalse(payload["ok"])
            self.assertIn(
                "status_thread_registry_latest_event_missing",
                {item["code"] for item in payload["issues"]},
            )

    def test_audit_rejects_worker_event_missing_todo_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            strict_payload = _mode_payload(root, "strict")
            events_path = root / "artifacts" / "strict" / "run-demo" / "events.log"
            record = {
                "schema_version": 1,
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "level": "INFO",
                "event_type": "worker_progress",
                "message": "progress without todo context",
                "pid": 1,
                "thread_id": 1,
                "thread_name": "MainThread",
                "context": {"run_id": "run-demo", "challenge": "demo-challenge"},
            }
            events_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "strict": strict_payload,
                    },
                    "comparison": {"available": False},
                },
            )

            payload = audit_ablation_manifest(report_path, expected_modes=("strict",))

            self.assertFalse(payload["ok"])
            self.assertIn("event_worker_context", {item["code"] for item in payload["issues"]})

    def test_audit_rejects_unredacted_rag_hint_literals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "rag" / "_rag_ablation.json"
            oracle_payload = _mode_payload(root, "oracle")
            strict_payload = _mode_payload(root, "strict")
            state_path = root / "artifacts" / "strict" / "run-demo" / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["metadata"]["rag"]["knowledge_hints"] = [
                {
                    "rank": 1,
                    "category": "crypto",
                    "description": "The answer is flag{do_not_audit_pass}.",
                    "files": [
                        "solve.py",
                        "lower_case_answer_token.txt",
                        "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME.bin",
                    ],
                    "solution_sketch": "Recover flag{do_not_copy_this} with the method.",
                }
            ]
            write_json(state_path, state)
            write_json(
                report_path,
                {
                    "schema_version": 1,
                    "finished": True,
                    "modes": {
                        "oracle": oracle_payload,
                        "strict": strict_payload,
                    },
                    "comparison": {"available": True, "strict_minus_oracle": {"solved": 0}},
                },
            )

            payload = audit_ablation_manifest(report_path)

            self.assertFalse(payload["ok"])
            self.assertIn("rag_hint_literal_leak", {item["code"] for item in payload["issues"]})


if __name__ == "__main__":
    unittest.main()
