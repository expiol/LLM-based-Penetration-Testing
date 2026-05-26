from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from killchain_docker.batch.monitor import (
    MONITOR_HTML_NAME,
    MONITOR_JSON_NAME,
    build_monitor_snapshot,
    monitor_result,
    sanitize_monitor_paths,
    status_path_for_logfile,
    write_batch_monitor,
    write_batch_monitor_snapshot,
    write_run_status,
    write_text,
)


class BatchMonitorTests(unittest.TestCase):
    def test_run_status_is_written_next_to_challenge_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logfile = Path(tmp) / "demo.json"
            status_path = status_path_for_logfile(logfile)

            write_run_status(
                status_path,
                challenge="demo",
                stage="assessment",
                status="running",
                message="orchestrator running",
            )

            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["challenge"], "demo")
            self.assertIsInstance(payload["thread_id"], int)
            self.assertIsInstance(payload["thread_name"], str)
            self.assertIsInstance(payload["status_writer_thread_id"], int)
            self.assertIsInstance(payload["status_writer_thread_name"], str)
            self.assertEqual(payload["threads"]["observed"]["id"], payload["thread_id"])
            self.assertEqual(
                payload["threads"]["observed"]["name"], payload["thread_name"]
            )
            self.assertEqual(
                payload["threads"]["status_writer"]["id"],
                payload["status_writer_thread_id"],
            )
            self.assertEqual(
                payload["threads"]["status_writer"]["name"],
                payload["status_writer_thread_name"],
            )
            self.assertEqual(payload["threads"]["registry"][0]["challenge"], "demo")
            self.assertIn("observed", payload["threads"]["registry"][0]["roles"])
            self.assertIn("status_writer", payload["threads"]["registry"][0]["roles"])
            self.assertEqual(payload["stage"], "assessment")
            self.assertEqual(payload["status"], "running")

    def test_run_status_stringifies_non_json_extra_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "demo.status.json"
            marker = Path(tmp) / "marker"

            write_run_status(
                status_path,
                challenge="demo",
                stage="assessment",
                status="running",
                error={"marker": marker},
            )

            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["error"]["marker"], str(marker))

    def test_run_status_core_observability_fields_cannot_be_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "demo.status.json"

            write_run_status(
                status_path,
                challenge="demo",
                stage="assessment",
                status="running",
                schema_version=99,
                pid="bad",
                thread_id="bad",
                thread_name="bad",
                status_writer_thread_id="bad",
                status_writer_thread_name="bad",
                threads={"observed": {"id": "bad", "name": "bad"}},
                updated_at="bad",
            )

            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["challenge"], "demo")
            self.assertEqual(payload["stage"], "assessment")
            self.assertEqual(payload["status"], "running")
            self.assertIsInstance(payload["pid"], int)
            self.assertIsInstance(payload["thread_id"], int)
            self.assertNotEqual(payload["thread_name"], "bad")
            self.assertIsInstance(payload["status_writer_thread_id"], int)
            self.assertNotEqual(payload["status_writer_thread_name"], "bad")
            self.assertNotEqual(payload["threads"]["observed"]["id"], "bad")
            self.assertIn("registry", payload["threads"])
            self.assertNotEqual(payload["updated_at"], "bad")

    def test_monitor_snapshot_tracks_completed_active_and_queued_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            snapshot = build_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha", "beta", "gamma"],
                results=[
                    {
                        "challenge": "alpha",
                        "status": "solved",
                        "solved": True,
                        "status_file": str(logdir / "alpha.status.json"),
                    }
                ],
                batch_start=0,
                active_runs=[
                    {
                        "challenge": "beta",
                        "status_file": "beta.status.json",
                    }
                ],
            )

            states = {
                entry["challenge"]: entry["state"] for entry in snapshot["entries"]
            }
            self.assertEqual(
                states, {"alpha": "completed", "beta": "active", "gamma": "queued"}
            )
            self.assertEqual(snapshot["counts"]["completed"], 1)
            self.assertEqual(snapshot["counts"]["active"], 1)
            self.assertEqual(snapshot["entries"][0]["status_file"], "alpha.status.json")

    def test_monitor_counts_interrupted_separately_from_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = build_monitor_snapshot(
                logdir=Path(tmp),
                challenge_names=["failed", "interrupted"],
                results=[
                    {"challenge": "failed", "status": "failed", "solved": False},
                    {
                        "challenge": "interrupted",
                        "status": "interrupted",
                        "solved": False,
                    },
                ],
                batch_start=0,
                finished=True,
            )

            self.assertEqual(snapshot["counts"]["failed"], 1)
            self.assertEqual(snapshot["counts"]["interrupted"], 1)

    def test_monitor_snapshot_does_not_expose_absolute_logdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            snapshot = build_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
            )

            self.assertEqual(snapshot["logdir"], ".")
            self.assertNotEqual(snapshot["logdir"], str(logdir))

    def test_monitor_snapshot_preserves_active_thread_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            snapshot = build_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {
                        "challenge": "alpha",
                        "status": "active",
                        "stage": "scheduled",
                        "pid": 123,
                        "thread_id": 456,
                        "thread_name": "scheduler",
                        "threads": {
                            "scheduler": {"id": 456, "name": "scheduler"},
                        },
                        "status_file": "alpha.status.json",
                    }
                ],
            )

            active = snapshot["entries"][0]["active"]
            self.assertEqual(active["pid"], 123)
            self.assertEqual(active["thread_id"], 456)
            self.assertEqual(active["threads"]["scheduler"]["name"], "scheduler")

    def test_monitor_counts_active_after_completed_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            snapshot = build_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[{"challenge": "alpha", "status": "failed"}],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )

            self.assertEqual(snapshot["entries"][0]["state"], "completed")
            self.assertEqual(snapshot["counts"]["active"], 0)

    def test_monitor_snapshot_sanitizes_active_run_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp) / "logs"
            outside = Path(tmp) / "outside.status.json"
            snapshot = build_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha", "beta"],
                results=[],
                batch_start=0,
                active_runs=[
                    {
                        "challenge": "alpha",
                        "status_file": str(logdir / "alpha.status.json"),
                    },
                    {
                        "challenge": "beta",
                        "status_file": str(outside),
                    },
                ],
            )

            alpha = snapshot["entries"][0]
            beta = snapshot["entries"][1]
            self.assertEqual(alpha["status_file"], "alpha.status.json")
            self.assertEqual(alpha["active"]["status_file"], "alpha.status.json")
            self.assertIsNone(beta["status_file"])
            self.assertNotIn("status_file", beta["active"])

    def test_monitor_snapshot_sanitizes_queued_default_status_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = build_monitor_snapshot(
                logdir=Path(tmp),
                challenge_names=[
                    "alpha",
                    "../escape",
                    r"..\escape",
                    "javascript:alert(1)",
                ],
                results=[],
                batch_start=0,
            )

            status_files = {
                entry["challenge"]: entry["status_file"]
                for entry in snapshot["entries"]
            }
            self.assertEqual(status_files["alpha"], "alpha.status.json")
            self.assertIsNone(status_files["../escape"])
            self.assertIsNone(status_files[r"..\escape"])
            self.assertIsNone(status_files["javascript:alert(1)"])

    def test_monitor_result_keeps_only_logdir_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            inside = logdir / "artifacts" / "report.md"
            outside = Path(tmp).parent / "outside-report.md"
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "logfile": str(logdir / "alpha.json"),
                    "artifacts": {
                        "run_dir": str(outside),
                        "report_path": str(inside),
                        "compact_markdown_path": str(outside),
                    },
                },
                logdir,
            )

            assert result is not None
            self.assertEqual(result["logfile"], "alpha.json")
            self.assertEqual(result["artifacts"]["report_path"], "artifacts/report.md")
            self.assertNotIn("run_dir", result["artifacts"])
            self.assertNotIn("compact_markdown_path", result["artifacts"])

    def test_monitor_result_exposes_public_rag_status_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "rag": {
                        "enabled": True,
                        "mode": "oracle",
                        "status": "hit",
                        "hit_count": 3,
                        "knowledge_hints": [{"solution_sketch": "raw hint"}],
                        "hit_provenance": [{"challenge_id": "alpha"}],
                    },
                },
                Path(tmp),
            )

            assert result is not None
            self.assertEqual(
                result["rag"],
                {
                    "enabled": True,
                    "status": "hit",
                    "policy": "supplemental_context",
                    "hint_count": 1,
                },
            )

    def test_monitor_result_preserves_public_rag_hint_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "rag": {
                        "enabled": True,
                        "status": "hit",
                        "policy": "supplemental_context",
                        "hint_count": 3,
                    },
                },
                Path(tmp),
            )

            assert result is not None
            self.assertEqual(result["rag"]["hint_count"], 3)

    def test_monitor_result_drops_raw_debug_payloads_and_compacts_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "status": "worker_error",
                    "traceback": "full internal traceback",
                    "raw_response": {"debug": "payload"},
                    "error": {
                        "type": "ValueError",
                        "message": "x" * 500,
                        "traceback": "raw nested traceback",
                    },
                    "runtime_error": {
                        "type": "RuntimeError",
                        "message": "runtime failed",
                        "traceback": "raw runtime traceback",
                    },
                },
                Path(tmp),
            )

            assert result is not None
            self.assertNotIn("traceback", result)
            self.assertNotIn("raw_response", result)
            self.assertEqual(result["error"]["type"], "ValueError")
            self.assertLessEqual(len(result["error"]["message"]), 360)
            self.assertNotIn("traceback", result["error"])
            self.assertEqual(
                result["runtime_error"],
                {
                    "type": "RuntimeError",
                    "message": "runtime failed",
                },
            )

    def test_monitor_result_rejects_parent_traversal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "logfile": "../alpha.json",
                    "artifacts": {
                        "report_path": "nested/../report.md",
                        "run_dir": "nested/..",
                    },
                },
                Path(tmp),
            )

            assert result is not None
            self.assertNotIn("logfile", result)
            self.assertNotIn("report_path", result["artifacts"])
            self.assertNotIn("run_dir", result["artifacts"])

    def test_monitor_result_rejects_backslash_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "logfile": r"..\alpha.json",
                    "artifacts": {"report_path": r"nested\report.md"},
                },
                Path(tmp),
            )

            assert result is not None
            self.assertNotIn("logfile", result)
            self.assertNotIn("report_path", result["artifacts"])

    def test_monitor_result_rejects_uri_scheme_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = monitor_result(
                {
                    "challenge": "alpha",
                    "logfile": "javascript:alert(1)",
                    "artifacts": {
                        "report_path": "data:text/html,<script>alert(1)</script>",
                    },
                },
                Path(tmp),
            )

            assert result is not None
            self.assertNotIn("logfile", result)
            self.assertNotIn("report_path", result["artifacts"])

    def test_status_payload_exposes_only_monitor_safe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp) / "logs"
            outside = Path(tmp) / "outside" / "report.md"
            status_path = logdir / "alpha.status.json"

            write_run_status(
                status_path,
                challenge="alpha",
                stage="assessment",
                status="running",
                logfile=str(logdir / "alpha.json"),
                artifacts={
                    "report_path": str(logdir / "artifacts" / "alpha" / "report.md"),
                    "compact_markdown_path": str(outside),
                },
            )

            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["logfile"], "alpha.json")
            self.assertEqual(
                payload["artifacts"]["report_path"], "artifacts/alpha/report.md"
            )
            self.assertNotIn("compact_markdown_path", payload["artifacts"])

    def test_sanitize_monitor_paths_handles_nested_dicts_and_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = sanitize_monitor_paths(
                {
                    "items": [
                        {"status_file": str(root / "alpha.status.json")},
                        {"status_file": "javascript:alert(1)"},
                    ],
                    "metadata": {"count": 2},
                },
                root,
            )

            self.assertEqual(payload["items"][0]["status_file"], "alpha.status.json")
            self.assertNotIn("status_file", payload["items"][1])
            self.assertEqual(payload["metadata"]["count"], 2)

    def test_sanitize_monitor_paths_filters_plural_path_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = Path(tmp).parent / "outside.txt"
            payload = sanitize_monitor_paths(
                {
                    "artifact_paths": [
                        str(root / "inside.txt"),
                        str(outside),
                        "../escape.txt",
                        "javascript:alert(1)",
                    ],
                    "cache_dirs": [
                        str(root / "cache"),
                        r"..\cache",
                    ],
                },
                root,
            )

            self.assertEqual(payload["artifact_paths"], ["inside.txt"])
            self.assertEqual(payload["cache_dirs"], ["cache"])

    def test_write_batch_monitor_creates_static_html_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)

            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )

            self.assertEqual(html_path, logdir / MONITOR_HTML_NAME)
            self.assertTrue((logdir / MONITOR_HTML_NAME).exists())
            payload = json.loads(
                (logdir / MONITOR_JSON_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["entries"][0]["state"], "active")
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("_batch_monitor.json", html)
            self.assertIn("function escapeHtml", html)
            self.assertIn("function safeLink", html)
            self.assertIn("function isRelativeSafePath", html)
            self.assertIn("new URL(raw, window.location.href)", html)
            self.assertIn('window.location.protocol === "file:"', html)
            self.assertIn('url.protocol !== "file:"', html)
            self.assertIn('!raw.startsWith("/")', html)
            self.assertIn(r'!raw.includes("\\")', html)
            self.assertIn('!raw.endsWith("/..")', html)
            self.assertIn("function threadSummary", html)
            self.assertIn("threads = live.threads || {}", html)
            self.assertIn("activeThreads = active.threads || {}", html)
            self.assertIn('structured.push(labeledThread("observed"', html)
            self.assertIn("statusWriter: threads.status_writer", html)
            self.assertNotIn("activeThreads.scheduler", html)
            self.assertIn("function threadRegistrySummary", html)
            self.assertIn("threads.registry", html)
            self.assertIn("writerThreadId", html)
            self.assertIn("writerThreadName", html)
            self.assertIn("eventThreadId", html)
            self.assertIn("eventThreadName", html)
            self.assertIn("function ageSeconds", html)
            self.assertIn("heartbeat", html)
            self.assertIn("stateUpdatedAt", html)
            self.assertIn("latestEvent", html)
            self.assertIn("latestEventLevel", html)
            self.assertIn("latestEventAt", html)
            self.assertIn("_status_error", html)
            self.assertIn("statusError", html)
            self.assertIn('if (row.statusError) return "stale"', html)
            self.assertIn("status read failed", html)
            self.assertIn(
                "runtimeError = live.runtime_error || result.runtime_error", html
            )
            self.assertIn("runError = live.error || result.error", html)
            self.assertIn("function fmtTokenUsage", html)
            self.assertIn("function sumTokenUsage", html)
            self.assertIn("function countEventLevels", html)
            self.assertIn("function countRagStatus", html)
            self.assertIn("function firstNonEmptyObject", html)
            self.assertIn("function firstPresent", html)
            self.assertIn("function fmtRagKnowledge", html)
            self.assertIn("function metricNumber", html)
            self.assertIn("function fmtStateMetrics", html)
            self.assertIn("tokenUsage = live.token_usage || result.token_usage", html)
            self.assertIn("runtimeSec: firstPresent(result.runtime_sec", html)
            self.assertIn('["LLM Calls", tokenTotals.llmCalls]', html)
            self.assertIn('["LLM Tokens", tokenTotals.totalTokens]', html)
            self.assertIn('["Warnings", eventLevels.warnings]', html)
            self.assertIn('["Errors", eventLevels.errors]', html)
            self.assertIn('["RAG On", ragTotals.enabled]', html)
            self.assertIn('["RAG Hits", ragTotals.hits]', html)
            self.assertIn('["RAG Hints", ragTotals.hints]', html)
            self.assertIn("function pollStatusText", html)
            self.assertIn("browser refresh", html)
            self.assertIn("polling ${(refreshMs / 1000).toFixed(0)}s", html)
            self.assertIn('["Stale", staleRows]', html)
            self.assertIn("Monitor read failed", html)

    def test_generated_monitor_script_does_not_read_queued_status_files(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
            )
            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_queued_monitor.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: "",
      innerHTML: "",
      textContent: "",
      addEventListener() {}
    });
  }
  return elements.get(id);
}

const fetched = [];
global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  fetched.push(String(requestPath));
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("alpha"), rows);
  assert(rows.includes("queued"), rows);
  assert(!rows.includes("status read failed"), rows);
  assert.deepStrictEqual(fetched, ["_batch_monitor.json"]);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_write_batch_monitor_snapshot_updates_json_without_rewriting_html(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = logdir / MONITOR_HTML_NAME
            write_text(html_path, "existing html")

            json_path = write_batch_monitor_snapshot(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(json_path, logdir / MONITOR_JSON_NAME)
            self.assertEqual(payload["entries"][0]["state"], "active")
            self.assertEqual(html_path.read_text(encoding="utf-8"), "existing html")

    def test_generated_monitor_script_is_valid_javascript(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
            )
            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")

            result = subprocess.run(
                [node, "--check", str(script_path)],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_live_status_rows(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha", "beta"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"},
                    {"challenge": "beta", "status_file": "beta.status.json"},
                ],
            )
            status_path = logdir / "alpha.status.json"
            write_run_status(
                status_path,
                challenge="alpha",
                stage="assessment",
                status="running",
                worker="analysis-worker",
                current_todo={
                    "status": "running",
                    "todo_id": "todo-alpha",
                    "goal": "Analyze parser state",
                },
                latest_event={
                    "event_type": "worker_progress",
                    "message": "tool running",
                    "thread_id": 321,
                    "thread_name": "worker-thread",
                },
                token_usage={
                    "llm_calls": 2,
                    "prompt_tokens": 120,
                    "completion_tokens": 225,
                    "total_tokens": 345,
                },
                state_metrics={
                    "round_count": 3,
                    "todo_count": 5,
                    "open_todo_count": 1,
                    "evidence_count": 4,
                    "flag_candidates": 0,
                    "todo_status_counts": {
                        "completed": 2,
                        "pending": 1,
                        "running": 1,
                    },
                },
            )
            status_payload = json.loads(status_path.read_text(encoding="utf-8"))
            status_payload["thread_id"] = 123
            status_payload["thread_name"] = "observed-thread"
            status_payload["status_writer_thread_id"] = 456
            status_payload["status_writer_thread_name"] = "writer-thread"
            status_payload["threads"] = {
                "observed": {"id": 123, "name": "observed-thread"},
                "status_writer": {"id": 456, "name": "writer-thread"},
                "latest_event": {"id": 321, "name": "worker-thread"},
                "registry": [
                    {
                        "id": 123,
                        "name": "observed-thread",
                        "pid": status_payload["pid"],
                        "challenge": "alpha",
                        "stage": "assessment",
                        "status": "running",
                        "roles": ["observed"],
                        "current_todo": {
                            "todo_id": "todo-alpha",
                            "status": "running",
                            "goal": "Analyze parser state",
                        },
                    },
                    {
                        "id": 456,
                        "name": "writer-thread",
                        "pid": status_payload["pid"],
                        "challenge": "alpha",
                        "stage": "assessment",
                        "status": "running",
                        "roles": ["status_writer"],
                    },
                    {
                        "id": 321,
                        "name": "worker-thread",
                        "pid": status_payload["pid"],
                        "challenge": "alpha",
                        "stage": "assessment",
                        "status": "running",
                        "roles": ["latest_event"],
                        "latest_event": {
                            "level": "WARNING",
                            "event_type": "worker_progress",
                        },
                    },
                ],
            }
            status_payload["latest_event"]["level"] = "WARNING"
            status_payload["latest_event"]["timestamp"] = "2026-05-23T00:00:00Z"
            status_payload["rag"] = {
                "enabled": True,
                "status": "hit",
                "policy": "supplemental_context",
                "hint_count": 2,
            }
            status_path.write_text(json.dumps(status_payload), encoding="utf-8")

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_monitor.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: "",
      innerHTML: "",
      textContent: "",
      addEventListener() {}
    });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  try {
    const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
    return { ok: true, status: 200, json: async () => JSON.parse(text) };
  } catch (_err) {
    return { ok: false, status: 404, json: async () => ({}) };
  }
};
global.setInterval = () => 0;
Date.now = () => Date.parse("2026-05-23T00:00:05Z");

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  const stats = element("stats").innerHTML;
  const updated = element("updated").textContent;
  assert(!updated.startsWith("Monitor read failed"), updated);
  assert(rows.includes("alpha"), rows);
  assert(rows.includes("observed-thread"), rows);
  assert(rows.includes("writer-thread"), rows);
  assert(rows.includes("worker-thread"), rows);
  assert(rows.includes("analysis-worker"), rows);
  assert(rows.includes("todo-alpha"), rows);
  assert(rows.includes("Analyze parser state"), rows);
  assert(rows.includes("knowledge supplemental_context hints 2"), rows);
  assert(rows.includes("LLM 2 calls / 345 tok"), rows);
  assert(rows.includes("rounds 3 / todos 5 / open 1 / evidence 4 / flags 0 / todo completed=2,pending=1,running=1"), rows);
  assert(!rows.includes('{"completed"'), rows);
            assert(stats.includes("LLM Calls"), stats);
            assert(stats.includes("<strong>2</strong>"), stats);
  assert(stats.includes("LLM Tokens"), stats);
  assert(stats.includes("<strong>345</strong>"), stats);
  assert(stats.includes("Stale"), stats);
  assert(stats.includes("<strong>1</strong>"), stats);
  assert(stats.includes("<span>Warnings</span><strong>1</strong>"), stats);
  assert(stats.includes("<span>Errors</span><strong>0</strong>"), stats);
  assert(stats.includes("<span>Interrupted</span><strong>0</strong>"), stats);
  assert(stats.includes("<span>RAG On</span><strong>1</strong>"), stats);
  assert(stats.includes("<span>RAG Hits</span><strong>1</strong>"), stats);
  assert(stats.includes("<span>RAG Hints</span><strong>2</strong>"), stats);
            assert(rows.includes("WARNING worker_progress 5s ago: tool running"), rows);
            assert(rows.includes("beta"), rows);
            assert(rows.includes("status read failed"), rows);
            assert(updated.includes("browser refresh"), updated);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_preserves_zero_runtime(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            status_path = logdir / "zero.status.json"
            write_run_status(
                status_path,
                challenge="zero",
                stage="complete",
                status="failed",
                runtime_sec=5,
            )
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["zero"],
                results=[
                    {
                        "challenge": "zero",
                        "status": "failed",
                        "solved": False,
                        "runtime_sec": 0,
                        "status_file": str(status_path),
                        "run_id": "run-zero",
                    }
                ],
                batch_start=0,
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_zero_runtime.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = { location: { href: `file://${process.cwd()}/_batch_monitor.html`, protocol: "file:" } };
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("0.0s"), rows);
  assert(!rows.includes("5.0s"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_prefers_final_unsolved_result(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            status_path = logdir / "final.status.json"
            write_run_status(
                status_path,
                challenge="final",
                stage="complete",
                status="solved",
                solved=True,
            )
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["final"],
                results=[
                    {
                        "challenge": "final",
                        "status": "failed",
                        "solved": False,
                        "status_file": str(status_path),
                        "run_id": "run-final",
                    }
                ],
                batch_start=0,
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_final_unsolved.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = { location: { href: `file://${process.cwd()}/_batch_monitor.html`, protocol: "file:" } };
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("badge failed"), rows);
  assert(!rows.includes("badge solved"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_interrupted_badge(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            status_path = logdir / "cancelled.status.json"
            write_run_status(
                status_path,
                challenge="cancelled",
                stage="complete",
                status="interrupted",
                solved=False,
            )
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["cancelled"],
                results=[
                    {
                        "challenge": "cancelled",
                        "status": "interrupted",
                        "solved": False,
                        "status_file": str(status_path),
                        "run_id": "run-cancelled",
                    }
                ],
                batch_start=0,
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_interrupted.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = { location: { href: `file://${process.cwd()}/_batch_monitor.html`, protocol: "file:" } };
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  const stats = element("stats").innerHTML;
  assert(rows.includes("badge interrupted"), rows);
  assert(!rows.includes("badge failed"), rows);
  assert(stats.includes("<span>Failed</span><strong>0</strong>"), stats);
  assert(stats.includes("<span>Interrupted</span><strong>1</strong>"), stats);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_unsolved_terminal_status_as_failed(
        self,
    ) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            status_path = logdir / "exhausted.status.json"
            write_run_status(
                status_path,
                challenge="exhausted",
                stage="complete",
                status="unsolved_exhausted",
                solved=False,
            )
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["exhausted"],
                results=[
                    {
                        "challenge": "exhausted",
                        "status": "unsolved_exhausted",
                        "solved": False,
                        "status_file": str(status_path),
                        "run_id": "run-exhausted",
                    }
                ],
                batch_start=0,
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_unsolved_terminal.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = { location: { href: `file://${process.cwd()}/_batch_monitor.html`, protocol: "file:" } };
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  const stats = element("stats").innerHTML;
  assert(rows.includes("badge failed"), rows);
  assert(!rows.includes("badge queued"), rows);
  assert(rows.includes("unsolved_exhausted"), rows);
  assert(stats.includes("<span>Failed</span><strong>1</strong>"), stats);
  assert(stats.includes("<span>Interrupted</span><strong>0</strong>"), stats);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_runtime_errors(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )
            write_run_status(
                logdir / "alpha.status.json",
                challenge="alpha",
                stage="complete",
                status="failed",
                runtime_error={
                    "type": "RuntimeError",
                    "message": "router crashed before finalizing state",
                },
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_runtime_error.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: "",
      innerHTML: "",
      textContent: "",
      addEventListener() {}
    });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("RuntimeError"), rows);
  assert(rows.includes("router crashed before finalizing state"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_prefers_message_over_completed_todo(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )
            write_run_status(
                logdir / "alpha.status.json",
                challenge="alpha",
                stage="assessment",
                status="running",
                message="[cycle 3] planning next todos",
                current_todo={
                    "status": "completed",
                    "todo_id": "todo-done",
                    "goal": "Finished artifact triage",
                },
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_completed_todo.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("[cycle 3] planning next todos"), rows);
  assert(!rows.includes("todo-done"), rows);
  assert(!rows.includes("Finished artifact triage"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_event_source_threads(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )
            status_path = logdir / "alpha.status.json"
            write_run_status(
                status_path,
                challenge="alpha",
                stage="assessment",
                status="running",
            )
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["threads"]["registry"] = [
                {
                    "id": 10,
                    "name": "worker-a",
                    "pid": status["pid"],
                    "challenge": "alpha",
                    "stage": "assessment",
                    "status": "running",
                    "roles": ["event_source"],
                    "current_todo": {
                        "todo_id": "todo-a",
                        "status": "running",
                        "worker": "script-worker",
                    },
                    "latest_event": {
                        "level": "INFO",
                        "event_type": "script_exec",
                        "message": "running bounded solver",
                    },
                },
                {
                    "id": 11,
                    "name": "worker-b",
                    "pid": status["pid"],
                    "challenge": "alpha",
                    "stage": "assessment",
                    "status": "running",
                    "roles": ["event_source"],
                    "current_todo": {
                        "todo_id": "todo-b",
                        "status": "running",
                        "worker": "validator",
                    },
                    "latest_event": {
                        "level": "WARNING",
                        "event_type": "validation",
                        "message": "candidate rejected",
                    },
                },
            ]
            status_path.write_text(json.dumps(status), encoding="utf-8")

            match = re.search(
                r"<script>\s*(.*?)\s*</script>",
                html_path.read_text(encoding="utf-8"),
                flags=re.DOTALL,
            )
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_event_threads.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, { value: "", innerHTML: "", textContent: "", addEventListener() {} });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("event_source worker-a (10) | running | running todo-a -&gt; script-worker | INFO script_exec: running bounded solver"), rows);
  assert(rows.includes("event_source worker-b (11) | running | running todo-b -&gt; validator | WARNING validation: candidate rejected"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_monitor_script_renders_status_errors(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")

        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
                active_runs=[
                    {"challenge": "alpha", "status_file": "alpha.status.json"}
                ],
            )
            write_run_status(
                logdir / "alpha.status.json",
                challenge="alpha",
                stage="load_challenge",
                status="load_error",
                error={
                    "type": "ValueError",
                    "message": "challenge metadata could not be loaded",
                },
            )

            html = html_path.read_text(encoding="utf-8")
            match = re.search(r"<script>\s*(.*?)\s*</script>", html, flags=re.DOTALL)
            self.assertIsNotNone(match)
            assert match is not None
            script_path = logdir / "monitor.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            harness_path = logdir / "render_status_error.js"
            harness_path.write_text(
                """
const assert = require("assert");
const fs = require("fs/promises");
const path = require("path");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: "",
      innerHTML: "",
      textContent: "",
      addEventListener() {}
    });
  }
  return elements.get(id);
}

global.document = { getElementById: element };
global.window = {
  location: {
    href: `file://${process.cwd()}/_batch_monitor.html`,
    protocol: "file:"
  }
};
global.fetch = async (requestPath) => {
  const text = await fs.readFile(path.join(process.cwd(), String(requestPath)), "utf8");
  return { ok: true, status: 200, json: async () => JSON.parse(text) };
};
global.setInterval = () => 0;

(async () => {
  const script = await fs.readFile(process.argv[2], "utf8");
  eval(script);
  for (let attempt = 0; attempt < 20 && !element("rows").innerHTML; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const rows = element("rows").innerHTML;
  assert(rows.includes("ValueError"), rows);
  assert(rows.includes("challenge metadata could not be loaded"), rows);
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
""",
                encoding="utf-8",
            )

            result = subprocess.run(
                [node, str(harness_path), str(script_path)],
                cwd=logdir,
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_write_batch_monitor_refreshes_existing_generated_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logdir = Path(tmp)
            html_path = logdir / MONITOR_HTML_NAME
            write_text(html_path, "old template")

            write_batch_monitor(
                logdir=logdir,
                challenge_names=["alpha"],
                results=[],
                batch_start=0,
            )

            html = html_path.read_text(encoding="utf-8")
            self.assertIn("Killchain Batch Monitor", html)
            self.assertNotEqual(html, "old template")


if __name__ == "__main__":
    unittest.main()
