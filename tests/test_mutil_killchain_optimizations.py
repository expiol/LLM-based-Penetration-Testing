from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from pydantic import BaseModel

from nyuctf_mutil_killchain.agents.base import WorkerAgent, infer_web_urls, infer_web_urls_from_banners
from nyuctf_mutil_killchain.llm.client import OpenAICompatibleLLMClient
from nyuctf_mutil_killchain.orchestrator.loop import Orchestrator
from nyuctf_mutil_killchain.orchestrator.planner import PlannerDecision, TaskPlanner
from nyuctf_mutil_killchain.state import GlobalState, RunStatus, Service, Task, WorkerReport
from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest
from nyuctf_mutil_killchain.tools.plugins import archive_triage, artifact_triage, source_review


class LLMProbe(BaseModel):
    summary: str


class StaticPlanner(TaskPlanner):
    def plan(self, state: GlobalState) -> PlannerDecision:
        return PlannerDecision(summary="Planner proposed 0 task(s).")


class ChainedWorker(WorkerAgent):
    name = "chained-worker"
    supported_task_types = ("demo.",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary="Completed demo task.",
            new_tasks=[
                Task(
                    title="Follow-up demo task",
                    description="Remains queued for the next cycle.",
                    task_type="demo.followup",
                    priority=40,
                )
            ],
        )


class MultiKillchainOptimizationTests(unittest.TestCase):
    def test_infer_web_urls_ignores_non_http_high_port_service(self) -> None:
        urls = infer_web_urls(
            hostname="target.local",
            ip_address=None,
            services=[Service(port=5000, protocol="tcp", name="upnp")],
        )
        self.assertEqual(urls, [])

    def test_infer_web_urls_defers_ambiguous_http_alt_without_fingerprint(self) -> None:
        urls = infer_web_urls(
            hostname="target.local",
            ip_address=None,
            services=[Service(port=8000, protocol="tcp", name="http-alt")],
        )
        self.assertEqual(urls, [])

    def test_infer_web_urls_accepts_http_alt_with_server_fingerprint(self) -> None:
        urls = infer_web_urls(
            hostname="target.local",
            ip_address=None,
            services=[Service(port=8000, protocol="tcp", name="http-alt", product="nginx")],
        )
        self.assertEqual(urls, ["http://target.local:8000"])

    def test_infer_web_urls_from_banners_detects_http_targets(self) -> None:
        urls = infer_web_urls_from_banners(
            hostname="target.local",
            ip_address=None,
            banner_hits={"8000": "HTTP/1.1 200 OK\r\nServer: test\r\n"},
        )
        self.assertEqual(urls, ["http://target.local:8000"])

    def test_llm_client_accepts_fenced_json_payloads(self) -> None:
        client = OpenAICompatibleLLMClient(
            base_url="https://example.invalid/v1",
            model="fake-model",
            api_key="fake-key",
            transport=lambda *_args: {
                "choices": [
                    {
                        "message": {
                            "content": "```json\n{\"summary\": \"ok\"}\n```",
                        }
                    }
                ]
            },
        )

        result = client.generate_json(
            system_prompt="Return JSON",
            user_prompt="Return JSON",
            schema=LLMProbe,
        )
        self.assertEqual(result.summary, "ok")

    def test_source_review_reads_zip_member_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            archive_path = root / "bundle.zip"
            with zipfile.ZipFile(archive_path, "w") as zf:
                zf.writestr(
                    "app.py",
                    "API_KEY = 'demo'\nroute = '/flag'\nprint('flag{archive-ok}')\n",
                )

            request = ToolExecutionRequest(
                tool_name="source_review",
                metadata={
                    "files_root": str(root),
                    "source_files": ["bundle.zip:app.py"],
                    "max_files": 4,
                },
            )
            argv = [sys.executable, *source_review.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("bundle.zip:app.py", output_context["inspected_sources"])
            self.assertIn("/flag", output_context["interesting_routes"])
            self.assertIn("flag{archive-ok}", output_context["flag_candidates"])

    def test_artifact_triage_classifies_verilog_as_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "ncore_tb.v").write_text("module top; endmodule\n", encoding="utf-8")

            request = ToolExecutionRequest(
                tool_name="artifact_triage",
                metadata={
                    "files_root": str(root),
                    "challenge_files": ["ncore_tb.v"],
                    "max_files": 10,
                },
            )
            argv = [sys.executable, *artifact_triage.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("ncore_tb.v", output_context["web_source_files"])

    def test_archive_triage_detects_rust_and_template_members_as_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            archive_path = root / "bundle.zip"
            with zipfile.ZipFile(archive_path, "w") as zf:
                zf.writestr(
                    "dist/src/main.rs",
                    'fn main() { println!("flag{archive-rust}"); }\n',
                )
                zf.writestr(
                    "dist/templates/login.html.tera",
                    '<a href="/login">Login</a>\n',
                )

            request = ToolExecutionRequest(
                tool_name="archive_triage",
                metadata={
                    "files_root": str(root),
                    "archive_files": ["bundle.zip"],
                    "max_files": 4,
                },
            )
            argv = [sys.executable, *archive_triage.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn(
                "bundle.zip:dist/src/main.rs",
                output_context["qualified_source_like_members"],
            )
            self.assertIn(
                "bundle.zip:dist/templates/login.html.tera",
                output_context["qualified_source_like_members"],
            )
            self.assertIn("flag{archive-rust}", output_context["flag_candidates"])

    def test_orchestrator_marks_stopped_when_cycle_budget_exhausted(self) -> None:
        state = GlobalState(objective="demo")
        state.queue_task(
            Task(
                title="Initial demo task",
                description="Seeds a follow-up task.",
                task_type="demo.initial",
                priority=50,
            )
        )
        events: list[str] = []
        orchestrator = Orchestrator(
            state=state,
            workers=[ChainedWorker()],
            planner=StaticPlanner(),
            emit=events.append,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.STOPPED)
        self.assertIn(
            "Max cycle budget (1) exhausted with 1 open task(s) remaining.",
            final_state.notes,
        )
        self.assertIn(
            "[cycle 1] max cycles exhausted — 1 task(s) still open",
            events,
        )


if __name__ == "__main__":
    unittest.main()
