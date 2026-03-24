from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

from pydantic import BaseModel

from run_mutil_killchain import derive_authorized_scope, derive_objective
from nyuctf_mutil_killchain.agents.artifact import ArtifactTriageAgent
from nyuctf_mutil_killchain.agents.base import WorkerAgent, infer_web_urls, infer_web_urls_from_banners
from nyuctf_mutil_killchain.llm.client import OpenAICompatibleLLMClient
from nyuctf_mutil_killchain.orchestrator.loop import Orchestrator
from nyuctf_mutil_killchain.orchestrator.planner import PlannerDecision, TaskPlanner
from nyuctf_mutil_killchain.state import EvidenceRecord, GlobalState, RunStatus, Service, Task, WorkerReport
from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest
from nyuctf_mutil_killchain.tools.plugins import archive_triage, artifact_triage, computation_analysis, runtime_probe, source_review


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
    def test_derive_authorized_scope_skips_ambiguous_bare_host_for_local_rev_challenge(self) -> None:
        challenge = SimpleNamespace(
            server_name="rev.chal.csaw.io",
            server_type=None,
            port=None,
            files=["checker.py"],
            category="rev",
            challenge={},
        )

        scope = derive_authorized_scope(challenge)

        self.assertEqual(scope, [])

    def test_derive_objective_prefers_local_artifact_analysis_without_scope(self) -> None:
        challenge = SimpleNamespace(
            name="checker",
            description="Reverse the transform.",
            category="rev",
            files=["checker.py"],
        )

        objective = derive_objective(challenge, [])

        self.assertIn("Inspect the bundled challenge files first", objective)
        self.assertNotIn("Enumerate the reachable challenge surface", objective)

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

    def test_artifact_triage_schedules_computation_analysis_for_rev_sources(self) -> None:
        parsed = SimpleNamespace(
            summary="Artifact triage completed.",
            output_context={
                "files_root": "/tmp/ctf",
                "binary_files": [],
                "archive_files": [],
                "database_files": [],
                "pcap_files": [],
                "repo_paths": [],
                "web_source_files": ["checker.py"],
                "script_files": ["checker.py"],
                "flag_candidates": [],
            },
            asset_updates=[],
            finding_updates=[],
            credential_updates=[],
            network_updates=[],
            notes=[],
        )
        bundle = SimpleNamespace(
            parsed=parsed,
            evidence=EvidenceRecord(
                task_id="task-demo",
                tool_name="artifact_triage",
                mode="local_command",
                summary="Artifact triage completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, task_id, request):
                self.task_id = task_id
                self.request = request
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "rev", "files": ["checker.py"]}},
        )
        agent = ArtifactTriageAgent(execution_plane=FakeExecutionPlane())
        report = agent.run(
            Task(
                title="Inventory challenge files",
                description="Enumerate bundled files.",
                task_type="artifact.triage",
                input_context={"files_root": "/tmp/ctf"},
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("artifact.source_review", task_types)
        self.assertIn("artifact.runtime_probe", task_types)
        self.assertIn("artifact.computation_analysis", task_types)

    def test_computation_analysis_recovers_checker_style_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "checker.py").write_text(
                (
                    "def up(x):\n"
                    "    x = [f\"{ord(x[i]) << 1:08b}\" for i in range(len(x))]\n"
                    "    return ''.join(x)\n\n"
                    "def down(x):\n"
                    "    x = ''.join(['1' if x[i] == '0' else '0' for i in range(len(x))])\n"
                    "    return x\n\n"
                    "def right(x,d):\n"
                    "    x = x[d:] + x[0:d]\n"
                    "    return x\n\n"
                    "def left(x,d):\n"
                    "    x = right(x,len(x)-d)\n"
                    "    return x[::-1]\n\n"
                    "def encode(plain):\n"
                    "    d = 24\n"
                    "    x = up(plain)\n"
                    "    x = right(x,d)\n"
                    "    x = down(x)\n"
                    "    x = left(x,d)\n"
                    "    return x\n\n"
                    "def main():\n"
                    "    encoded = \"1010000011011000101011001001010011011000100001001000100010000010100001001010010010101100111011001001000010001100101111001110010011001100\"\n"
                    "    print(encoded)\n\n"
                    "if __name__ == \"__main__\":\n"
                    "    main()\n"
                ),
                encoding="utf-8",
            )

            request = ToolExecutionRequest(
                tool_name="computation_analysis",
                metadata={
                    "files_root": str(root),
                    "source_files": ["checker.py"],
                    "max_files": 4,
                    "flag_format": "flag{...}",
                },
            )
            argv = [sys.executable, *computation_analysis.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("flag{demo_worker}", output_context["flag_candidates"])

    def test_runtime_probe_extracts_blob_candidates_from_script_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "emit.py").write_text(
                (
                    "print('1010000011011000101011001001010011011000100001001000100010000010')\n"
                ),
                encoding="utf-8",
            )

            request = ToolExecutionRequest(
                tool_name="runtime_probe",
                metadata={
                    "files_root": str(root),
                    "source_files": ["emit.py"],
                    "max_files": 4,
                    "flag_format": "flag{...}",
                },
            )
            argv = [sys.executable, *runtime_probe.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("emit.py", output_context["executed_scripts"])
            self.assertIn(
                "1010000011011000101011001001010011011000100001001000100010000010",
                output_context["blob_candidates"],
            )

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
