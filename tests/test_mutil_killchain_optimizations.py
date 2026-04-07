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
from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_cve_probe_task,
    build_http_path_probe_task,
    infer_web_urls,
    infer_web_urls_from_banners,
    normalize_probe_paths,
)
from nyuctf_mutil_killchain.agents.credential import CredentialHuntAgent
from nyuctf_mutil_killchain.agents.exploit import CredentialExploitAgent, WebPwnExploitAgent
from nyuctf_mutil_killchain.agents.exploit_reasoning import ExploitReasoningAgent
from nyuctf_mutil_killchain.agents.enrichment import WebPathProbeAgent
from nyuctf_mutil_killchain.agents.flag import FlagValidationAgent
from nyuctf_mutil_killchain.agents.llm_guidance import FormProbeGuidance, StageAnalysisGuidance
from nyuctf_mutil_killchain.agents.source_review import SourceReviewAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.agents.web_form import WebFormProbeAgent
from nyuctf_mutil_killchain.llm.client import OpenAICompatibleLLMClient, StaticLLMClient
from nyuctf_mutil_killchain.orchestrator.loop import Orchestrator
from nyuctf_mutil_killchain.orchestrator.planner import HeuristicPlanner, PlannerDecision, TaskPlanner
from nyuctf_mutil_killchain.orchestrator.router import LLMWorkerRouter
from nyuctf_mutil_killchain.state import (
    Asset,
    AssetKind,
    Credential,
    EvidenceRecord,
    Finding,
    GlobalState,
    RunStatus,
    Service,
    Task,
    WorkerReport,
)
from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest
from nyuctf_mutil_killchain.tools.plugins import (
    archive_triage,
    artifact_triage,
    computation_analysis,
    credential_login_probe,
    credential_harvest,
    ctf_exploit_probe,
    flag_harvest,
    http_content,
    http_form_probe,
    runtime_probe,
    source_review,
)


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


class RoutedSourceWorker(WorkerAgent):
    supported_task_types = ("artifact.source_review",)
    required_context_keys = ("source_files",)

    def __init__(self, *, name: str, score: int = 0) -> None:
        super().__init__(llm_client=None, execution_plane=None)
        self.name = name
        self._score = score

    def routing_score(self, task: Task, state: GlobalState) -> int:
        del task, state
        return self._score

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=f"{self.name} handled the routed task.",
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

    def test_llm_client_coerces_wrapped_payloads_and_missing_summary(self) -> None:
        client = OpenAICompatibleLLMClient(
            base_url="https://example.invalid/v1",
            model="fake-model",
            api_key="fake-key",
            transport=lambda *_args: {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "stageAnalysis": {
                                        "interestingRoutes": ["/cgi-bin/file.pl"],
                                        "flagEvidence": ["flag{wrapped-json}"],
                                        "manualChecks": ["Inspect the CGI upload flow."],
                                    }
                                }
                            ),
                        }
                    }
                ]
            },
        )

        result = client.generate_json(
            system_prompt="Return JSON",
            user_prompt="Return JSON",
            schema=StageAnalysisGuidance,
        )
        self.assertIn("/cgi-bin/file.pl", result.interesting_paths)
        self.assertIn("flag{wrapped-json}", result.grounded_flag_candidates)
        self.assertIn("Inspect the CGI upload flow.", result.manual_checks)
        self.assertTrue(result.summary)

    def test_normalize_probe_paths_ignores_freeform_findings(self) -> None:
        paths = normalize_probe_paths(
            [
                "Web assessment for http://web.chal.csaw.io:8000 (HTTP 200). 3 security header issue(s) detected.",
                "http://web.chal.csaw.io:8000/cgi-bin/file.pl?cat%20%2fflag%20|",
                "/admin",
                "cgi-bin/forms.pl",
            ]
        )

        self.assertEqual(
            paths,
            ["/cgi-bin/file.pl?cat%20%2fflag%20|", "/admin", "/cgi-bin/forms.pl"],
        )

    def test_http_content_marks_cgi_links_as_interesting(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "index.html").write_text(
                (
                    "<html><body>"
                    '<a href="/cgi-bin/hello.pl">Hello</a>'
                    '<a href="/cgi-bin/forms.pl">Forms</a>'
                    '<a href="/cgi-bin/file.pl">Files</a>'
                    "</body></html>"
                ),
                encoding="utf-8",
            )
            request = ToolExecutionRequest(
                tool_name="local_http_content",
                metadata={
                    "asset_id": "web-1",
                    "base_url": (root / "index.html").resolve().as_uri(),
                },
            )
            argv = [sys.executable, *http_content.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)

            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("/cgi-bin/file.pl", output_context["links"])
            self.assertTrue(
                any(link.endswith("/cgi-bin/file.pl") for link in output_context["interesting_links"])
            )

    def test_planner_requeues_cve_probe_when_new_seed_paths_appear(self) -> None:
        planner = HeuristicPlanner()
        state = GlobalState(objective="demo", metadata={"challenge": {"category": "web"}})
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
                services=[Service(port=8080, protocol="tcp", name="http")],
            )
        )
        state.upsert_finding(
            Finding(
                finding_id="finding-initial",
                title="Admin route exposed",
                severity="medium",
                description="Found /admin.",
                asset_refs=["web-1"],
                evidence_refs=["/admin"],
            )
        )

        first_decision = planner.plan(state)
        first_task = next(task for task in first_decision.tasks if task.task_type == "exploit.cve_probe")
        state.task_chain.add_task(first_task.to_task())

        state.upsert_finding(
            Finding(
                finding_id="finding-cgi",
                title="CGI upload route exposed",
                severity="medium",
                description="Found /cgi-bin/file.pl.",
                asset_refs=["web-1"],
                evidence_refs=["/cgi-bin/file.pl"],
            )
        )

        second_decision = planner.plan(state)
        second_task = next(task for task in second_decision.tasks if task.task_type == "exploit.cve_probe")

        self.assertIn("/cgi-bin/file.pl", second_task.input_context["seed_paths"])
        self.assertNotEqual(first_task.dedupe_key, second_task.dedupe_key)

    def test_planner_waits_for_grounded_web_context_before_initial_cve_probe(self) -> None:
        planner = HeuristicPlanner()
        state = GlobalState(objective="demo", metadata={"challenge": {"category": "web"}})
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
                services=[Service(port=8080, protocol="tcp", name="http")],
            )
        )
        review_task = Task(
            title="Review web surface for web-1",
            description="Collect HTTP metadata.",
            task_type="web.review_surface",
            input_context={"asset_id": "web-1", "base_url": "http://target.local:8080"},
        )
        review_task.mark_completed()
        state.task_chain.add_task(review_task)

        decision = planner.plan(state)

        self.assertNotIn("exploit.cve_probe", [task.task_type for task in decision.tasks])

    def test_planner_seeds_initial_exploit_reasoning_from_asset_urls(self) -> None:
        planner = HeuristicPlanner()
        state = GlobalState(objective="demo", metadata={"challenge": {"category": "web"}})
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
                services=[Service(port=8080, protocol="tcp", name="http")],
            )
        )

        decision = planner.plan(state)
        exploit_task = next(task for task in decision.tasks if task.task_type == "exploit.hypothesis")

        self.assertIn("http://target.local:8080", exploit_task.input_context["seed_terms"])

    def test_build_cve_probe_task_dedupe_is_stable_when_seed_path_order_changes(self) -> None:
        task_a = build_cve_probe_task(
            asset_id="web-1",
            base_url="http://target.local:8080",
            ports=[8080],
            seed_paths=["/cgi-bin/file.pl", "/cgi-bin/forms.pl", "/"],
        )
        task_b = build_cve_probe_task(
            asset_id="web-1",
            base_url="http://target.local:8080",
            ports=[8080],
            seed_paths=["/", "/cgi-bin/forms.pl", "/cgi-bin/file.pl"],
        )

        self.assertEqual(task_a.dedupe_key, task_b.dedupe_key)

    def test_build_http_path_probe_task_drops_freeform_prose(self) -> None:
        task = build_http_path_probe_task(
            asset_id="web-1",
            base_url="http://target.local:8080",
            paths=[
                "/cgi-bin/file.pl",
                "The absence of additional internal or external links minimizes attack vectors.",
            ],
        )

        self.assertEqual(task.input_context["paths"], ["/cgi-bin/file.pl"])

    def test_web_path_probe_agent_schedules_content_reviews_for_discovered_pages(self) -> None:
        parsed = SimpleNamespace(
            summary="HTTP path probe completed.",
            output_context={
                "interesting_paths": [
                    "http://target.local:8080/upload",
                    "http://target.local:8080/debug",
                ],
                "flag_candidates": [],
                "manual_checks": [],
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
                tool_name="http_path_probe",
                mode="local_command",
                summary="HTTP path probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        agent = WebPathProbeAgent(execution_plane=FakeExecutionPlane())
        report = agent.run(
            Task(
                title="Probe interesting paths for web-1",
                description="Probe paths.",
                task_type="web.path_probe",
                input_context={
                    "asset_id": "web-1",
                    "base_url": "http://target.local:8080",
                    "paths": ["/upload", "/debug"],
                },
            ),
            GlobalState(objective="demo"),
        )

        content_tasks = [task for task in report.new_tasks if task.task_type == "web.content_review"]
        self.assertEqual(len(content_tasks), 2)
        self.assertEqual(
            {task.input_context["base_url"] for task in content_tasks},
            {"http://target.local:8080/upload", "http://target.local:8080/debug"},
        )

    def test_web_content_agent_schedules_form_probe_when_forms_are_present(self) -> None:
        parsed = SimpleNamespace(
            summary="HTTP content review completed.",
            output_context={
                "forms": [
                    {
                        "action": "/submit",
                        "method": "post",
                        "enctype": "multipart/form-data",
                        "inputs": [{"name": "file", "type": "file"}],
                    }
                ],
                "interesting_links": [],
                "potential_flags": [],
                "keywords": ["upload"],
                "title": "Upload",
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
                tool_name="local_http_content",
                mode="local_command",
                summary="HTTP content review completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        agent = WebContentAgent(execution_plane=FakeExecutionPlane())
        report = agent.run(
            Task(
                title="Review upload page",
                description="Inspect upload page.",
                task_type="web.content_review",
                input_context={
                    "asset_id": "web-1",
                    "base_url": "http://target.local:8080/upload",
                },
            ),
            GlobalState(objective="demo"),
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("web.form_probe", task_types)
        form_task = next(task for task in report.new_tasks if task.task_type == "web.form_probe")
        self.assertEqual(form_task.input_context["page_url"], "http://target.local:8080/upload")
        self.assertEqual(form_task.input_context["forms"][0]["action"], "/submit")

    def test_web_form_probe_agent_promotes_submission_results_to_exploit_reasoning(self) -> None:
        parsed = SimpleNamespace(
            summary="HTTP form probe completed.",
            output_context={
                "submission_results": [
                    {
                        "form_index": 0,
                        "method": "POST",
                        "url": "http://target.local:8080/upload",
                        "status": 200,
                        "query_variant": "",
                        "marker": "autopentest-canary-form0",
                        "filename": "autopentest.txt",
                        "has_file_input": True,
                        "body_preview": "autopentest-canary-form0",
                    }
                ],
                "interesting_paths": ["http://target.local:8080/upload"],
                "action_urls": ["http://target.local:8080/upload"],
                "flag_candidates": [],
                "manual_checks": [],
                "reflected_markers": ["autopentest-canary-form0"],
                "reflected_filenames": ["autopentest.txt"],
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
                tool_name="http_form_probe",
                mode="local_command",
                summary="HTTP form probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def __init__(self):
                self.request = None

            def execute(self, _task_id, request):
                self.request = request
                return bundle

        plane = FakeExecutionPlane()
        agent = WebFormProbeAgent(execution_plane=plane)
        report = agent.run(
            Task(
                title="Interact with discovered forms for web-1",
                description="Probe forms.",
                task_type="web.form_probe",
                input_context={
                    "asset_id": "web-1",
                    "page_url": "http://target.local:8080/cgi-bin/upload.pl",
                    "forms": [
                        {
                            "action": "/upload",
                            "method": "post",
                            "enctype": "multipart/form-data",
                            "inputs": [{"name": "file", "type": "file"}],
                        }
                    ],
                },
            ),
            GlobalState(objective="demo"),
        )

        self.assertEqual(plane.request.tool_name, http_form_probe.TOOL_NAME)
        self.assertEqual(plane.request.metadata["text_payloads"], ["autopentest-canary"])
        self.assertIn("file=ARGV", plane.request.metadata["query_variants"])
        self.assertIn("file=ARGV&cat%20%2Fflag%20%7C", plane.request.metadata["query_variants"])
        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("exploit.hypothesis", task_types)

    def test_static_llm_client_coerces_form_probe_variant_wrappers(self) -> None:
        client = StaticLLMClient(
            [
                {
                    "form_probe_variants": [
                        {
                            "test_case": "Replay the upload with env output.",
                            "query": "file=ARGV&env%20%7C",
                            "inputs": {
                                "file": {
                                    "filename": "llm-note.txt",
                                    "content": "llm-canary",
                                }
                            },
                        }
                    ]
                }
            ]
        )

        result = client.generate_json(
            system_prompt="Return JSON.",
            user_prompt="Plan form probes.",
            schema=FormProbeGuidance,
        )

        self.assertIn("file=ARGV&env%20%7C", result.query_variants)
        self.assertIn("llm-note.txt", result.filename_variants)
        self.assertIn("llm-canary", result.text_payloads)
        self.assertIn("Replay the upload with env output.", result.manual_checks)

    def test_web_form_probe_agent_prefers_llm_query_variants_over_deterministic_fallback(self) -> None:
        parsed = SimpleNamespace(
            summary="HTTP form probe completed.",
            output_context={
                "submission_results": [],
                "interesting_paths": [],
                "action_urls": [],
                "flag_candidates": [],
                "manual_checks": [],
                "reflected_markers": [],
                "reflected_filenames": [],
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
                tool_name="http_form_probe",
                mode="local_command",
                summary="HTTP form probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def __init__(self):
                self.request = None

            def execute(self, _task_id, request):
                self.request = request
                return bundle

        plane = FakeExecutionPlane()
        agent = WebFormProbeAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "query_variants": ["file=ARGV&env%20%7C"],
                        "filename_variants": ["llm.txt"],
                        "text_payloads": ["llm-payload"],
                        "summary": "Use the env-based replay first.",
                    }
                ]
            ),
            execution_plane=plane,
        )
        agent.run(
            Task(
                title="Interact with discovered forms for web-1",
                description="Probe forms.",
                task_type="web.form_probe",
                input_context={
                    "asset_id": "web-1",
                    "page_url": "http://target.local:8080/cgi-bin/upload.pl",
                    "forms": [
                        {
                            "action": "/upload",
                            "method": "post",
                            "enctype": "multipart/form-data",
                            "inputs": [{"name": "file", "type": "file"}],
                        }
                    ],
                },
            ),
            GlobalState(objective="demo"),
        )

        self.assertEqual(plane.request.metadata["query_variants"], ["file=ARGV&env%20%7C"])
        self.assertEqual(plane.request.metadata["filename_variants"], ["autopentest.txt", "llm.txt"])
        self.assertEqual(plane.request.metadata["text_payloads"], ["autopentest-canary", "llm-payload"])

    def test_http_form_probe_helpers_preserve_all_variants_and_replace_existing_query_key(self) -> None:
        variants = http_form_probe._iter_query_variants(
            [
                "file=ARGV",
                "file=STDIN",
                "file=%2Fdev%2Ffd%2F0",
                "file=ARGV&id%20%7C",
            ]
        )
        merged_paths = [
            http_form_probe._merge_query_variant_url(
                "http://target.local/cgi-bin/file.pl?file=/etc/passwd",
                variant,
            )
            for variant in variants
        ]

        self.assertEqual(len(variants), 4)
        self.assertEqual(
            merged_paths,
            [
                "http://target.local/cgi-bin/file.pl?file=ARGV",
                "http://target.local/cgi-bin/file.pl?file=STDIN",
                "http://target.local/cgi-bin/file.pl?file=%2Fdev%2Ffd%2F0",
                "http://target.local/cgi-bin/file.pl?file=ARGV&id%20%7C",
            ],
        )

    def test_http_form_probe_helper_replaces_existing_bare_query_segment(self) -> None:
        merged_path = http_form_probe._merge_query_variant_url(
            "http://target.local/cgi-bin/file.pl?cat%20%2Fflag%20%7C",
            "id%20%7C",
        )

        self.assertEqual(merged_path, "http://target.local/cgi-bin/file.pl?id%20%7C")

    def test_http_form_probe_lifts_same_name_file_assignments_into_multipart_fields(self) -> None:
        url_query, duplicate_fields = http_form_probe._split_query_variant_for_file_inputs(
            "file=ARGV&cat%20%2Fflag%20%7C",
            ["file"],
        )
        merged_url = http_form_probe._merge_query_variant_url(
            "http://target.local/cgi-bin/file.pl",
            url_query,
        )

        self.assertEqual(url_query, "cat%20%2Fflag%20%7C")
        self.assertEqual(duplicate_fields, [("file", "ARGV")])
        self.assertEqual(merged_url, "http://target.local/cgi-bin/file.pl?cat%20%2Fflag%20%7C")

    def test_web_form_probe_agent_schedules_direct_replay_for_promising_action_urls(self) -> None:
        parsed = SimpleNamespace(
            summary="HTTP form probe completed.",
            output_context={
                "submission_results": [
                    {
                        "form_index": 0,
                        "method": "POST",
                        "url": "http://target.local:8080/cgi-bin/upload.pl?cat%20%2Fflag%20%7C",
                        "status": 200,
                        "query_variant": "file=ARGV&cat%20%2Fflag%20%7C",
                        "marker": "autopentest-canary-form0",
                        "filename": "autopentest.txt",
                        "has_file_input": True,
                        "body_preview": "",
                    }
                ],
                "interesting_paths": ["http://target.local:8080/cgi-bin/upload.pl?cat%20%2Fflag%20%7C"],
                "action_urls": ["http://target.local:8080/cgi-bin/upload.pl?cat%20%2Fflag%20%7C"],
                "flag_candidates": [],
                "manual_checks": [],
                "reflected_markers": [],
                "reflected_filenames": [],
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
                tool_name="http_form_probe",
                mode="local_command",
                summary="HTTP form probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        agent = WebFormProbeAgent(execution_plane=FakeExecutionPlane())
        report = agent.run(
            Task(
                title="Interact with discovered forms for web-1",
                description="Probe forms.",
                task_type="web.form_probe",
                input_context={
                    "asset_id": "web-1",
                    "page_url": "http://target.local:8080/cgi-bin/upload.pl",
                    "forms": [
                        {
                            "action": "",
                            "method": "post",
                            "enctype": "multipart/form-data",
                            "inputs": [{"name": "file", "type": "file"}],
                        }
                    ],
                },
            ),
            GlobalState(objective="demo"),
        )

        replay_tasks = [task for task in report.new_tasks if task.task_type == "web.form_probe"]
        self.assertEqual(len(replay_tasks), 1)
        self.assertEqual(
            replay_tasks[0].input_context["page_url"],
            "http://target.local:8080/cgi-bin/upload.pl?cat%20%2Fflag%20%7C",
        )

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
        source_task = next(task for task in report.new_tasks if task.task_type == "artifact.source_review")
        self.assertEqual(source_task.input_context["routing_intent"], "computation")

    def test_artifact_triage_llm_guidance_boosts_prioritized_follow_ups(self) -> None:
        parsed = SimpleNamespace(
            summary="Artifact triage completed.",
            output_context={
                "files_root": "/tmp/ctf",
                "binary_files": ["checker.bin"],
                "archive_files": [],
                "database_files": [],
                "pcap_files": [],
                "repo_paths": [],
                "web_source_files": ["checker.py"],
                "script_files": ["checker.py"],
                "flag_candidates": [],
                "manual_checks": [],
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
            def execute(self, _task_id, _request):
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "rev", "files": ["checker.py"], "flag_format": "flag{...}"}},
        )
        agent = ArtifactTriageAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "Prioritize Python reversing before raw strings review.",
                        "prioritized_analysis_kinds": ["binary"],
                        "source_routing_intent": "computation",
                        "prioritized_task_types": [
                            "artifact.source_review",
                            "artifact.deep_review",
                            "artifact.source_review",
                        ],
                        "preferred_source_workers": ["computation-analysis-agent"],
                        "extra_flag_candidates": ["flag{llm-priority}"],
                        "focus_files": ["checker.py"],
                        "manual_checks": ["Reconstruct the Python transform pipeline first."],
                    }
                ]
            ),
            execution_plane=FakeExecutionPlane(),
        )

        report = agent.run(
            Task(
                title="Inventory challenge files",
                description="Enumerate bundled files.",
                task_type="artifact.triage",
                input_context={"files_root": "/tmp/ctf"},
            ),
            state,
        )

        by_type = {task.task_type: task for task in report.new_tasks if task.task_type != "flag.validate"}
        self.assertIn("artifact.deep_review", by_type)
        self.assertIn("artifact.source_review", by_type)
        self.assertGreater(by_type["artifact.source_review"].priority, 82)
        self.assertEqual(by_type["artifact.source_review"].input_context["routing_intent"], "computation")
        self.assertEqual(by_type["artifact.deep_review"].input_context["analysis_kind"], "binary")
        self.assertEqual(report.output_context["llm_summary"], "Prioritize Python reversing before raw strings review.")
        self.assertIn("flag{llm-priority}", [task.input_context["candidate_flag"] for task in report.new_tasks if task.task_type == "flag.validate"])

    def test_source_review_llm_guidance_adds_runtime_and_path_followups(self) -> None:
        parsed = SimpleNamespace(
            summary="Source review completed for 1 file.",
            output_context={
                "files_root": "/tmp/ctf",
                "inspected_sources": ["checker.py"],
                "interesting_routes": ["/api/debug"],
                "secret_files": ["checker.py"],
                "flag_candidates": [],
                "manual_checks": [],
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
                tool_name="source_review",
                mode="local_command",
                summary="Source review completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "rev", "flag_format": "flag{...}"}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )

        agent = SourceReviewAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "The route names suggest an admin backup flow and reversible checker logic.",
                        "grounded_flag_candidates": ["flag{from-source-llm}"],
                        "interesting_paths": ["admin/backup"],
                        "recommended_checks": ["Inspect the admin backup endpoint before broader crawling."],
                        "promote_runtime_probe": True,
                        "promote_computation_analysis": True,
                    }
                ]
            ),
            execution_plane=FakeExecutionPlane(),
        )

        report = agent.run(
            Task(
                title="Review source artifacts",
                description="Inspect bundled source files.",
                task_type="artifact.source_review",
                input_context={"files_root": "/tmp/ctf", "source_files": ["checker.py"]},
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("web.path_probe", task_types)
        self.assertIn("flag.validate", task_types)
        routed_followups = [task for task in report.new_tasks if task.task_type == "artifact.source_review"]
        self.assertEqual({task.input_context["routing_intent"] for task in routed_followups}, {"runtime", "computation"})
        self.assertTrue(all(task.metadata["exclude_workers"] == ["source-review-agent"] for task in routed_followups))

        path_probe_task = next(task for task in report.new_tasks if task.task_type == "web.path_probe")
        self.assertIn("/api/debug", path_probe_task.input_context["paths"])
        self.assertIn("/admin/backup", path_probe_task.input_context["paths"])
        self.assertEqual(
            report.output_context["llm_summary"],
            "The route names suggest an admin backup flow and reversible checker logic.",
        )

    def test_llm_worker_router_selects_named_candidate(self) -> None:
        task = Task(
            title="Review source artifacts",
            description="Inspect bundled source files.",
            task_type="artifact.source_review",
            input_context={"files_root": "/tmp/ctf", "source_files": ["checker.py"]},
        )
        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "rev"}},
        )
        candidates = [
            RoutedSourceWorker(name="source-review-agent", score=10),
            RoutedSourceWorker(name="runtime-probe-agent", score=5),
            RoutedSourceWorker(name="computation-analysis-agent", score=1),
        ]
        router = LLMWorkerRouter(
            StaticLLMClient(
                [
                    {
                        "worker_name": "runtime-probe-agent",
                        "rationale": "checker.py is script-like and should be executed first.",
                        "confidence": 0.82,
                    }
                ]
            )
        )

        decision = router.route(task=task, state=state, candidates=candidates)

        self.assertEqual(decision.worker_name, "runtime-probe-agent")
        self.assertIn("executed first", decision.rationale)

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

    def test_credential_harvest_extracts_password_and_token_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".env").write_text(
                "USERNAME=admin\nPASSWORD=swordfish\nAPI_KEY=token-demo-123\n",
                encoding="utf-8",
            )

            request = ToolExecutionRequest(
                tool_name="credential_harvest",
                metadata={
                    "files_root": str(root),
                    "seed_terms": ["admin", "login"],
                    "max_files": 10,
                },
            )
            argv = [sys.executable, *credential_harvest.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertGreaterEqual(len(output_context["credential_candidates"]), 2)
            self.assertIn("admin", [item["username"] for item in output_context["credential_candidates"]])

    def test_flag_harvest_decodes_base64_flag_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "note.txt").write_text(
                "candidate=ZmxhZ3tkZWNvZGVkLWhhcnZlc3R9\n",
                encoding="utf-8",
            )

            request = ToolExecutionRequest(
                tool_name="flag_harvest",
                metadata={
                    "files_root": str(root),
                    "seed_terms": ["candidate"],
                    "max_files": 10,
                },
            )
            argv = [sys.executable, *flag_harvest.build_arguments(request)]
            completed = subprocess.run(argv, capture_output=True, text=True, check=True)
            records = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            output_context = next(
                record for record in records if record.get("type") == "output_context"
            )

            self.assertIn("flag{decoded-harvest}", output_context["flag_candidates"])

    def test_credential_login_probe_handles_unreachable_target_without_crashing(self) -> None:
        request = ToolExecutionRequest(
            tool_name="credential_login_probe",
            metadata={
                "asset_id": "web-1",
                "base_url": "http://127.0.0.1:1",
                "candidate_credentials": [
                    {
                        "credential_id": "credential-demo",
                        "username": "admin",
                        "credential_type": "password",
                        "secret_value": "swordfish",
                    }
                ],
                "seed_paths": ["/admin", "/flag"],
            },
            timeout_s=2,
        )
        argv = [sys.executable, *credential_login_probe.build_arguments(request)]
        completed = subprocess.run(argv, capture_output=True, text=True, check=True)
        records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        output_context = next(record for record in records if record.get("type") == "output_context")

        self.assertEqual(output_context["successful_credential_ids"], [])
        self.assertEqual(output_context["flag_candidates"], [])

    def test_ctf_exploit_probe_handles_unreachable_target_without_crashing(self) -> None:
        request = ToolExecutionRequest(
            tool_name="ctf_exploit_probe",
            metadata={
                "asset_id": "svc-1",
                "hostname": "127.0.0.1",
                "ports": [1],
                "tcp_inputs": ["flag"],
            },
            timeout_s=2,
        )
        argv = [sys.executable, *ctf_exploit_probe.build_arguments(request)]
        completed = subprocess.run(argv, capture_output=True, text=True, check=True)
        records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        output_context = next(record for record in records if record.get("type") == "output_context")

        self.assertEqual(output_context["flag_candidates"], [])
        self.assertEqual(output_context["tcp_results"], [])

    def test_heuristic_planner_seeds_ctf_hunt_tasks_for_local_files(self) -> None:
        planner = HeuristicPlanner()
        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"files": ["app.py"], "name": "demo", "category": "misc"}},
        )

        decision = planner.plan(state)

        task_types = [task.task_type for task in decision.tasks]
        self.assertIn("artifact.triage", task_types)
        self.assertIn("credential.hunt", task_types)
        self.assertIn("flag.hunt", task_types)

    def test_heuristic_planner_seeds_credential_test_for_web_asset_when_credentials_present(self) -> None:
        planner = HeuristicPlanner()
        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "web", "files": ["app.py"]}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )
        state.upsert_credential(
            Credential(
                credential_id="credential-demo",
                username="admin",
                secret_ref="file:.env:PASSWORD",
                credential_type="password",
                asset_ref="web-1",
                metadata={"secret_value": "swordfish"},
            )
        )

        decision = planner.plan(state)

        task_types = [task.task_type for task in decision.tasks]
        self.assertIn("exploit.credential_test", task_types)

    def test_credential_hunt_agent_queues_exploit_reasoning_followup(self) -> None:
        parsed = SimpleNamespace(
            summary="Credential harvesting completed.",
            output_context={
                "files_root": "/tmp/ctf",
                "credential_candidates": [
                    {
                        "credential_id": "credential-demo",
                        "username": "admin",
                        "secret_value": "swordfish",
                        "credential_type": "password",
                        "path": ".env",
                    }
                ],
                "credential_ids": ["credential-demo"],
                "flag_candidates": [],
                "interesting_paths": ["/login"],
                "manual_checks": [],
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
                tool_name="credential_harvest",
                mode="local_command",
                summary="Credential harvesting completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "web", "files": ["app.py"], "flag_format": "flag{...}"}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )
        agent = CredentialHuntAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "The admin credential likely maps to the login route.",
                        "prioritized_credential_ids": ["credential-demo"],
                        "grounded_flag_candidates": [],
                        "interesting_paths": ["/admin"],
                        "manual_checks": ["Try the admin credential on the exposed login flow."],
                        "should_schedule_exploit_hypothesis": True,
                    }
                ]
            ),
            execution_plane=FakeExecutionPlane(),
        )

        report = agent.run(
            Task(
                title="Harvest candidate credentials",
                description="Search challenge files for credentials.",
                task_type="credential.hunt",
                input_context={"files_root": "/tmp/ctf"},
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("web.path_probe", task_types)
        self.assertIn("exploit.hypothesis", task_types)
        self.assertEqual(
            report.output_context["llm_summary"],
            "The admin credential likely maps to the login route.",
        )

    def test_credential_exploit_agent_schedules_targeted_probe_after_login_success(self) -> None:
        parsed = SimpleNamespace(
            summary="Credential probe completed.",
            output_context={
                "base_url": "http://target.local:8080",
                "successful_credential_ids": ["credential-demo"],
                "interesting_paths": ["/admin"],
                "auth_results": [],
                "flag_candidates": [],
                "manual_checks": [],
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
                tool_name="credential_login_probe",
                mode="local_command",
                summary="Credential probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "web", "files": ["app.py"], "flag_format": "flag{...}"}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )
        state.upsert_credential(
            Credential(
                credential_id="credential-demo",
                username="admin",
                secret_ref="file:.env:PASSWORD",
                credential_type="password",
                asset_ref="web-1",
                metadata={"secret_value": "swordfish"},
            )
        )
        agent = CredentialExploitAgent(execution_plane=FakeExecutionPlane())

        report = agent.run(
            Task(
                title="Test recovered credentials against web-1",
                description="Reuse credentials against the live app.",
                task_type="exploit.credential_test",
                input_context={
                    "asset_id": "web-1",
                    "base_url": "http://target.local:8080",
                    "credential_ids": ["credential-demo"],
                },
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("exploit.cve_probe", task_types)

    def test_exploit_reasoning_agent_converts_llm_output_to_followups(self) -> None:
        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "web", "files": ["app.py"], "flag_format": "flag{...}"}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )
        state.upsert_finding(
            Finding(
                finding_id="finding-demo",
                title="Admin route exposed",
                severity="medium",
                description="Found /admin in the source.",
                asset_refs=["web-1"],
                evidence_refs=["/admin"],
            )
        )
        agent = ExploitReasoningAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "The shortest path is to inspect the admin surface and validate the recovered candidate.",
                        "hypotheses": ["The admin route may expose the flag directly."],
                        "focus_asset_ids": ["web-1"],
                        "interesting_paths": ["/admin", "/debug/flag"],
                        "grounded_flag_candidates": ["flag{exploit-reasoning}"],
                        "manual_checks": ["Inspect the admin route before broader fuzzing."],
                        "should_schedule_flag_hunt": True,
                        "should_schedule_credential_hunt": False,
                    }
                ]
            )
        )

        report = agent.run(
            Task(
                title="Synthesize CTF exploit hypotheses",
                description="Use accumulated evidence to prioritize the next pivot.",
                task_type="exploit.hypothesis",
                input_context={"files_root": "/tmp/ctf", "focus_asset_ids": ["web-1"]},
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("web.path_probe", task_types)
        self.assertIn("flag.validate", task_types)
        self.assertIn("flag.hunt", task_types)

    def test_web_pwn_exploit_agent_turns_probe_output_into_flag_validation(self) -> None:
        parsed = SimpleNamespace(
            summary="CTF exploit probe completed.",
            output_context={
                "http_results": [{"url": "http://target.local:8080/admin", "status": 200}],
                "tcp_results": [],
                "interesting_paths": ["/admin"],
                "flag_candidates": ["flag{web-pwn-probe}"],
                "manual_checks": [],
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
                tool_name="ctf_exploit_probe",
                mode="local_command",
                summary="CTF exploit probe completed.",
            ),
        )

        class FakeExecutionPlane:
            def execute(self, _task_id, _request):
                return bundle

        state = GlobalState(
            objective="demo",
            metadata={"challenge": {"category": "web", "files": ["app.py"], "flag_format": "flag{...}"}},
        )
        state.upsert_asset(
            Asset(
                asset_id="web-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://target.local:8080",
            )
        )
        agent = WebPwnExploitAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "Probe the admin surface first.",
                        "prioritized_credential_ids": [],
                        "preferred_protocol": "web",
                        "http_paths": ["/admin"],
                        "tcp_inputs": [],
                        "focus_ports": [],
                        "grounded_flag_candidates": [],
                        "manual_checks": ["Inspect the admin response body closely."],
                        "should_schedule_flag_hunt": True,
                    },
                    {
                        "summary": "The probe already exposed a grounded flag candidate.",
                        "grounded_flag_candidates": ["flag{web-pwn-probe}"],
                        "interesting_paths": ["/admin"],
                        "manual_checks": ["Validate the recovered candidate immediately."],
                        "should_schedule_flag_hunt": False,
                        "should_schedule_credential_hunt": False,
                        "should_schedule_exploit_hypothesis": False,
                    },
                ]
            ),
            execution_plane=FakeExecutionPlane(),
        )

        report = agent.run(
            Task(
                title="Probe targeted exploit paths for web-1",
                description="Attempt grounded exploit interactions.",
                task_type="exploit.cve_probe",
                input_context={"asset_id": "web-1", "base_url": "http://target.local:8080", "seed_paths": ["/admin"]},
            ),
            state,
        )

        task_types = [task.task_type for task in report.new_tasks]
        self.assertIn("flag.validate", task_types)
        self.assertEqual(report.output_context["llm_summary"], "The probe already exposed a grounded flag candidate.")

    def test_flag_validation_agent_uses_llm_normalization(self) -> None:
        agent = FlagValidationAgent(
            llm_client=StaticLLMClient(
                [
                    {
                        "summary": "The candidate only needs surrounding quotes removed.",
                        "normalized_candidate": "flag{normalized}",
                        "likely_valid": True,
                        "confidence": 0.91,
                    }
                ]
            ),
            expected_flag="flag{normalized}",
        )

        report = agent.run(
            Task(
                title="Validate candidate flag",
                description="Compare a candidate against the expected flag.",
                task_type="flag.validate",
                input_context={"candidate_flag": "\"flag{normalized}\"", "candidate_source": "test"},
            ),
            GlobalState(objective="demo", metadata={"challenge": {"flag_format": "flag{...}"}}),
        )

        self.assertTrue(report.solved)
        self.assertEqual(report.output_context["normalized_candidate"], "flag{normalized}")

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
