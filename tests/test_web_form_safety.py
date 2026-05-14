"""Regression tests for web form fan-out and unsafe URL filtering."""

from __future__ import annotations

import unittest

from killchain_docker.workers.web_form import (
    WebFormProbeAgent,
    _candidate_replay_urls,
    _filter_query_variants,
)
from killchain_docker.llm import StaticLLMClient
from killchain_docker.state import (
    EvidenceRecord,
    GlobalState,
    Task,
)
from killchain_docker.tools import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionBundle,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from killchain_docker.tools.plugins.http_form_probe import _iter_query_variants


class WebFormSafetyTests(unittest.TestCase):
    def test_raw_http_query_variants_are_rejected(self) -> None:
        raw_http = (
            "POST /uploadify/uploadify.php HTTP/1.1\n"
            "Content-Type: multipart/form-data\n\nbody"
        )
        filtered = _filter_query_variants(
            [raw_http, "Test login with username admin", "file=ARGV&cmd=id%20%7C"]
        )
        self.assertEqual(filtered, ["file=ARGV&cmd=id%20%7C"])
        self.assertEqual(_iter_query_variants([raw_http]), [""])

    def test_replay_urls_must_be_submitted_safe_and_same_origin(self) -> None:
        forms = [{"method": "post", "inputs": [{"name": "username", "type": "text"}]}]
        page_url = "http://example.test/register"

        no_signal = {
            "submission_results": [
                {"url": "http://example.test/register?x=1", "status": 200}
            ],
        }
        self.assertEqual(_candidate_replay_urls(page_url, forms, no_signal), [])

        with_signal = {
            "interesting_paths": ["http://example.test/register?x=1"],
            "submission_results": [
                {"url": "http://example.test/register?x=1", "status": 200}
            ],
        }
        self.assertEqual(
            _candidate_replay_urls(page_url, forms, with_signal),
            ["http://example.test/register?x=1"],
        )

        unsafe = {
            "interesting_paths": ["http://example.test/register?x=1"],
            "submission_results": [
                {"url": "http://example.test?POST /x HTTP/1.1", "status": 200},
                {"url": "http://evil.test/register?x=1", "status": 200},
            ],
        }
        self.assertEqual(_candidate_replay_urls(page_url, forms, unsafe), [])

    def test_llm_only_flag_candidates_are_not_validated(self) -> None:
        class _FakePlane:
            def execute(self, task_id: str, request: ToolExecutionRequest) -> ToolExecutionBundle:
                return ToolExecutionBundle(
                    request=request,
                    result=ToolExecutionResult(
                        tool_name="http_form_probe",
                        mode=ExecutionMode.LOCAL_COMMAND,
                        stdout="",
                    ),
                    parsed=ParsedToolOutput(
                        summary="HTTP form probe completed.",
                        output_context={
                            "flag_candidates": [],
                            "submission_results": [],
                        },
                    ),
                    evidence=EvidenceRecord(
                        task_id=task_id,
                        tool_name="http_form_probe",
                        mode="local_command",
                        summary="HTTP form probe completed.",
                    ),
                )

        agent = WebFormProbeAgent(
            llm_client=StaticLLMClient([
                {
                    "summary": "try a guessed flag",
                    "query_variants": [],
                    "text_payloads": [],
                    "filename_variants": [],
                    "grounded_flag_candidates": ["key{ssti}"],
                    "manual_checks": [],
                    "should_schedule_exploit_hypothesis": False,
                }
            ]),
            execution_plane=_FakePlane(),
        )
        state = GlobalState(objective="Solve web.", authorized_scope=[])
        task = Task(
            title="Probe forms",
            description="Probe forms",
            task_type="web.form_probe",
            input_context={
                "asset_id": "seed-asset",
                "page_url": "http://example.test/",
                "forms": [{"method": "post", "inputs": [{"name": "username"}]}],
            },
        )

        report = agent.run(task, state)

        self.assertTrue(report.success)
        self.assertEqual(report.planner_signals, [])
        self.assertEqual(
            report.output_context["llm_grounded_flag_candidates"],
            ["key{ssti}"],
        )
        self.assertEqual(report.output_context["flag_candidates"], [])


if __name__ == "__main__":
    unittest.main()
