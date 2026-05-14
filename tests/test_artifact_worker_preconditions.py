"""Artifact worker precondition handling."""

from __future__ import annotations

import unittest

from killchain_docker.workers.artifact import (
    ComputationAnalysisAgent,
    RuntimeProbeAgent,
    SourceReviewAgent,
)
from killchain_docker.state import GlobalState, Task


def _state() -> GlobalState:
    return GlobalState(
        objective="Solve challenge.",
        authorized_scope=[],
        metadata={"challenge": {"category": "rev", "flag_format": "flag{...}"}},
    )


def _task(task_type: str, source_files: list[str]) -> Task:
    return Task(
        title="Artifact task",
        description="Inspect files.",
        task_type=task_type,
        input_context={
            "files_root": "/tmp/does-not-matter",
            "source_files": source_files,
        },
    )


class ArtifactWorkerPreconditionTests(unittest.TestCase):
    def test_source_review_skips_non_source_files_without_tool_gateway(self) -> None:
        report = SourceReviewAgent().run(
            _task("artifact.source_review", ["challenge.bin", "image.raw"]),
            _state(),
        )

        self.assertTrue(report.success)
        self.assertEqual(report.output_context["skip_reason"], "no_source_like_files")

    def test_runtime_probe_skips_non_script_files_without_tool_gateway(self) -> None:
        report = RuntimeProbeAgent().run(
            _task("artifact.runtime_probe", ["notes.txt", "data.bin"]),
            _state(),
        )

        self.assertTrue(report.success)
        self.assertEqual(report.output_context["skip_reason"], "no_executable_script_files")

    def test_computation_analysis_skips_non_python_files_without_tool_gateway(self) -> None:
        report = ComputationAnalysisAgent().run(
            _task("artifact.computation_analysis", ["algorithm.c", "script.sh"]),
            _state(),
        )

        self.assertTrue(report.success)
        self.assertEqual(report.output_context["skip_reason"], "no_python_source_files")


if __name__ == "__main__":
    unittest.main()
