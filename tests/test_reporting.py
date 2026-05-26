from __future__ import annotations
import unittest
from killchain_docker.reporting import render_markdown_report
from killchain_docker.state.run_state import RunState


class ReportingTests(unittest.TestCase):
    def test_report_surfaces_runtime_error(self) -> None:
        state = RunState(objective="Solve failed run", authorized_scope=[])
        state.metadata["runtime_error"] = {
            "type": "RuntimeError",
            "message": "router crashed\nbefore finalizing state",
        }
        report = render_markdown_report(state)
        self.assertIn(
            "- Runtime Error: `RuntimeError` router crashed before finalizing state",
            report,
        )

    def test_report_surfaces_public_rag_status(self) -> None:
        state = RunState(objective="Solve strict run", authorized_scope=[])
        state.metadata["rag"] = {
            "mode": "strict",
            "enabled": True,
            "status": "hit",
            "knowledge_hints": [{"solution_sketch": "raw hint"}],
            "hit_provenance": [{"challenge_id": "hidden"}],
        }
        report = render_markdown_report(state)
        self.assertIn(
            "- RAG: enabled=`True` status=`hit` policy=`filtered_context` hints=1",
            report,
        )
        self.assertNotIn("hidden", report)


if __name__ == "__main__":
    unittest.main()
