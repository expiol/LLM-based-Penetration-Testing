"""Tests for the capability-group worker registry."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.agents.groups import (
    CREDENTIAL_WORKERS,
    EXPLOIT_WORKERS,
    FLAG_WORKERS,
    HOST_WORKERS,
    SOLVER_WORKERS,
    STATIC_ANALYSIS_WORKERS,
    VULN_WORKERS,
    WEB_WORKERS,
    all_worker_classes,
)


_EXPECTED_TASK_TYPES = {
    # static analysis (one worker per task)
    "artifact.triage",
    "artifact.binary_triage",
    "artifact.archive_triage",
    "artifact.sqlite_review",
    "artifact.pcap_review",
    "artifact.repo_review",
    "artifact.source_review",
    "artifact.computation_analysis",
    "artifact.runtime_probe",
    "artifact.deep_review",
    # web
    "web.review_surface",
    "web.header_analysis",
    "web.content_review",
    "web.crawl",
    "web.form_probe",
    "web.path_probe",
    # host
    "host.audit",
    "host.port_scan",
    "host.banner_grab",
    "host.service_fingerprint",
    # credential
    "credential.hunt",
    # exploit
    "exploit.credential_test",
    "exploit.cve_probe",
    "exploit.sqli",
    "exploit.hypothesis",
    # flag/solver
    "flag.hunt",
    "flag.validate",
    "solve.generate_script",
}


def _supported(cls) -> tuple[str, ...]:
    return getattr(cls, "supported_task_types", ()) or ()


class GroupsRegistryTests(unittest.TestCase):
    def test_no_aggregator_workers_remain(self):
        for cls in all_worker_classes():
            self.assertNotIn(cls.__name__, {
                "ArtifactWorker", "SurfaceWorker", "ExploitWorker", "CredentialWorker",
            })

    def test_all_groups_are_non_empty(self):
        for group_name, workers in [
            ("static_analysis", STATIC_ANALYSIS_WORKERS),
            ("web", WEB_WORKERS),
            ("host", HOST_WORKERS),
            ("credential", CREDENTIAL_WORKERS),
            ("exploit", EXPLOIT_WORKERS),
            ("vuln", VULN_WORKERS),
            ("flag", FLAG_WORKERS),
            ("solver", SOLVER_WORKERS),
        ]:
            self.assertGreater(
                len(workers), 0, f"group {group_name} has no workers",
            )

    def test_static_analysis_workers_are_focused(self):
        # Each static analysis worker handles 1-2 task types (its primary +
        # optionally artifact.deep_review when analysis_kind matches).
        for cls in STATIC_ANALYSIS_WORKERS:
            count = len(_supported(cls))
            self.assertIn(
                count, (1, 2),
                f"{cls.__name__} should claim 1-2 task types (got {count})",
            )

    def test_artifact_deep_review_has_multiple_candidates(self):
        # binary/archive/sqlite/pcap/repo workers all claim deep_review
        # with their respective analysis_kind so the Router gets exercised.
        from nyuctf_mutil_killchain.state import Task
        kinds_with_candidates = {
            "binary": "binary_files",
            "archive": "archive_files",
            "sqlite": "database_files",
            "pcap": "pcap_files",
            "repo": "repo_paths",
        }
        for kind, field in kinds_with_candidates.items():
            task = Task(
                title="deep", description="d",
                task_type="artifact.deep_review",
                input_context={"analysis_kind": kind, field: ["x"]},
            )
            candidates = [c() for c in STATIC_ANALYSIS_WORKERS if c().supports(task)]
            self.assertGreaterEqual(
                len(candidates), 1,
                f"deep_review with kind={kind} should have at least one worker",
            )

    def test_every_expected_task_type_has_at_least_one_worker(self):
        covered: set[str] = set()
        for cls in all_worker_classes():
            for prefix in _supported(cls):
                covered.add(prefix.rstrip("."))
                covered.add(prefix)

        for task_type in _EXPECTED_TASK_TYPES:
            matched = any(
                task_type == cov or task_type.startswith(cov + ".") or
                cov == task_type or cov.startswith(task_type)
                for cov in covered
            )
            # Also accept prefix-matching workers (e.g., recon. handles recon.enumerate_scope)
            prefix_match = any(
                task_type.startswith(prefix)
                for cls in all_worker_classes()
                for prefix in _supported(cls)
            )
            self.assertTrue(
                matched or prefix_match,
                f"task type {task_type!r} has no registered worker",
            )

    def test_total_worker_count_matches_groups_sum(self):
        total = sum(len(g) for g in [
            STATIC_ANALYSIS_WORKERS, WEB_WORKERS, HOST_WORKERS,
            CREDENTIAL_WORKERS, EXPLOIT_WORKERS, VULN_WORKERS,
            FLAG_WORKERS, SOLVER_WORKERS,
        ])
        self.assertEqual(len(all_worker_classes()), total)


if __name__ == "__main__":
    unittest.main()
