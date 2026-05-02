"""Regression tests for ``Task.normalise_input_context``.

The LLM planner sometimes emits a list where a worker expects a scalar (and
vice versa).  Centralised normalisation in :class:`Task` saves every worker
from defending against the type drift.  Concrete bug this guards against:
``recon-agent`` crashing with ``AttributeError: 'list' object has no attribute
'decode'`` when ``scope=["http://x"]`` was passed straight to ``urlparse``.
"""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.state.models import Task


class TestScalarCoercion(unittest.TestCase):
    def test_list_scope_becomes_scalar(self) -> None:
        task = Task(
            title="Recon",
            description="Recon task",
            task_type="recon.enumerate_scope",
            input_context={"scope": ["http://example.com:80"]},
        )
        self.assertEqual(task.input_context["scope"], "http://example.com:80")

    def test_empty_list_scope_becomes_none(self) -> None:
        task = Task(
            title="Recon",
            description="Recon task",
            task_type="recon.enumerate_scope",
            input_context={"scope": []},
        )
        self.assertIsNone(task.input_context["scope"])

    def test_scalar_scope_unchanged(self) -> None:
        task = Task(
            title="Recon",
            description="Recon task",
            task_type="recon.enumerate_scope",
            input_context={"scope": "http://example.com:80"},
        )
        self.assertEqual(task.input_context["scope"], "http://example.com:80")

    def test_list_candidate_flag_takes_first(self) -> None:
        task = Task(
            title="Validate",
            description="Validate task",
            task_type="flag.validate",
            input_context={"candidate_flag": ["flag{abc}", "flag{def}"]},
        )
        self.assertEqual(task.input_context["candidate_flag"], "flag{abc}")


class TestListCoercion(unittest.TestCase):
    def test_scalar_paths_becomes_list(self) -> None:
        task = Task(
            title="Probe",
            description="Probe task",
            task_type="web.path_probe",
            input_context={"paths": "/admin"},
        )
        self.assertEqual(task.input_context["paths"], ["/admin"])

    def test_comma_separated_paths_split(self) -> None:
        task = Task(
            title="Probe",
            description="Probe task",
            task_type="web.path_probe",
            input_context={"paths": "/admin,/api,/login"},
        )
        self.assertEqual(task.input_context["paths"], ["/admin", "/api", "/login"])

    def test_empty_list_paths_unchanged(self) -> None:
        task = Task(
            title="Probe",
            description="Probe task",
            task_type="web.path_probe",
            input_context={"paths": []},
        )
        self.assertEqual(task.input_context["paths"], [])

    def test_unknown_keys_pass_through(self) -> None:
        task = Task(
            title="Custom",
            description="Custom",
            task_type="custom.task",
            input_context={"random_field": ["a", "b"]},
        )
        self.assertEqual(task.input_context["random_field"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
