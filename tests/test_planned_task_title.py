"""Regression tests for PlannedTask title narrowing (fix #7).

The LLM planner emits ever-broader solver titles ("Comprehensive FuelPHP
source analysis & live exploitation: extract encryption keys, forge admin
session cookie, bypass auth, and exploit /uploadify/uploadify.php for RCE
to read flag").  Each becomes a fresh chain because dedupe is title-based,
and each chain tries to do everything in one 250-line script.  We force
solver task titles into "one experiment per task" shape at construction
time so a too-broad LLM proposal is silently narrowed.
"""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.orchestrator.planning.schemas import PlannedTask


class TestSolverTitleNarrowing(unittest.TestCase):
    def test_strips_comprehensive_prefix(self) -> None:
        task = PlannedTask(
            title="Comprehensive FuelPHP source analysis: extract encryption_key",
            description="x",
            task_type="solve.generate_script",
        )
        self.assertNotIn("Comprehensive", task.title)
        self.assertTrue(task.title.startswith("FuelPHP"))

    def test_cuts_at_multiple_conjunctions(self) -> None:
        task = PlannedTask(
            title=(
                "Extract FuelPHP source, locate session encryption keys, "
                "forge admin cookie, and exploit /uploadify/uploadify.php "
                "for RCE to retrieve flag"
            ),
            description="x",
            task_type="solve.generate_script",
        )
        # Should keep only the first concrete experiment.
        self.assertTrue(task.title.startswith("Extract FuelPHP source"))
        self.assertNotIn(", forge", task.title)
        self.assertNotIn("and exploit", task.title)

    def test_caps_length_at_80(self) -> None:
        long_title = (
            "Decrypt the very long crypto challenge using a custom many-time-pad "
            "approach with crib-dragging across all eight ciphertexts to recover the flag"
        )
        task = PlannedTask(
            title=long_title,
            description="x",
            task_type="solve.generate_script",
        )
        self.assertLessEqual(len(task.title), 80)

    def test_keeps_short_focused_title(self) -> None:
        title = "Decrypt flag.stfu via LFSR keystream"
        task = PlannedTask(
            title=title, description="x", task_type="solve.generate_script"
        )
        self.assertEqual(task.title, title)

    def test_does_not_narrow_non_solver_titles(self) -> None:
        # Web/recon/etc. task titles are deterministic and don't need narrowing.
        title = "Comprehensive web content review for seed-asset"
        task = PlannedTask(
            title=title, description="x", task_type="web.content_review"
        )
        self.assertEqual(task.title, title)

    def test_handles_ampersand_conjunction(self) -> None:
        task = PlannedTask(
            title="Decode csawpad cipher & recover keystream & extract flag",
            description="x",
            task_type="solve.generate_script",
        )
        self.assertTrue(task.title.startswith("Decode csawpad cipher"))
        self.assertNotIn("&", task.title)


if __name__ == "__main__":
    unittest.main()
