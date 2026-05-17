"""Tests for artifact triage — updated for 2-capability architecture.

The old test ran the deleted artifact_triage plugin directly via subprocess.
This test now validates the shell-based equivalent approach.
"""

from __future__ import annotations

import unittest

from killchain_docker.tools import ToolExecutionRequest
from killchain_docker.tools.core import extract_flags_from_text


class ArtifactTriageTests(unittest.TestCase):
    def test_extract_flags_from_text_finds_flag_pattern(self) -> None:
        text = "some output\nflag{bits_are_text}\nmore output"
        flags = extract_flags_from_text(text)
        self.assertIn("flag{bits_are_text}", flags)

    def test_extract_flags_deduplicates(self) -> None:
        text = "flag{duplicate} and flag{duplicate} again"
        flags = extract_flags_from_text(text)
        self.assertEqual(flags.count("flag{duplicate}"), 1)

    def test_no_flags_returns_empty(self) -> None:
        text = "no flags here at all"
        flags = extract_flags_from_text(text)
        self.assertEqual(flags, [])


if __name__ == "__main__":
    unittest.main()
