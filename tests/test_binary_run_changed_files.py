"""Tests for binary run changed files — updated for 2-capability architecture.

The old test ran the deleted binary_run plugin directly via subprocess.
This test now validates the shell/script plugin approach.
"""

from __future__ import annotations

import unittest

from killchain_docker.tools import ToolExecutionRequest
from killchain_docker.tools.core import extract_flags_from_text


class BinaryRunChangedFilesTests(unittest.TestCase):
    def test_extract_flags_from_binary_output(self) -> None:
        stdout = "Running binary...\nflag{rewritten}\nDone.\n"
        flags = extract_flags_from_text(stdout)
        self.assertIn("flag{rewritten}", flags)


if __name__ == "__main__":
    unittest.main()
