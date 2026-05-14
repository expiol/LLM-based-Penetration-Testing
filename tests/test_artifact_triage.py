from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from killchain_docker.tools import ToolExecutionRequest
from killchain_docker.tools.plugins import artifact_triage


class ArtifactTriageTests(unittest.TestCase):
    def test_decodes_binary_text_flag_candidates(self) -> None:
        plaintext = "flag{bits_are_text}"
        bitstring = "".join(f"{ord(char):08b}" for char in plaintext)

        with tempfile.TemporaryDirectory() as tmpdir:
            files_root = Path(tmpdir)
            (files_root / "cipher.mpeg").write_text(bitstring, encoding="utf-8")
            request = ToolExecutionRequest(
                tool_name="artifact_triage",
                metadata={
                    "files_root": str(files_root),
                    "challenge_files": ["cipher.mpeg"],
                },
            )

            completed = subprocess.run(
                ["python3", *artifact_triage.build_arguments(request)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        output_context = next(record for record in records if record.get("type") == "output_context")

        self.assertIn(plaintext, output_context["flag_candidates"])
        self.assertEqual(output_context["decoded_text_previews"][0]["path"], "cipher.mpeg")


if __name__ == "__main__":
    unittest.main()
