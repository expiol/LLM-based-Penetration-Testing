from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from killchain_docker.tools import ToolExecutionRequest
from killchain_docker.tools.plugins import binary_run


class BinaryRunChangedFilesTests(unittest.TestCase):
    def test_captures_in_place_modified_input_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "rewrite.py"
            target = root / "flag.stfu"
            tool.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import sys\n"
                "Path(sys.argv[1]).write_text('flag{rewritten}\\n')\n",
                encoding="utf-8",
            )
            tool.chmod(0o755)
            target.write_text("ciphertext\n", encoding="utf-8")

            request = ToolExecutionRequest(
                tool_name="binary_run",
                metadata={
                    "files_root": str(root),
                    "binary_files": ["rewrite.py"],
                    "challenge_files": ["rewrite.py", "flag.stfu"],
                    "max_invocations_per_binary": 4,
                },
            )
            completed = subprocess.run(
                [sys.executable, *binary_run.build_arguments(request)],
                capture_output=True,
                text=True,
                timeout=20,
                check=True,
            )

        records = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        output_context = next(item for item in records if item.get("type") == "output_context")
        invocations = output_context["binary_runs"]["rewrite.py"]["invocations"]
        changed = [
            item
            for invocation in invocations
            for item in invocation.get("changed_files", [])
        ]
        self.assertTrue(changed)
        self.assertIn("flag{rewritten}", json.dumps(changed))
        self.assertIn("flag{rewritten}", output_context["flag_candidates"])


if __name__ == "__main__":
    unittest.main()
