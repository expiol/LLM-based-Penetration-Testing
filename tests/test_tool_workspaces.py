from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins.artifact_triage import ArtifactTriagePlugin
from killchain_docker.tools.plugins.binwalk import (
    BinwalkPlugin,
    build_output as binwalk_output_builder,
)
from killchain_docker.tools.plugins.foremost import ForemostPlugin
from killchain_docker.tools.plugins.gdb import GdbPlugin
from killchain_docker.tools.plugins.ltrace import LtracePlugin
from killchain_docker.tools.plugins.script import ScriptPlugin
from killchain_docker.tools.plugins.script import build_output as script_output_builder
from killchain_docker.tools.plugins.shell import ShellPlugin, build_output as shell_output_builder
from killchain_docker.tools.plugins.strace import StracePlugin
from killchain_docker.tools.plugins.workspace import protected_shell_command


class ToolWorkspaceTests(unittest.TestCase):
    def test_shell_exec_restores_challenge_files_after_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.txt"
            data.write_text("original", encoding="utf-8")

            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "command": "printf changed > data.txt; touch extra.txt; printf done",
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("done"))
            self.assertEqual(data.read_text(encoding="utf-8"), "original")
            self.assertFalse((root / "extra.txt").exists())

    def test_protected_shell_can_preserve_explicit_artifact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.txt"
            artifact = root / ".autopentest_artifacts" / "tool" / "result.txt"
            data.write_text("original", encoding="utf-8")

            command = protected_shell_command(
                (
                    "printf changed > data.txt; "
                    "touch extra.txt; "
                    'mkdir -p "$CTF_FILES_ROOT/.autopentest_artifacts/tool"; '
                    'printf durable > "$CTF_FILES_ROOT/.autopentest_artifacts/tool/result.txt"; '
                    "printf ok"
                ),
                root,
                preserve_relative_paths=(".autopentest_artifacts",),
            )
            result = subprocess.run(
                ["bash", "-c", command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ok")
            self.assertEqual(data.read_text(encoding="utf-8"), "original")
            self.assertFalse((root / "extra.txt").exists())
            self.assertEqual(artifact.read_text(encoding="utf-8"), "durable")

    def test_shell_exec_isolates_cleanup_state_from_user_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "files"
            root.mkdir()
            decoy = Path(tmp) / "decoy"
            decoy.mkdir()
            data = root / "data.txt"
            marker = decoy / "marker.txt"
            data.write_text("original", encoding="utf-8")
            marker.write_text("keep", encoding="utf-8")

            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "command": (
                            f"_kc_root={decoy}; "
                            "printf changed > data.txt; "
                            "printf done"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("done"))
            self.assertEqual(data.read_text(encoding="utf-8"), "original")
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_shell_exec_original_files_root_is_stable_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.txt"
            data.write_text("original", encoding="utf-8")

            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "command": (
                            "printf changed > data.txt; "
                            "printf corrupted > \"$CTF_ORIGINAL_FILES_ROOT/data.txt\"; "
                            "printf '%s|' \"$(cat data.txt)\"; "
                            "printf '%s' \"$(cat \"$CTF_ORIGINAL_FILES_ROOT/data.txt\")\""
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("changed|corrupted"))
            self.assertEqual(data.read_text(encoding="utf-8"), "original")

    def test_shell_exec_exposes_disposable_temp_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker_file = root / "marker.txt"

            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "command": (
                            "test -n \"$CTF_TEMP_DIR\"; "
                            "test \"$TMPDIR\" = \"$CTF_TEMP_DIR\"; "
                            "printf shell-temp > \"$CTF_TEMP_DIR/marker.txt\"; "
                            "cat \"$CTF_TEMP_DIR/marker.txt\""
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("shell-temp"))
            self.assertFalse(marker_file.exists())

    def test_shell_exec_persists_generated_artifacts_under_files_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=5,
                metadata={
                    "files_root": str(root),
                    "command": "mkdir -p generated && printf durable > generated/result.txt && printf done",
                },
            )

            result = ShellPlugin().execute(request)
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("done"))
            self.assertIn("__KILLCHAIN_SCRIPT_ARTIFACTS__", result.stdout)
            self.assertFalse((root / "generated" / "result.txt").exists())
            records = output.output_context["generated_artifact_records"]
            record = next(item for item in records if item["relative_path"] == "generated/result.txt")
            artifact_path = Path(str(record["path"]))
            self.assertEqual(record["origin"], "work")
            self.assertEqual(artifact_path.read_text(encoding="utf-8"), "durable")
            self.assertTrue(str(artifact_path).startswith(str(root / ".autopentest_artifacts")))
            self.assertEqual(output.output_context["generated_artifacts_durable"], True)
            self.assertEqual(output.artifacts[0].source, "shell_exec")
            self.assertRegex(str(record["digest"]), r"^[0-9a-f]{64}$")

    def test_shell_exec_prioritizes_readable_generated_artifacts_before_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=10,
                metadata={
                    "files_root": str(root),
                    "command": (
                        "mkdir -p blobs; "
                        "for i in $(seq -w 1 45); do "
                        "  printf '\\000\\001\\002\\003' > \"blobs/blob_$i\"; "
                        "done; "
                        "printf 'plain searchable configuration text\\n' > readable_target; "
                        "printf done"
                    ),
                },
            )

            result = ShellPlugin().execute(request)
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            records = output.output_context["generated_artifact_records"]
            relative_paths = {str(record["relative_path"]) for record in records}
            self.assertLessEqual(len(records), 40)
            self.assertIn("readable_target", relative_paths)
            self.assertEqual(output.artifacts[0].metadata["relative_path"], "readable_target")

    def test_shell_exec_prioritizes_source_like_artifacts_over_html_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=10,
                metadata={
                    "files_root": str(root),
                    "command": (
                        "mkdir -p docs; "
                        "for i in $(seq -w 1 45); do "
                        "  printf '<html><body>reference document</body></html>\\n' > \"docs/doc_$i\"; "
                        "done; "
                        "printf '#!/bin/sh\\necho important\\n' > source_like; "
                        "chmod +x source_like; "
                        "printf done"
                    ),
                },
            )

            result = ShellPlugin().execute(request)
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            records = output.output_context["generated_artifact_records"]
            relative_paths = [str(record["relative_path"]) for record in records]
            self.assertIn("source_like", relative_paths)
            self.assertEqual(relative_paths[0], "source_like")

    def test_shell_exec_enforces_workspace_growth_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=8,
                    metadata={
                        "files_root": tmp,
                        "max_workspace_mb": 1,
                        "command": (
                            'dd if=/dev/zero of="$CTF_TEMP_DIR/blob" '
                            "bs=1048576 count=2; sleep 3"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 125)
            self.assertIn("workspace budget exceeded", result.stderr)

    def test_shell_exec_uses_pipefail_for_pipeline_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=5,
                metadata={
                    "files_root": tmp,
                    "command": "python3 -c 'import sys; sys.exit(7)' | head -1",
                },
            )

            result = ShellPlugin().execute(request)
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 7)
            self.assertEqual(output.status, ToolOutputStatus.FAILURE)

    def test_shell_exec_wraps_user_command_with_resource_limits(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.shell._run", side_effect=fake_run):
                ShellPlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                    ToolExecutionRequest(
                        tool_name="shell_exec",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "max_memory_mb": 128,
                            "max_cpu_s": 7,
                            "command": "python3 -c 'print(1)'",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("_kc_memory_limit_kb=131072", command)
        self.assertIn("_kc_cpu_limit_s=7", command)
        self.assertIn("ulimit -v", command)
        self.assertIn("ulimit -t", command)

    def test_artifact_triage_preserves_generated_png_payload_artifacts(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.artifact_triage._run", side_effect=fake_run):
                ArtifactTriagePlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                    ToolExecutionRequest(
                        tool_name="artifact_triage",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "path": f"{tmp}/out.png",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("__KILLCHAIN_ARTIFACT_TRIAGE_PNG__", command)
        self.assertIn(".autopentest_artifacts", command)
        self.assertIn("_kc_preserve_paths=.autopentest_artifacts", command)

    def test_foremost_rehomes_requested_tmp_output_to_durable_artifacts(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.foremost._run", side_effect=fake_run):
                ForemostPlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                    ToolExecutionRequest(
                        tool_name="foremost",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "path": f"{tmp}/out.img",
                            "output_dir": "/tmp/foremost_out",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn(".autopentest_artifacts/foremost_out_foremost_out_", command)
        self.assertIn("_kc_preserve_paths=.autopentest_artifacts", command)
        self.assertNotIn("_kc_out=/tmp/foremost_out", command)

    def test_binwalk_signatures_are_successful_evidence_even_with_nonzero_exit(self) -> None:
        request = ToolExecutionRequest(
            tool_name="binwalk",
            timeout_s=5,
            metadata={"path": "/home/ctfplayer/ctf_files/out.img"},
        )
        result = ToolExecutionResult(
            tool_name="binwalk",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=1,
            stdout=(
                "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
                "1024          0x400           Zip archive data, at least v2.0\n"
            ),
            stderr="warning: extractor disabled\n",
        )

        output = binwalk_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.status, ToolOutputStatus.SUCCESS)
        self.assertEqual(output.output_context["signature_count"], 1)

    def test_shell_exec_blocks_direct_tmp_scratch_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = ShellPlugin().execute(
                ToolExecutionRequest(
                    tool_name="shell_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": tmp,
                        "command": "printf leak > /tmp/leak.txt",
                    },
                )
            )

            self.assertEqual(result.exit_code, 126)
            self.assertIn("CTF_TEMP_DIR", result.stderr)

    def test_shell_exec_blocks_raw_binwalk_extraction_before_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=5,
                metadata={
                    "files_root": tmp,
                    "command": "cd . && binwalk -e out.img -C $CTF_TEMP_DIR",
                },
            )
            result = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"]).execute(
                request
            )
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 126)
            self.assertIn("raw binwalk extraction", result.stderr)
            self.assertEqual(output.output_context["failure_kind"], "unbounded_extraction_blocked")

    def test_shell_exec_blocks_unbounded_byte_dd_before_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = ToolExecutionRequest(
                tool_name="shell_exec",
                timeout_s=5,
                metadata={
                    "files_root": tmp,
                    "command": "dd if=out.img of=$CTF_TEMP_DIR/blob.zip bs=1 skip=304128",
                },
            )
            result = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"]).execute(
                request
            )
            output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 126)
            self.assertIn("byte-by-byte extraction", result.stderr)
            self.assertEqual(output.output_context["failure_kind"], "unbounded_extraction_blocked")

    def test_script_exec_runs_in_disposable_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.txt"
            data.write_text("original", encoding="utf-8")

            result = ScriptPlugin().execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "script_language": "python",
                        "script_code": (
                            "import os\n"
                            "from pathlib import Path\n"
                            "path = Path(os.environ['CTF_FILES_ROOT']) / 'data.txt'\n"
                            "print(path.read_text(), end='')\n"
                            "path.write_text('changed')\n"
                            "Path('extra.txt').write_text('temporary')\n"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("original"))
            self.assertEqual(result.stderr, "")
            self.assertEqual(data.read_text(encoding="utf-8"), "original")
            self.assertFalse((root / "extra.txt").exists())

    def test_script_exec_persists_new_workdir_artifacts_with_file_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = ToolExecutionRequest(
                tool_name="script_exec",
                timeout_s=5,
                metadata={
                    "files_root": str(root),
                    "script_language": "python",
                    "script_code": (
                        "import base64\n"
                        "png = base64.b64decode(\n"
                        "    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII='\n"
                        ")\n"
                        "open('generated.png', 'wb').write(png)\n"
                        "print('wrote')\n"
                    ),
                },
            )

            result = ScriptPlugin().execute(request)
            output = script_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0)
            records = output.output_context["generated_artifact_records"]
            record = next(item for item in records if item["relative_path"] == "generated.png")
            self.assertEqual(record["origin"], "work")
            self.assertRegex(str(record["digest"]), r"^[0-9a-f]{64}$")
            self.assertIn("png", str(record["mime_type"]).lower())
            self.assertIn("png", str(record["file_type"]).lower())
            artifact = next(item for item in output.artifacts if item.path == record["path"])
            self.assertEqual(artifact.kind, "script_artifact_png")
            self.assertEqual(artifact.digest, record["digest"])
            self.assertEqual(artifact.metadata["mime_type"], record["mime_type"])
            self.assertFalse((root / "generated.png").exists())

    def test_script_exec_tempfile_uses_disposable_temp_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = ScriptPlugin().execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "script_language": "python",
                        "script_code": (
                            "import os, tempfile\n"
                            "scratch = tempfile.mkdtemp()\n"
                            "open(os.path.join(scratch, 'marker.txt'), 'w').write('x')\n"
                            "print(str(scratch.startswith(os.environ['CTF_TEMP_DIR'])) + '|', end='')\n"
                            "print(str(os.environ['TMPDIR'] == os.environ['CTF_TEMP_DIR']), end='')\n"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("True|True"))

    def test_script_exec_persists_scratch_artifacts_under_files_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = ToolExecutionRequest(
                tool_name="script_exec",
                timeout_s=5,
                metadata={
                    "files_root": str(root),
                    "script_language": "python",
                    "script_code": (
                        "import os\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['CTF_TEMP_DIR'], 'nested').mkdir()\n"
                        "Path(os.environ['CTF_TEMP_DIR'], 'nested', 'result.bin').write_bytes(b'durable')\n"
                        "print('done', end='')\n"
                    ),
                },
            )

            result = ScriptPlugin().execute(request)
            output = script_output_builder(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0)
            self.assertIn("__KILLCHAIN_SCRIPT_ARTIFACTS__", result.stdout)
            records = output.output_context["generated_artifact_records"]
            self.assertEqual(len(records), 1)
            artifact_path = Path(str(records[0]["path"]))
            self.assertEqual(artifact_path.read_bytes(), b"durable")
            self.assertTrue(str(artifact_path).startswith(str(root / ".autopentest_artifacts")))
            self.assertEqual(output.artifacts[0].path, str(artifact_path))
            self.assertRegex(str(records[0]["digest"]), r"^[0-9a-f]{64}$")

    def test_script_exec_enforces_workspace_growth_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = ScriptPlugin().execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=8,
                    metadata={
                        "files_root": tmp,
                        "max_workspace_mb": 1,
                        "script_language": "python",
                        "script_code": (
                            "import os, time\n"
                            "path = os.path.join(os.environ['CTF_TEMP_DIR'], 'blob')\n"
                            "open(path, 'wb').write(b'0' * (2 * 1024 * 1024))\n"
                            "time.sleep(3)\n"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 125)
            self.assertIn("workspace budget exceeded", result.stderr)

    def test_script_exec_wraps_generated_script_with_resource_limits(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.script._run", side_effect=fake_run):
                ScriptPlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                    ToolExecutionRequest(
                        tool_name="script_exec",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "script_language": "python",
                            "max_memory_mb": 256,
                            "max_cpu_s": 11,
                            "script_code": "print('ok')",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("_kc_memory_limit_kb=262144", command)
        self.assertIn("_kc_cpu_limit_s=11", command)
        self.assertIn("ulimit -v", command)
        self.assertIn("ulimit -t", command)

    def test_script_exec_blocks_direct_tmp_scratch_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = ScriptPlugin().execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": tmp,
                        "script_language": "python",
                        "script_code": "open('/tmp/leak.txt', 'w').write('x')\n",
                    },
                )
            )

            self.assertEqual(result.exit_code, 126)
            self.assertIn("CTF_TEMP_DIR", result.stderr)

    def test_script_exec_original_files_root_is_separate_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data.txt"
            data.write_text("original", encoding="utf-8")

            result = ScriptPlugin().execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=5,
                    metadata={
                        "files_root": str(root),
                        "script_language": "python",
                        "script_code": (
                            "import os\n"
                            "from pathlib import Path\n"
                            "work = Path(os.environ['CTF_FILES_ROOT']) / 'data.txt'\n"
                            "orig = Path(os.environ['CTF_ORIGINAL_FILES_ROOT']) / 'data.txt'\n"
                            "work.write_text('changed')\n"
                            "orig.write_text('corrupted')\n"
                            "print(work.read_text() + '|' + orig.read_text(), end='')\n"
                        ),
                    },
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.startswith("changed|corrupted"))
            self.assertEqual(data.read_text(encoding="utf-8"), "original")

    def test_ltrace_runs_under_protected_workspace(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(
                tool_name=name,
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

        with patch("killchain_docker.tools.plugins.ltrace._run", side_effect=fake_run):
            LtracePlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                ToolExecutionRequest(
                    tool_name="ltrace",
                    timeout_s=5,
                    metadata={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "path": "/home/ctfplayer/ctf_files/app",
                        "args": "/home/ctfplayer/ctf_files/input.dat",
                    },
                )
            )

        argv = captured["argv"]
        self.assertIsInstance(argv, list)
        command = argv[-1]
        self.assertIn("_kc_restore()", command)
        self.assertIn("CTF_ORIGINAL_FILES_ROOT", command)
        self.assertIn("ltrace", command)

    def test_strace_runs_under_protected_workspace(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            return ToolExecutionResult(
                tool_name=name,
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

        with patch("killchain_docker.tools.plugins.strace._run", side_effect=fake_run):
            StracePlugin().execute(
                ToolExecutionRequest(
                    tool_name="strace",
                    timeout_s=5,
                    metadata={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "path": "/home/ctfplayer/ctf_files/app",
                    },
                )
            )

        command = captured["argv"][-1]
        self.assertIn("_kc_restore()", command)
        self.assertIn("CTF_ORIGINAL_FILES_ROOT", command)
        self.assertIn("strace", command)

    def test_gdb_runs_under_protected_workspace(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            return ToolExecutionResult(
                tool_name=name,
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

        with patch("killchain_docker.tools.plugins.gdb._run", side_effect=fake_run):
            GdbPlugin().execute(
                ToolExecutionRequest(
                    tool_name="gdb",
                    timeout_s=5,
                    metadata={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "path": "/home/ctfplayer/ctf_files/app",
                        "commands": "run /home/ctfplayer/ctf_files/input.dat",
                    },
                )
            )

        command = captured["argv"][-1]
        self.assertIn("_kc_restore()", command)
        self.assertIn("CTF_ORIGINAL_FILES_ROOT", command)
        self.assertIn("gdb", command)

    def test_binwalk_extract_runs_under_bounded_scratch_workspace(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(
                tool_name=name,
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

        with patch("killchain_docker.tools.plugins.binwalk._run", side_effect=fake_run):
            BinwalkPlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                ToolExecutionRequest(
                    tool_name="binwalk",
                    timeout_s=5,
                    metadata={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "path": "/home/ctfplayer/ctf_files/out.img",
                        "extract": True,
                        "max_extract_mb": 12,
                    },
                )
            )

        command = captured["argv"][-1]
        self.assertIn("_kc_restore()", command)
        self.assertIn("CTF_TEMP_DIR", command)
        self.assertIn("binwalk_out", command)
        self.assertIn("--run-as=root", command)
        self.assertIn("12288KB", command)
        self.assertNotIn("/tmp/binwalk_out", command)

    def test_binwalk_output_marks_extracted_files_ephemeral(self) -> None:
        output = binwalk_output_builder(
            ToolExecutionRequest(
                tool_name="binwalk",
                metadata={
                    "path": "/home/ctfplayer/ctf_files/out.img",
                    "extract": True,
                },
            ),
            ToolExecutionResult(
                tool_name="binwalk",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=(
                    "304128 0x4A400 Zip archive data\n"
                    "/tmp/_shell_exec_abcd/scratch/binwalk_out/image0.gif\t4096\n"
                ),
                stderr="[binwalk extraction budget exceeded: 300000KB > 262144KB]",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.artifacts, [])
        self.assertIn("scratch file", output.summary)
        self.assertTrue(output.output_context["extracted_files_ephemeral"])
        self.assertTrue(output.output_context["extraction_budget_exceeded"])
        self.assertIn("same tool call", output.notes[0])


if __name__ == "__main__":
    unittest.main()
