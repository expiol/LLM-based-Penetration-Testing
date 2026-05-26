"""Tests for tool metadata contracts."""

from __future__ import annotations
import unittest
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionError
from killchain_docker.workers.tooling.contracts.catalog import tool_metadata_contract
from killchain_docker.workers.tooling.metadata.router import normalize_tool_metadata


class ToolMetadataContractTests(unittest.TestCase):
    def test_shell_exec_contract_requires_command(self) -> None:
        contract = tool_metadata_contract(ToolCapability.SHELL_EXEC)
        self.assertIn("command", contract["required"])

    def test_script_exec_contract_requires_script_code(self) -> None:
        contract = tool_metadata_contract(ToolCapability.SCRIPT_EXEC)
        self.assertIn("script_code", contract["required"])

    def test_artifact_triage_context_path_overrides_challenge_file_defaults(
        self,
    ) -> None:
        state = RunState(
            objective="solve", metadata={"challenge": {"files": ["sleeping_dist.py"]}}
        )
        generated = "/home/ctfplayer/ctf_files/.autopentest_artifacts/script/out.png"
        todo = TodoItem(
            goal="Triaged generated artifact",
            context={
                "path": generated,
                "challenge_files": ["sleeping_dist.py"],
                "files_root": "/home/ctfplayer/ctf_files",
            },
        )
        result = normalize_tool_metadata(
            ToolCapability.ARTIFACT_TRIAGE, todo, state, {}
        )
        self.assertEqual(result["paths"], [generated])

    def test_disk_extract_uses_context_path_for_direct_hint(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="Extract disk image",
            context={
                "path": "out.img",
                "files_root": "/home/ctfplayer/ctf_files",
                "max_extract_mb": 32,
            },
        )
        result = normalize_tool_metadata(ToolCapability.DISK_EXTRACT, todo, state, {})
        self.assertEqual(result["path"], "/home/ctfplayer/ctf_files/out.img")
        self.assertEqual(result["max_extract_mb"], 32)

    def test_disk_extract_requires_some_path_source(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="Extract disk image")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.DISK_EXTRACT, todo, state, {})

    def test_office_inspect_uses_context_path_for_direct_hint(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="Inspect Office document",
            context={
                "path": "deck.pptx",
                "files_root": "/home/ctfplayer/ctf_files",
                "max_text_chars": 600,
            },
        )
        result = normalize_tool_metadata(ToolCapability.OFFICE_INSPECT, todo, state, {})
        self.assertEqual(result["path"], "/home/ctfplayer/ctf_files/deck.pptx")
        self.assertEqual(result["max_text_chars"], 600)

    def test_office_inspect_requires_some_path_source(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="Inspect Office document")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.OFFICE_INSPECT, todo, state, {})

    def test_png_inspect_uses_context_path_for_direct_hint(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="Inspect PNG image",
            context={
                "path": "image.png",
                "files_root": "/home/ctfplayer/ctf_files",
                "max_lsb_bytes": 2048,
            },
        )
        result = normalize_tool_metadata(ToolCapability.PNG_INSPECT, todo, state, {})
        self.assertEqual(result["path"], "/home/ctfplayer/ctf_files/image.png")
        self.assertEqual(result["max_lsb_bytes"], 2048)

    def test_png_inspect_requires_some_path_source(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="Inspect PNG image")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.PNG_INSPECT, todo, state, {})

    def test_media_scan_normalizes_batch_paths(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="Scan embedded media",
            context={
                "paths": ["ppt/media/image0.gif", "ppt/media/image1.png"],
                "files_root": "/home/ctfplayer/ctf_files",
                "max_files": 12,
            },
        )
        result = normalize_tool_metadata(ToolCapability.MEDIA_SCAN, todo, state, {})
        self.assertEqual(
            result["paths"],
            [
                "/home/ctfplayer/ctf_files/ppt/media/image0.gif",
                "/home/ctfplayer/ctf_files/ppt/media/image1.png",
            ],
        )
        self.assertEqual(result["max_files"], 12)

    def test_media_scan_requires_some_path_source(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="Scan embedded media")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.MEDIA_SCAN, todo, state, {})

    def test_cli_path_normalization_allows_spaces_and_unicode(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="Inspect unusual path",
            context={
                "path": "folder with spaces/文件",
                "files_root": "/home/ctfplayer/ctf_files",
            },
        )
        result = normalize_tool_metadata(
            ToolCapability.ARTIFACT_TRIAGE, todo, state, {}
        )
        self.assertEqual(
            result["paths"], ["/home/ctfplayer/ctf_files/folder with spaces/文件"]
        )

    def test_shell_exec_normalization_requires_command(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SHELL_EXEC, todo, state, {})

    def test_shell_exec_normalization_passes_command(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC, todo, state, {"command": "nmap -sV 127.0.0.1"}
        )
        self.assertEqual(result["command"], "nmap -sV 127.0.0.1")
        self.assertEqual(result["authorized_scope"], ["tcp://example:31337"])

    def test_selected_command_overrides_stale_context_command(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"command": "rm -rf stale"})
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC, todo, state, {"command": "echo current"}
        )
        self.assertEqual(result["command"], "echo current")

    def test_required_command_cannot_be_satisfied_by_context(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"command": "echo hidden"})
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SHELL_EXEC, todo, state, {})

    def test_shell_exec_rejects_package_install_before_execution(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaisesRegex(ToolExecutionError, "package installation"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC,
                todo,
                state,
                {"command": "python3 -m pip install angr"},
            )

    def test_shell_exec_rejects_multiline_source_heredoc(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        command = "cat <<'EOF' > /tmp/runner.c\n#include <stdio.h>\nint main(){return 0;}\nEOF\ngcc /tmp/runner.c"
        with self.assertRaisesRegex(ToolExecutionError, "script.exec"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC, todo, state, {"command": command}
            )

    def test_shell_exec_rejects_complex_python_one_liner(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        command = "python3 -c \"import socket; data=b''; while True: chunk=sock.recv(4096); data += chunk\""
        with self.assertRaisesRegex(ToolExecutionError, "script.exec"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC, todo, state, {"command": command}
            )

    def test_shell_exec_rejects_raw_binwalk_extraction(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaisesRegex(ToolExecutionError, "raw binwalk extraction"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC,
                todo,
                state,
                {
                    "command": "cd /home/ctfplayer/ctf_files && binwalk -e out.img -C $CTF_TEMP_DIR"
                },
            )

    def test_shell_exec_rejects_unbounded_byte_dd_extraction(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaisesRegex(ToolExecutionError, "byte-by-byte extraction"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC,
                todo,
                state,
                {"command": "dd if=out.img of=$CTF_TEMP_DIR/blob.zip bs=1 skip=304128"},
            )

    def test_shell_exec_allows_bounded_byte_dd_extraction(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC,
            todo,
            state,
            {
                "command": "dd if=out.img of=$CTF_TEMP_DIR/chunk.bin bs=1 skip=304128 count=4096"
            },
        )
        self.assertEqual(
            result["command"],
            "dd if=out.img of=$CTF_TEMP_DIR/chunk.bin bs=1 skip=304128 count=4096",
        )

    def test_shell_exec_rejects_non_http_curl_before_execution(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test")
        with self.assertRaisesRegex(ToolExecutionError, "non-HTTP URL"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC,
                todo,
                state,
                {
                    "command": "curl -v --connect-timeout 10 --max-time 15 tcp://example:31337 2>&1 || echo CURL_FAILED"
                },
            )

    def test_shell_exec_allows_http_curl(self) -> None:
        state = RunState(objective="solve", authorized_scope=["http://example:8080"])
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC,
            todo,
            state,
            {"command": "curl -sS http://example:8080/health"},
        )
        self.assertEqual(result["command"], "curl -sS http://example:8080/health")

    def test_shell_exec_normalizes_stderr_suppression(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC,
            todo,
            state,
            {"command": "mmls out.img 2>/dev/null && fls -rd out.img &>/dev/null"},
        )
        self.assertEqual(
            result["command"], "mmls out.img  && fls -rd out.img > /dev/null"
        )

    def test_shell_exec_allows_stderr_to_stdout_redirect(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC,
            todo,
            state,
            {"command": "mmls out.img 2>&1 | head -50"},
        )
        self.assertEqual(result["command"], "mmls out.img 2>&1 | head -50")

    def test_script_exec_normalization_requires_script_code(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SCRIPT_EXEC, todo, state, {})

    def test_script_exec_normalization_passes_script_code(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": "print('hello')"}
        )
        self.assertEqual(result["script_code"], "print('hello')")
        self.assertEqual(result["script_language"], "python")

    def test_script_exec_normalization_rejects_invalid_python(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaisesRegex(ToolExecutionError, "Python syntax invalid"):
            normalize_tool_metadata(
                ToolCapability.SCRIPT_EXEC,
                todo,
                state,
                {"script_code": "print('unterminated"},
            )

    def test_script_exec_allows_unguarded_third_party_imports_until_runtime(
        self,
    ) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC,
            todo,
            state,
            {"script_code": "import pytesseract\nprint('ocr')\n"},
        )
        self.assertIn("import pytesseract", result["script_code"])

    def test_script_exec_allows_guarded_optional_imports(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC,
            todo,
            state,
            {
                "script_code": "try:\n    import pytesseract\nexcept ImportError:\n    pytesseract = None\nprint('fallback ready')\n"
            },
        )
        self.assertIn("fallback ready", result["script_code"])

    def test_script_exec_rejects_ambient_flag_search_before_execution(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test", context={"files_root": "/challenge/files"})
        script = "from pathlib import Path\nimport subprocess\nsubprocess.run(['grep', '-R', 'flag', '/tmp'])\nprint('search flag candidates')\n"
        with self.assertRaisesRegex(ToolExecutionError, "script.exec blocked"):
            normalize_tool_metadata(
                ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": script}
            )

    def test_script_exec_allows_remote_protocol_command_strings(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test", context={"files_root": "/challenge/files"})
        script = "import socket\nsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nsock.connect(('example', 31337))\nsock.sendall(b'cat /home/service/flag\\n')\nprint('requesting remote shell command: cat /home/service/flag')\n# Remote payload may execute system('/bin/sh') on the target.\n"
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": script}
        )
        self.assertIn("sock.sendall", result["script_code"])

    def test_script_exec_rejects_subprocess_ambient_flag_search(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test", context={"files_root": "/challenge/files"})
        script = "import subprocess\nsubprocess.run(['cat', '/flag'], check=False)\n"
        with self.assertRaisesRegex(ToolExecutionError, "script.exec blocked"):
            normalize_tool_metadata(
                ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": script}
            )

    def test_script_exec_allows_python_find_on_own_temp_file(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test", context={"files_root": "/challenge/files"})
        script = "from pathlib import Path\npath = Path('/tmp/current-output.bin')\npath.write_bytes(b'not a flag candidate')\ndata = path.read_bytes()\nprint(data.find(b'flag'))\n"
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": script}
        )
        rewritten = str(result["script_code"])
        self.assertIn("CTF_TEMP_DIR", rewritten)
        self.assertNotIn("/tmp/current-output.bin", rewritten)
        compile(rewritten, "<rewritten>", "exec")

    def test_script_exec_rewrites_direct_tmp_scratch_literals(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        script = "from __future__ import annotations\nfrom pathlib import Path\nout = Path('/tmp/recovered/image.png')\nout.parent.mkdir(parents=True, exist_ok=True)\nout.write_bytes(b'data')\nprint(out)\n"
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": script}
        )
        rewritten = str(result["script_code"])
        self.assertNotIn("/tmp/recovered/image.png", rewritten)
        self.assertIn("CTF_TEMP_DIR", rewritten)
        compile(rewritten, "<rewritten>", "exec")
        self.assertLess(
            rewritten.index("from __future__ import annotations"),
            rewritten.index("import os"),
        )

    def test_shell_exec_rejects_ambient_flag_search_before_execution(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test", context={"files_root": "/challenge/files"})
        with self.assertRaisesRegex(ToolExecutionError, "shell.exec blocked"):
            normalize_tool_metadata(
                ToolCapability.SHELL_EXEC,
                todo,
                state,
                {"command": "find /tmp -name '*flag*' -print"},
            )

    def test_selected_script_code_overrides_stale_context_script(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"script_code": "print('stale')"})
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": "print('current')"}
        )
        self.assertEqual(result["script_code"], "print('current')")

    def test_required_script_code_cannot_be_satisfied_by_context(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"script_code": "print('hidden')"})
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SCRIPT_EXEC, todo, state, {})

    def test_context_can_supply_optional_defaults_only(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(
            goal="test", context={"files_root": "/tmp/ctf", "timeout_s": 42}
        )
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": "print('hello')"}
        )
        self.assertEqual(result["script_code"], "print('hello')")
        self.assertEqual(result["files_root"], "/tmp/ctf")
        self.assertEqual(result["timeout_s"], 42)

    def test_authorized_scope_does_not_auto_extend_script_timeout(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": "print('hello')"}
        )
        self.assertNotIn("timeout_s", result)

    def test_script_exec_normalizes_language(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC,
            todo,
            state,
            {"script_code": "echo hi", "script_language": "shell"},
        )
        self.assertEqual(result["script_language"], "bash")

    def test_script_exec_passes_flag_format_from_challenge(self) -> None:
        state = RunState(
            objective="solve", metadata={"challenge": {"flag_format": "flag{...}"}}
        )
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state, {"script_code": "print(1)"}
        )
        self.assertEqual(result["flag_format"], "flag{...}")

    def test_curl_rejects_explicit_non_http_scheme_before_execution(self) -> None:
        state = RunState(objective="solve", authorized_scope=["tcp://example:31337"])
        todo = TodoItem(goal="validate raw tcp flag")
        with self.assertRaisesRegex(ToolExecutionError, "HTTP/HTTPS"):
            normalize_tool_metadata(
                ToolCapability.CURL, todo, state, {"url": "tcp://example:31337"}
            )

    def test_curl_allows_http_url(self) -> None:
        state = RunState(objective="solve", authorized_scope=["http://example:8080"])
        todo = TodoItem(goal="fetch page")
        result = normalize_tool_metadata(
            ToolCapability.CURL,
            todo,
            state,
            {"url": "https://example.test/login", "method": "POST"},
        )
        self.assertEqual(result["url"], "https://example.test/login")
        self.assertEqual(result["method"], "POST")

    def test_path_cli_tool_resolves_relative_path_under_files_root(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.FILE_CMD, todo, state, {"path": "stfu"}
        )
        self.assertEqual(result["path"], "/home/ctfplayer/ctf_files/stfu")

    def test_path_cli_tool_respects_context_files_root(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"files_root": "/tmp/challenge"})
        result = normalize_tool_metadata(
            ToolCapability.STRINGS_CMD, todo, state, {"path": "./payload.bin"}
        )
        self.assertEqual(result["path"], "/tmp/challenge/payload.bin")

    def test_path_cli_tool_leaves_absolute_path_unchanged(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test", context={"files_root": "/tmp/challenge"})
        result = normalize_tool_metadata(
            ToolCapability.FILE_CMD, todo, state, {"path": "/tmp/challenge/stfu"}
        )
        self.assertEqual(result["path"], "/tmp/challenge/stfu")

    def test_path_cli_tool_rejects_shell_fragments(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(
                ToolCapability.FILE_CMD, todo, state, {"path": "stfu; cat flag.stfu"}
            )


if __name__ == "__main__":
    unittest.main()
