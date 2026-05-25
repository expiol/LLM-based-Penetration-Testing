"""Guardrails for script execution (flag plausibility + challenge file metadata).

Updated for 2-capability architecture — tests that validated the deleted
script_execution plugin payload format are removed; flag plausibility and
bracket-span tests are preserved as-is since they test state/constants.
"""

from __future__ import annotations

import base64
import unittest
import tempfile
from unittest.mock import patch

from killchain_docker.reasoning import flag as flag_module
from killchain_docker.reasoning.flag import (
    _bracket_span_candidates,
    extract_flag_candidates,
)
from killchain_docker.state.constants import plausible_flag, validatable_flag_candidate as is_validatable_flag_candidate
from killchain_docker.tools import ToolCapability
from killchain_docker.tools import ExecutionPlane, ToolGateway
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from killchain_docker.tools.plugins import _base as tool_base
from killchain_docker.tools.plugins import script as script_module
from killchain_docker.tools.plugins.artifact_triage import (
    _END_MARKER,
    _FILE_CMD_MARKER,
    _FILE_MARKER,
    _STRINGS_MARKER,
)
from killchain_docker.tools.plugins.artifact_triage import build_output as build_artifact_triage_output
from killchain_docker.tools.plugins.disk_extract import (
    _FILE_MARKER as _DISK_FILE_MARKER,
)
from killchain_docker.tools.plugins.disk_extract import build_output as build_disk_extract_output
from killchain_docker.tools.plugins.office_inspect import (
    _TEXT_MARKER as _OFFICE_TEXT_MARKER,
)
from killchain_docker.tools.plugins.office_inspect import build_output as build_office_inspect_output
from killchain_docker.tools.plugins.media_scan import (
    _ARTIFACT_MARKER as _MEDIA_ARTIFACT_MARKER,
    _MEDIA_MARKER,
)
from killchain_docker.tools.plugins.media_scan import build_output as build_media_scan_output
from killchain_docker.tools.plugins.png_inspect import (
    _LSB_MARKER as _PNG_LSB_MARKER,
    _PNG_MARKER as _PNG_DOC_MARKER,
)
from killchain_docker.tools.plugins.png_inspect import build_output as build_png_inspect_output
from killchain_docker.tools.plugins.script import ScriptPlugin
from killchain_docker.tools.plugins.script import build_output as build_script_output
from killchain_docker.state import RunState, TodoItem, TodoPhase
from killchain_docker.llm import StaticLLMClient
from killchain_docker.workers.protocols import ARTIFACT_PERSONA
from killchain_docker.workers.worker import Worker, _is_flag_recovery_task


class _StaticArtifactTriagePlugin:
    name = "artifact_triage"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        path = "/home/ctfplayer/ctf_files/out.bin"
        stdout = "\n".join(
            [
                f"{_FILE_MARKER}\t{path}\t32",
                _FILE_CMD_MARKER,
                "ASCII text",
                "text/plain",
                _STRINGS_MARKER,
                "FLAG FOUND: flag{triaged_candidate}",
                _END_MARKER,
            ]
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )


class _StaticDiskExtractPlugin:
    name = "disk_extract"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        path = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "disk_extract_out/offset_0/slides.pptx"
        )
        stdout = "\n".join(
            [
                f"{_DISK_FILE_MARKER}\t{path}\t32\tfilesystem\t0\t12\tSLIDES.PPTX",
                "FLAG FOUND: flag{disk_extract_candidate}",
            ]
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )


class _StaticOfficeInspectPlugin:
    name = "office_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        stdout = "\n".join(
            [
                "__KILLCHAIN_OFFICE_INSPECT_DOC__\tpptx\t1",
                f"{_OFFICE_TEXT_MARKER}\tppt/slides/slide1.xml\tslide\tflag{{office_candidate}}",
            ]
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )


class _StaticMediaScanPlugin:
    name = "media_scan"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        path = "/home/ctfplayer/ctf_files/ppt/media/image1.gif"
        artifact = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "media_scan_out/image1.appended.bin"
        )
        stdout = "\n".join(
            [
                f"{_MEDIA_MARKER}\t{path}\t96\tgif\t1\t24\t{artifact}\tflag{{media_candidate}}\tappended_payload=24",
                f"{_MEDIA_ARTIFACT_MARKER}\t{artifact}\t24\tappended\t{path}\tdeadbeef",
            ]
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )


class _StaticPngInspectPlugin:
    name = "png_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        stdout = "\n".join(
            [
                f"{_PNG_DOC_MARKER}\t64\t8\t8\t2\t0\t1",
                f"{_PNG_LSB_MARKER}\tall\t1\tmsb\t32\t0.900\t\tflag{{png_candidate}}\tflag{{png_candidate}}",
            ]
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )


class TestPlausibleFlagFormatEcho(unittest.TestCase):
    def test_rejects_debug_format_fragments(self) -> None:
        self.assertFalse(plausible_flag("x{seed:08x}"))
        self.assertFalse(plausible_flag("0x{seed:08x} = {seed}"))
        self.assertFalse(plausible_flag("line{x:08x}"))
        self.assertFalse(plausible_flag("fmt{val:08x}"))

    def test_accepts_normal_flags(self) -> None:
        self.assertTrue(plausible_flag("ctf{abc123_xyz}"))
        self.assertTrue(plausible_flag("flag{hello_world_12345}"))
        self.assertTrue(plausible_flag("KEY{PlainBodyHere}"))

    def test_accepts_flags_with_spaces(self) -> None:
        self.assertTrue(plausible_flag("key{And yes the nsa can read this to}"))
        self.assertTrue(plausible_flag("flag{multiple words allowed}"))

    def test_rejects_single_char_prefix(self) -> None:
        self.assertFalse(plausible_flag("t{pagination}"))
        self.assertFalse(plausible_flag("t{link}"))
        self.assertFalse(plausible_flag("f{x:08x}"))

    def test_rejects_template_noise_bodies(self) -> None:
        self.assertFalse(plausible_flag("flag{pagination}"))
        self.assertFalse(plausible_flag("key{link}"))
        self.assertFalse(plausible_flag("ctf{description}"))
        self.assertFalse(plausible_flag("flag{decompressed}"))
        self.assertFalse(plausible_flag("flag{non-standard}"))

    def test_rejects_python_dump_style_prefixes(self) -> None:
        self.assertFalse(plausible_flag("repr{byte_dump_preview}"))
        self.assertFalse(plausible_flag("ascii{garbage}"))
        self.assertFalse(plausible_flag("foo(bar{not_real}"))

    def test_rejects_structured_error_bodies(self) -> None:
        self.assertFalse(
            plausible_flag(
                "flag{'command': './stfu flag.stfu', 'error': \"[Errno 2] No such file or directory: 'strace'\"}"
            )
        )
        self.assertFalse(
            plausible_flag(
                'key{"command": "./stfu", "stderr": "Could not open input file for reading"}'
            )
        )

    def test_rejects_python_repr_and_expression_bodies(self) -> None:
        self.assertFalse(plausible_flag("key{0: 830, 3: 1, 1: 1}"))
        self.assertFalse(plausible_flag("key{'), (82, 'z}"))
        self.assertFalse(plausible_flag("flag{' and '}"))
        self.assertFalse(plausible_flag("oR{t', '3Rj}"))
        self.assertFalse(plausible_flag("flag{os.strerror(err) if err else 'Success'}"))
        self.assertFalse(plausible_flag("flag{'='*80}"))

    def test_rejects_format_placeholders(self) -> None:
        self.assertFalse(plausible_flag("flag{....}"))
        self.assertFalse(plausible_flag("FLAG{????}"))
        self.assertFalse(plausible_flag("ctf{xxxx}"))
        self.assertFalse(plausible_flag("key{____}"))
        self.assertFalse(plausible_flag("flag{<flag>}"))
        self.assertFalse(plausible_flag("ctf{[secret]}"))


class TestValidatableFlagCandidate(unittest.TestCase):
    def test_accepts_canonical_flags(self) -> None:
        self.assertTrue(is_validatable_flag_candidate("flag{abc123}"))
        self.assertTrue(is_validatable_flag_candidate("key{And yes the nsa can read this to}"))

    def test_rejects_short_and_noise_prefixes(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("t{pagination}"))
        self.assertFalse(is_validatable_flag_candidate("t{link}"))
        self.assertFalse(is_validatable_flag_candidate("key{pagination}"))

    def test_accepts_bare_token(self) -> None:
        self.assertTrue(is_validatable_flag_candidate("STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"))

    def test_rejects_low_information_repeated_bare_tokens(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("SSSSSSSSSSSSSSS"))
        self.assertFalse(is_validatable_flag_candidate("TTTTTTTTTTTTTTTTTTTTTTTHHHHHHHHH"))
        self.assertFalse(is_validatable_flag_candidate("CCCCCCCCCCCCCHHHHHHHHH"))
        self.assertFalse(
            is_validatable_flag_candidate(
                "AAAAAAALLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLEEEEEEEEEEEEEEEEEEEEEENNNNNNNN"
            )
        )

    def test_rejects_hexdump_ascii_column_bare_token(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("G.......9.M."))

    def test_rejects_diagnostic_bare_words(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("sequences..."))
        self.assertFalse(is_validatable_flag_candidate("plaintext"))
        self.assertFalse(is_validatable_flag_candidate("flag_not_found"))

    def test_rejects_standard_and_service_fingerprint_bare_tokens(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("IEC61966-2.1"))
        self.assertFalse(is_validatable_flag_candidate("SF-Port8000-TCP"))
        self.assertFalse(is_validatable_flag_candidate("little-endian"))
        self.assertFalse(is_validatable_flag_candidate("decrypted.bin"))

    def test_rejects_metadata_namespace_and_uuid_bare_tokens(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("63A36ECB-BC33-4E88-9986-F84A006F35E4"))
        self.assertFalse(is_validatable_flag_candidate("chromaticity"))
        self.assertFalse(is_validatable_flag_candidate("com.adobe.xmp"))
        self.assertFalse(is_validatable_flag_candidate("22-rdf-syntax-ns"))
        self.assertFalse(is_validatable_flag_candidate("ns.adobe.com"))
        self.assertFalse(is_validatable_flag_candidate("CTF_TEMP_DIR"))

    def test_does_not_reject_bare_token_only_because_it_has_a_suffix_like_segment(self) -> None:
        self.assertTrue(is_validatable_flag_candidate("FLAG.CHALLENGE_BLOB"))
        self.assertFalse(is_validatable_flag_candidate("plaintext.opaque"))
        self.assertFalse(is_validatable_flag_candidate("x02-EJNENHRBX"))
        self.assertTrue(is_validatable_flag_candidate("TEAM.FOUND_SECRET_VALUE"))

    def test_rejects_diagnostic_descriptor_bare_phrases(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("brace-enclosed"))
        self.assertFalse(is_validatable_flag_candidate("ascii-art"))
        self.assertFalse(is_validatable_flag_candidate("long-base64-token"))

    def test_rejects_python_exception_token(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("FileNotFoundError"))

    def test_rejects_format_placeholders(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("flag{....}"))
        self.assertFalse(is_validatable_flag_candidate("FLAG{....}"))
        self.assertFalse(is_validatable_flag_candidate("ctf{....}"))
        self.assertFalse(is_validatable_flag_candidate("key{....}"))
        self.assertFalse(is_validatable_flag_candidate("flag{' and '}"))
        self.assertFalse(is_validatable_flag_candidate("oR{t', '3Rj}"))
        self.assertFalse(is_validatable_flag_candidate("flag{~ayv}"))
        self.assertFalse(is_validatable_flag_candidate("flag{_TL^eb8&W}"))
        self.assertFalse(is_validatable_flag_candidate(r"flag{#=WlCj_B\\He}"))
        self.assertFalse(is_validatable_flag_candidate("flag{MN_P}"))

    def test_rejects_unbounded_prefix_candidates(self) -> None:
        candidate = ("y" * 5000) + "{abc123}"
        self.assertFalse(is_validatable_flag_candidate(candidate))


class TestWorkerInnerLoopPolicy(unittest.TestCase):
    def test_script_rules_do_not_include_domain_specific_pcap_escape(self) -> None:
        rules = " ".join(Worker._tool_use_rules({ToolCapability.SCRIPT_EXEC})).lower()

        self.assertNotIn("pcap extraction", rules)
        self.assertNotIn("packet records", rules)
        self.assertNotIn("reassemble streams", rules)

    def test_script_failure_returns_to_planner_after_prior_diagnostic(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {"capability": "file_cmd", "returncode": 0, "flag_candidates": []},
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "syntax_error",
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_metadata_validation_followed_by_script_failure_allows_one_repair(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": -1,
                "flag_candidates": [],
                "failure_kind": "metadata_validation",
                "executed": False,
            },
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "syntax_error",
                "executed": True,
            },
        ]

        self.assertTrue(Worker._should_continue_after_step(task, prior_steps))

    def test_mechanical_script_failure_after_prior_script_stops(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "failure_kind": "no_candidate",
                "executed": True,
            },
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "undefined_name",
                "executed": True,
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_first_mechanical_script_failure_allows_one_repair(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "undefined_name",
                "executed": True,
            },
        ]

        self.assertTrue(Worker._should_continue_after_step(task, prior_steps))

    def test_first_unbounded_script_guard_allows_one_repair(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "unbounded_loop_guard",
                "executed": True,
            },
        ]

        self.assertTrue(Worker._should_continue_after_step(task, prior_steps))

    def test_first_scope_violation_script_guard_allows_one_repair(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 126,
                "flag_candidates": [],
                "failure_kind": "scope_violation_blocked",
                "executed": True,
            },
        ]

        self.assertTrue(Worker._should_continue_after_step(task, prior_steps))

    def test_first_path_resolution_script_failure_allows_one_repair(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 1,
                "flag_candidates": [],
                "failure_kind": "path_resolution_error",
                "executed": True,
            },
        ]

        self.assertTrue(Worker._should_continue_after_step(task, prior_steps))

    def test_successful_no_candidate_script_returns_to_planner_by_default(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "failure_kind": "no_candidate",
                "executed": True,
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_structured_closure_no_candidate_returns_to_planner(self) -> None:
        task = TodoItem(
            goal="Recover the flag from computed plaintext.",
            context={
                "execution_closure": True,
                "dispatch_intent": {
                    "profile": "execution_closure",
                    "required_capability": "script.exec",
                },
            },
        )
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "failure_kind": "no_candidate",
                "executed": True,
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_near_miss_returns_to_planner_for_explicit_followup(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "near_miss_candidates": ["readable/plaintext-or-ascii-art preview:\nFLAG MAYBE"],
                "failure_kind": "",
                "executed": True,
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_metadata_validation_failure_kind_preserves_repair_signal(self) -> None:
        self.assertEqual(
            Worker._metadata_failure_kind(
                "script.exec Python syntax invalid line 3: unterminated string literal",
                ToolCapability.SCRIPT_EXEC,
            ),
            "syntax_error",
        )
        self.assertEqual(
            Worker._metadata_failure_kind(
                "script.exec blocked: scratch files must use CTF_TEMP_DIR or relative paths, not /tmp",
                ToolCapability.SCRIPT_EXEC,
            ),
            "scope_violation_blocked",
        )
        self.assertEqual(
            Worker._metadata_failure_kind(
                "shell.exec blocked: raw binwalk extraction can expand unboundedly",
                ToolCapability.SHELL_EXEC,
            ),
            "unbounded_extraction_blocked",
        )
        self.assertEqual(
            Worker._metadata_failure_kind(
                "curl blocked: curl supports only HTTP/HTTPS URLs; use script.exec for raw TCP services",
                ToolCapability.CURL,
            ),
            "non_http_url_blocked",
        )
        self.assertEqual(
            Worker._metadata_failure_kind(
                "shell.exec blocked: curl in shell.exec used a non-HTTP URL tcp://example:31337",
                ToolCapability.SHELL_EXEC,
            ),
            "non_http_url_blocked",
        )
        self.assertEqual(
            Worker._metadata_failure_kind(
                "script.exec blocked: unguarded third-party import(s): pytesseract; catch ImportError",
                ToolCapability.SCRIPT_EXEC,
            ),
            "missing_tool",
        )

    def test_stops_after_one_script_repair_attempt(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {"capability": "script.exec", "returncode": 1, "flag_candidates": []},
            {"capability": "script.exec", "returncode": 1, "flag_candidates": []},
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_stops_after_two_no_candidate_script_attempts(self) -> None:
        task = TodoItem(goal="Recover the flag from computed plaintext.")
        prior_steps = [
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "failure_kind": "no_candidate",
            },
            {
                "capability": "script.exec",
                "returncode": 0,
                "flag_candidates": [],
                "failure_kind": "no_candidate",
            },
        ]

        self.assertFalse(Worker._should_continue_after_step(task, prior_steps))

    def test_metadata_validation_retries_once_then_hands_back_to_planner(self) -> None:
        calls = 0

        def invalid_script_response(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "try:\n    print('broken')\n"},
                "rationale": "exercise validation retry",
            }

        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(invalid_script_response),
            tool_gateway=ToolGateway(ExecutionPlane()),
        )
        result = worker.run(
            TodoItem(goal="Recover the flag from computed plaintext."),
            RunState(objective="test"),
        )

        self.assertEqual(calls, 2)
        self.assertFalse(result.success)
        self.assertTrue(result.partial)
        self.assertEqual(result.result_quality, "syntax_error")
        self.assertEqual(result.output_context["executed"], False)
        self.assertEqual(result.output_context["agent_handoff"]["target"], "planner")

    def test_artifact_triage_hint_runs_without_llm_selection(self) -> None:
        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError("LLM tool selection should not run")

        plugin = _StaticArtifactTriagePlugin()
        plane = ExecutionPlane()
        plane.register(plugin, build_artifact_triage_output)
        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(fail_if_called),
            tool_gateway=ToolGateway(plane),
        )

        result = worker.run(
            TodoItem(
                goal="Run deterministic first-pass triage on a newly generated artifact.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "capability_hint": "artifact.triage",
                    "path": "/home/ctfplayer/ctf_files/out.bin",
                },
            ),
            RunState(objective="test"),
        )

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.success)
        self.assertEqual(result.output_context["capability"], "artifact.triage")
        self.assertEqual(
            [candidate.value for candidate in result.state_delta.flag_candidates],
            ["flag{triaged_candidate}"],
        )

    def test_disk_extract_hint_runs_without_llm_selection(self) -> None:
        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError("LLM tool selection should not run")

        plugin = _StaticDiskExtractPlugin()
        plane = ExecutionPlane()
        plane.register(plugin, build_disk_extract_output)
        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(fail_if_called),
            tool_gateway=ToolGateway(plane),
        )

        result = worker.run(
            TodoItem(
                goal="Extract files from the detected disk image.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "forensics-extract",
                    "capability_hint": "disk.extract",
                    "path": "/home/ctfplayer/ctf_files/out.img",
                },
            ),
            RunState(objective="test"),
        )

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.success)
        self.assertEqual(result.output_context["capability"], "disk.extract")
        self.assertEqual(
            [candidate.value for candidate in result.state_delta.flag_candidates],
            ["flag{disk_extract_candidate}"],
        )

    def test_office_inspect_hint_runs_without_llm_selection(self) -> None:
        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError("LLM tool selection should not run")

        plugin = _StaticOfficeInspectPlugin()
        plane = ExecutionPlane()
        plane.register(plugin, build_office_inspect_output)
        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(fail_if_called),
            tool_gateway=ToolGateway(plane),
        )

        result = worker.run(
            TodoItem(
                goal="Inspect Office document container deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "capability_hint": "office.inspect",
                    "path": "/home/ctfplayer/ctf_files/deck.pptx",
                },
            ),
            RunState(objective="test"),
        )

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.success)
        self.assertEqual(result.output_context["capability"], "office.inspect")
        self.assertEqual(
            [candidate.value for candidate in result.state_delta.flag_candidates],
            ["flag{office_candidate}"],
        )

    def test_media_scan_hint_runs_without_llm_selection(self) -> None:
        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError("LLM tool selection should not run")

        plugin = _StaticMediaScanPlugin()
        plane = ExecutionPlane()
        plane.register(plugin, build_media_scan_output)
        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(fail_if_called),
            tool_gateway=ToolGateway(plane),
        )

        result = worker.run(
            TodoItem(
                goal="Scan embedded media files deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "capability_hint": "media.scan",
                    "paths": ["/home/ctfplayer/ctf_files/ppt/media/image1.gif"],
                },
            ),
            RunState(objective="test"),
        )

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.success)
        self.assertEqual(result.output_context["capability"], "media.scan")
        self.assertEqual(
            [candidate.value for candidate in result.state_delta.flag_candidates],
            ["flag{media_candidate}"],
        )

    def test_png_inspect_hint_runs_without_llm_selection(self) -> None:
        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError("LLM tool selection should not run")

        plugin = _StaticPngInspectPlugin()
        plane = ExecutionPlane()
        plane.register(plugin, build_png_inspect_output)
        worker = Worker(
            persona=ARTIFACT_PERSONA,
            llm_client=StaticLLMClient(fail_if_called),
            tool_gateway=ToolGateway(plane),
        )

        result = worker.run(
            TodoItem(
                goal="Inspect PNG image structure and hidden payload surfaces deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "capability_hint": "png.inspect",
                    "path": "/home/ctfplayer/ctf_files/image.png",
                },
            ),
            RunState(objective="test"),
        )

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.success)
        self.assertEqual(result.output_context["capability"], "png.inspect")
        self.assertEqual(
            [candidate.value for candidate in result.state_delta.flag_candidates],
            ["flag{png_candidate}"],
        )


class TestBracketSpanExtraction(unittest.TestCase):
    """Bracket-span recovery uses source-local or configured prefixes only."""

    def test_uses_local_preceding_word_without_global_prefix_synthesis(self) -> None:
        text = (
            "Message 7:\nMY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = _bracket_span_candidates(text)
        self.assertIn("key{And yes the nsa can read this to}", candidates)
        self.assertNotIn("flag{And yes the nsa can read this to}", candidates)

    def test_script_stdout_accepts_bracket_candidate_with_key_context(self) -> None:
        text = (
            "validated key plaintext: MY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = script_module._flag_candidates_from_script_stdout(
            text,
            source="script",
        )

        self.assertIn(
            "key{And yes the nsa can read this to}",
            [candidate.value for candidate in candidates],
        )

    def test_script_stdout_rejects_negative_bracket_context(self) -> None:
        text = (
            "no flag found in plaintext: "
            "{And yes the nsa can read this to}\n"
        )
        candidates = script_module._flag_candidates_from_script_stdout(
            text,
            source="script",
        )

        self.assertEqual([candidate.value for candidate in candidates], [])


class TestFlagRecoveryTaskDetection(unittest.TestCase):
    def test_does_not_treat_flag_named_artifact_parsing_as_flag_recovery(self) -> None:
        todo = TodoItem(
            goal="Extract and parse the 16-byte header from flag.stfu to recover seed and skip count.",
            success_criteria=["Print seed, taps, and skip values."],
        )

        self.assertFalse(_is_flag_recovery_task(todo))

    def test_detects_explicit_plaintext_or_flag_recovery(self) -> None:
        todo = TodoItem(
            goal="Decrypt the ciphertext and recover the flag.",
            success_criteria=["Output contains a flag candidate."],
        )

        self.assertTrue(_is_flag_recovery_task(todo))

    def test_glue_word_prefix_is_skipped(self) -> None:
        text = (
            "Message 7:\nMY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = _bracket_span_candidates(text)
        self.assertNotIn("is{And yes the nsa can read this to}", candidates)
        self.assertEqual(
            candidates[0], "key{And yes the nsa can read this to}",
            f"unexpected first candidate: {candidates[:5]}",
        )

    def test_local_context_word_promotes_prefix(self) -> None:
        text = "Found customPrefix: {hello_world_12345}"
        candidates = _bracket_span_candidates(text)
        self.assertEqual(candidates[0], "customPrefix{hello_world_12345}")

    def test_flag_format_prefix_wins(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = _bracket_span_candidates(
            text, flag_format_prefix="key"
        )
        self.assertEqual(
            candidates[0], "key{And yes the nsa can read this to}"
        )

    def test_extract_uses_bracket_span_when_canonical_misses(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        self.assertTrue(any("key{And yes" in c for c in candidates))

    def test_extracts_uppercase_bare_token_candidates(self) -> None:
        text = "FLAG FOUND: STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"
        candidates = extract_flag_candidates(text)
        self.assertEqual(candidates, ["STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"])

    def test_does_not_extract_standard_version_bare_token(self) -> None:
        text = "profile: sRGB IEC61966-2.1"
        candidates = extract_flag_candidates(text)
        self.assertEqual(candidates, [])

    def test_does_not_extract_nmap_service_fingerprint_token(self) -> None:
        text = "Service Info: SF-Port8000-TCP:V=7.80"
        candidates = extract_flag_candidates(text)
        self.assertEqual(candidates, [])

    def test_does_not_extract_metadata_namespace_or_uuid_tokens(self) -> None:
        text = (
            "metadata: chromaticity com.adobe.xmp 22-rdf-syntax-ns "
            "63A36ECB-BC33-4E88-9986-F84A006F35E4 CTF_TEMP_DIR"
        )
        candidates = extract_flag_candidates(text)
        self.assertEqual(candidates, [])

    def test_does_not_lift_runtime_environment_identifiers(self) -> None:
        self.assertEqual(
            extract_flag_candidates("CTF_FILES_ROOT: /tmp/_script_exec_a6bX8v/work"),
            [],
        )
        self.assertEqual(extract_flag_candidates("FLAG FOUND: CTF_FILES_ROOT"), [])

    def test_does_not_lift_unlabeled_diagnostic_bare_tokens(self) -> None:
        self.assertEqual(extract_flag_candidates("APPENDED_DATA: 200 bytes"), [])
        self.assertEqual(
            extract_flag_candidates(
                "lsb_rgb_4_msb.bin: hoyo%w_DOwF_F_5OVo|O`/%xofOUo"
            ),
            [],
        )

    def test_extracts_labeled_printable_phrase_candidates(self) -> None:
        text = "FLAG FOUND: And yes the nsa can read this to"
        candidates = extract_flag_candidates(text)
        self.assertEqual(candidates, ["flag{And yes the nsa can read this to}"])

    def test_labeled_phrase_uses_known_flag_prefix(self) -> None:
        text = "ANSWER: And yes the nsa can read this to"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        self.assertEqual(candidates, ["key{And yes the nsa can read this to}"])

    def test_extracts_repeated_letter_ascii_art_banner(self) -> None:
        text = (
            "HHHHH     HHHHH EEEEEEEEE LLLLL     LLLLL OOOOOOOOO"
            "                         WWWWW     WWWWW OOOOOOOOO RRRRRRRR"
            " LLLLL DDDDDDDD                         OOOOOOOOO KKKKKKKK\n"
        )

        self.assertEqual(extract_flag_candidates(text), ["HELLO_WORLD_OK"])

    def test_does_not_lift_keystream_debug_word_as_bare_candidate(self) -> None:
        text = "Retrying with big-endian keystream..."
        self.assertEqual(extract_flag_candidates(text), [])

    def test_does_not_lift_hexdump_ascii_column_as_bare_candidate(self) -> None:
        text = "00000010: 4e3b 47f8 97ad 13cc fbe6 39d6 4dc3 2c5b  N;G.......9.M.,["
        self.assertEqual(extract_flag_candidates(text), [])

    def test_does_not_lift_diagnostic_sequences_as_bare_candidate(self) -> None:
        text = "No flag found. Longest printable sequences... inspect manually."
        self.assertEqual(extract_flag_candidates(text), [])

    def test_does_not_lift_found_diagnostic_word_as_bare_candidate(self) -> None:
        text = "No PNG signature found in concatenated data"
        self.assertEqual(extract_flag_candidates(text), [])

    def test_does_not_lift_key_diagnostic_fields_as_bare_candidates(self) -> None:
        self.assertEqual(
            extract_flag_candidates("Key 'IHDR': starts_png=False, printable_in_first_200=113"),
            [],
        )
        self.assertEqual(
            extract_flag_candidates(
                "Decoded with filler key first 100 ascii: b'noise x7fudfylu.tad noise'"
            ),
            [],
        )

    def test_does_not_lift_key_material_or_rejected_candidate_tokens(self) -> None:
        self.assertEqual(
            extract_flag_candidates("Derived key: b'WoAh_A_KWoAh'"),
            [],
        )
        self.assertEqual(
            extract_flag_candidates("XOR key: WoAh_A_KWoAh"),
            [],
        )
        self.assertEqual(
            extract_flag_candidates(
                'Rejected candidate "WoAh_A_KWoAh" not found in decrypted data'
            ),
            [],
        )

    def test_does_not_lift_source_code_identifier_tokens_from_key_context(self) -> None:
        text = (
            "IV/nonce references: ['private $CIPHER = MCRYPT_RIJNDAEL_128;', "
            "\"private $key =  '13somerandomkey2';\", "
            "'private $MODE = MCRYPT_MODE_ECB;']\n"
            "Key management references: ['$plaintext = "
            "mcrypt_decrypt($this->CIPHER, $this->key, $ciphertext, $this->MODE);']\n"
        )

        self.assertEqual(extract_flag_candidates(text), [])

    def test_key_label_can_still_lift_bare_candidate(self) -> None:
        self.assertEqual(
            extract_flag_candidates("KEY: STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"),
            ["STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"],
        )

    def test_weak_context_does_not_lift_lowercase_labels(self) -> None:
        self.assertEqual(extract_flag_candidates("FLAG CANDIDATE: SSSSSSSSSSSSSSS"), [])
        self.assertEqual(extract_flag_candidates("candidate: little-endian"), [])
        self.assertEqual(extract_flag_candidates("decrypted output: decrypted.bin"), [])
        self.assertEqual(extract_flag_candidates("FLAG CANDIDATE: brace-enclosed"), [])
        self.assertEqual(extract_flag_candidates("FLAG FOUND: no flag found"), [])
        self.assertEqual(extract_flag_candidates("FLAG FOUND: autoCompressPictures"), [])
        self.assertEqual(extract_flag_candidates("FLAG FOUND: 2012-05-07T19"), [])
        self.assertEqual(extract_flag_candidates("candidate: 2012-05-07T19:44:33"), [])
        self.assertEqual(
            extract_flag_candidates("No flag in ppt/notesSlides/notesSlide17.xml"),
            [],
        )

    def test_canonical_match_suppresses_bracket_span_extraction(self) -> None:
        text = "found flag{abc123_real_one} in output"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        self.assertEqual(candidates, ["flag{abc123_real_one}"])

    def test_structured_error_span_is_not_wrapped_as_flag(self) -> None:
        text = (
            "Results:\n"
            "{'command': './stfu flag.stfu', 'error': \"[Errno 2] "
            "No such file or directory: 'strace'\"}\n"
        )
        self.assertEqual(_bracket_span_candidates(text), [])
        self.assertEqual(extract_flag_candidates(text), [])

    def test_ascii_art_long_prefix_does_not_emit_candidate(self) -> None:
        text = ("y" * 10000) + "{abc123}"
        self.assertEqual(extract_flag_candidates(text), [])

    def test_oversized_encoded_blob_is_not_decoded(self) -> None:
        old_decode = flag_module._try_decode_blob

        def fail_decode(blob: str) -> list[str]:
            self.fail(f"oversized blob should not be decoded: {len(blob)}")

        flag_module._try_decode_blob = fail_decode
        try:
            self.assertEqual(extract_flag_candidates("A" * 200_000), [])
        finally:
            flag_module._try_decode_blob = old_decode

    def test_bounded_base64_blob_still_decodes(self) -> None:
        blob = base64.b64encode(b"flag{encoded_ok_123}").decode("ascii")
        self.assertEqual(extract_flag_candidates(blob), ["flag{encoded_ok_123}"])

    def test_invalid_base64_padding_is_skipped_without_debug_traceback(self) -> None:
        calls: list[str] = []
        original = flag_module._debug_decode_failure

        def record(operation: str, exc: Exception, *, value: str) -> None:
            del exc, value
            calls.append(operation)

        flag_module._debug_decode_failure = record
        try:
            self.assertEqual(flag_module._try_decode_blob("QUJDQUJDQUJDQUJD===="), [])
        finally:
            flag_module._debug_decode_failure = original

        self.assertEqual(calls, [])

    def test_tool_flag_extraction_uses_bounded_scan_text(self) -> None:
        old_extract = tool_base.extract_flag_candidates
        captured: dict[str, int] = {}

        def capture_extract(text: str) -> list[str]:
            captured["length"] = len(text)
            return []

        tool_base.extract_flag_candidates = capture_extract
        try:
            tool_base._flag_candidates_from("A" * 1_000_000)
        finally:
            tool_base.extract_flag_candidates = old_extract

        self.assertLessEqual(captured["length"], 170_000)

    def test_tool_flag_extraction_keeps_relevant_middle_window(self) -> None:
        text = (
            "A" * 300_000
            + "\nFLAG FOUND: flag{middle_window_candidate}\n"
            + "B" * 300_000
        )

        candidates = tool_base._flag_candidates_from(text)

        self.assertEqual([item.value for item in candidates], ["flag{middle_window_candidate}"])


class TestScriptOutputFailureSignals(unittest.TestCase):
    def _output_context(
        self,
        stderr: str = "",
        *,
        stdout: str = "",
        exit_code: int = 1,
    ) -> dict[str, object]:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
            ),
            ParsedToolOutput(summary="raw"),
        )
        return output.output_context

    def test_classifies_broken_pipe_as_network_pipe_closed(self) -> None:
        ctx = self._output_context(
            'Traceback (most recent call last):\nBrokenPipeError: [Errno 32] Broken pipe'
        )

        self.assertEqual(ctx["failure_kind"], "network_pipe_closed")
        self.assertIn("socket", str(ctx["failure_detail"]))

    def test_preserves_traceback_excerpt_in_output_context(self) -> None:
        ctx = self._output_context(
            "noise before traceback\n"
            "Traceback (most recent call last):\n"
            "  File \"/workspace/solver.py\", line 7, in <module>\n"
            "    data.decode('utf-8')\n"
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff\n"
        )

        traceback = str(ctx["traceback"])
        self.assertTrue(traceback.startswith("Traceback (most recent call last):"))
        self.assertIn("solver.py", traceback)
        self.assertIn("UnicodeDecodeError", traceback)

    def test_classifies_broken_pipe_reported_on_stdout(self) -> None:
        ctx = self._output_context(
            stdout=(
                "Connected\n"
                "Round 1: answered\n"
                "Error at round 2: [Errno 32] Broken pipe\n"
            )
        )

        self.assertEqual(ctx["failure_kind"], "network_pipe_closed")

    def test_classifies_runtime_guard_reported_on_stdout(self) -> None:
        ctx = self._output_context(
            stdout=(
                "Round 1: work started\n"
                "Error at round 1: script.exec Python time limit exceeded "
                "at line 166; use bounded loops or fast-forward math\n"
            )
        )

        self.assertEqual(ctx["failure_kind"], "unbounded_loop_guard")

    def test_classifies_bytes_text_mismatch(self) -> None:
        ctx = self._output_context(
            "TypeError: a bytes-like object is required, not 'str'"
        )

        self.assertEqual(ctx["failure_kind"], "bytes_text_mismatch")

    def test_classifies_python3_byte_index_mismatch(self) -> None:
        ctx = self._output_context(
            "TypeError: byte indices must be integers or slices, not str"
        )

        self.assertEqual(ctx["failure_kind"], "bytes_text_mismatch")

    def test_classifies_unicode_decode_error_as_bytes_text_mismatch(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0\n"
        )

        self.assertEqual(ctx["failure_kind"], "bytes_text_mismatch")

    def test_classifies_path_type_mismatch(self) -> None:
        ctx = self._output_context(
            "TypeError: unsupported operand type(s) for /: 'str' and 'str'"
        )

        self.assertEqual(ctx["failure_kind"], "path_type_mismatch")

    def test_classifies_missing_path_as_path_resolution_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 37, in <module>\n"
            "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/work/output'\n"
        )

        self.assertEqual(ctx["failure_kind"], "path_resolution_error")

    def test_classifies_missing_python_module_as_missing_tool(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 1, in <module>\n"
            "ModuleNotFoundError: No module named 'pytesseract'\n"
        )

        self.assertEqual(ctx["failure_kind"], "missing_tool")
        self.assertIn("module", str(ctx["failure_detail"]))
        self.assertIn("stdlib", str(ctx["failure_detail"]))

    def test_classifies_odd_length_hex_decode_as_parse_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "binascii.Error: Odd-length string\n"
        )

        self.assertEqual(ctx["failure_kind"], "parse_error")

    def test_classifies_fromhex_value_error_as_parse_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 42, in <module>\n"
            "ValueError: non-hexadecimal number found in fromhex() arg at position 187\n"
        )

        self.assertEqual(ctx["failure_kind"], "parse_error")

    def test_classifies_undefined_name_runtime_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 42, in <module>\n"
            "NameError: name 'target' is not defined\n"
        )

        self.assertEqual(ctx["failure_kind"], "undefined_name")
        self.assertIn("before assignment", str(ctx["failure_detail"]))

    def test_classifies_unbound_local_runtime_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 14, in main\n"
            "    root = os.environ.get('CTF_TEMP_DIR', tempfile.mkdtemp())\n"
            "UnboundLocalError: local variable 'tempfile' referenced before assignment\n"
        )

        self.assertEqual(ctx["failure_kind"], "undefined_name")
        self.assertIn("before assignment", str(ctx["failure_detail"]))

    def test_classifies_generic_type_error_after_specific_type_checks(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/runner.py\", line 91, in <module>\n"
            "TypeError: unsupported operand type(s) for |: 'int' and 'tuple'\n"
        )

        self.assertEqual(ctx["failure_kind"], "type_error")
        self.assertIn("incompatible", str(ctx["failure_detail"]))

    def test_classifies_attribute_method_mismatch_as_type_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "AttributeError: 'list' object has no attribute 'ljust'\n"
        )

        self.assertEqual(ctx["failure_kind"], "type_error")

    def test_classifies_short_binary_unpack_as_binary_structure_error(self) -> None:
        ctx = self._output_context(
            "Traceback (most recent call last):\n"
            "  File \"/tmp/extract.py\", line 37, in <module>\n"
            "struct.error: unpack requires a buffer of 28 bytes\n"
        )

        self.assertEqual(ctx["failure_kind"], "binary_structure_error")
        self.assertIn("bounds", str(ctx["failure_detail"]))

    def test_classifies_parse_error_reported_on_stdout(self) -> None:
        ctx = self._output_context(
            stdout=(
                "Connected\n"
                "Failed to parse next value: prompt label and data were merged\n"
            )
        )

        self.assertEqual(ctx["failure_kind"], "parse_error")


class TestScriptExecutionRuntime(unittest.TestCase):
    def test_python_runtime_guard_tracks_request_timeout_by_default(self) -> None:
        old_limit = script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S
        script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = 0
        try:
            wrapper = script_module._python_runtime_guard_wrapper(300)
        finally:
            script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = old_limit

        self.assertIn("_kc_runtime_limit_s = 299", wrapper)

    def test_python_runtime_guard_can_be_capped_for_tests(self) -> None:
        old_limit = script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S
        script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = 7
        try:
            wrapper = script_module._python_runtime_guard_wrapper(300)
        finally:
            script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = old_limit

        self.assertIn("_kc_runtime_limit_s = 7", wrapper)

    def test_python_runtime_guard_sets_default_socket_deadline(self) -> None:
        wrapper = script_module._python_runtime_guard_wrapper(300)

        self.assertIn("import socket as _kc_socket", wrapper)
        self.assertIn("_kc_socket.setdefaulttimeout(5)", wrapper)

    def test_python_timeout_keeps_observations_printed_before_timeout(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=1,
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": (
                            "import time\n"
                            "print('header-before-timeout')\n"
                            "time.sleep(5)\n"
                        ),
                    },
                )
            )

        self.assertEqual(result.exit_code, -1)
        self.assertIn("header-before-timeout", result.stdout)
        self.assertIn("[timeout after 1s]", result.stderr)

    def test_user_signal_alarm_is_clamped_below_tool_timeout(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=4,
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": (
                            "import signal, time\n"
                            "def handler(signum, frame):\n"
                            "    print('user alarm fired')\n"
                            "    raise TimeoutError('internal alarm fired')\n"
                            "signal.signal(signal.SIGALRM, handler)\n"
                            "signal.alarm(120)\n"
                            "print('before long sleep')\n"
                            "time.sleep(20)\n"
                        ),
                    },
                )
            )

        self.assertNotEqual(result.exit_code, -1)
        self.assertIn("before long sleep", result.stdout)
        self.assertIn("user alarm fired", result.stdout)
        self.assertIn("internal alarm fired", result.stderr)
        self.assertNotIn("[timeout after 4s]", result.stderr)

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            result,
            ParsedToolOutput(summary="raw"),
        )
        self.assertEqual(output.output_context["failure_kind"], "timeout")

    def test_network_script_timeout_is_capped(self) -> None:
        plugin = ScriptPlugin()
        captured: dict[str, int] = {}

        def fake_run(name, argv, timeout_s, **kwargs):
            del name, argv, kwargs
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name="script_exec", exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.script._run", side_effect=fake_run):
                plugin.execute(
                    ToolExecutionRequest(
                        tool_name="script_exec",
                        timeout_s=300,
                        metadata={
                            "script_language": "python",
                            "files_root": tmp,
                            "script_code": (
                                "import socket\n"
                                "socket.create_connection(('example.com', 31337), timeout=3)\n"
                            ),
                        },
                    )
                )

        self.assertEqual(captured["timeout_s"], script_module._NETWORK_SCRIPT_TIMEOUT_CAP_S)

    def test_local_script_timeout_is_not_capped_as_network_io(self) -> None:
        plugin = ScriptPlugin()
        captured: dict[str, int] = {}

        def fake_run(name, argv, timeout_s, **kwargs):
            del name, argv, kwargs
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name="script_exec", exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.script._run", side_effect=fake_run):
                plugin.execute(
                    ToolExecutionRequest(
                        tool_name="script_exec",
                        timeout_s=300,
                        metadata={
                            "script_language": "python",
                            "files_root": tmp,
                            "script_code": "print(sum(range(10)))\n",
                        },
                    )
                )

        self.assertEqual(captured["timeout_s"], 300)

    def test_python_oversized_range_fails_fast(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=20,
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": "for _ in range(10**9):\n    pass\n",
                    },
                )
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("range too large for script.exec", result.stderr)
        self.assertIn("line 1", result.stderr)
        self.assertIn("range(10**9)", result.stderr)

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            result,
            ParsedToolOutput(summary="raw"),
        )
        self.assertEqual(output.output_context["failure_kind"], "unbounded_loop_guard")

    def test_python_oversized_product_fails_fast(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    tool_name="script_exec",
                    timeout_s=20,
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": (
                            "import itertools\n"
                            "for _ in itertools.product(range(1000), repeat=3):\n"
                            "    pass\n"
                        ),
                    },
                )
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("product too large for script.exec", result.stderr)
        self.assertIn("line 2", result.stderr)
        self.assertIn("itertools.product", result.stderr)

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            result,
            ParsedToolOutput(summary="raw"),
        )
        self.assertEqual(output.output_context["failure_kind"], "unbounded_loop_guard")

    def test_python_busy_loop_hits_runtime_guard(self) -> None:
        plugin = ScriptPlugin()
        old_limit = script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S
        script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                result = plugin.execute(
                    ToolExecutionRequest(
                        tool_name="script_exec",
                        timeout_s=5,
                        metadata={
                            "script_language": "python",
                            "files_root": tmp,
                            "script_code": "while True:\n    pass\n",
                        },
                    )
                )
        finally:
            script_module._PYTHON_SCRIPT_RUNTIME_LIMIT_S = old_limit

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("script.exec Python time limit exceeded", result.stderr)
        self.assertIn("line 1", result.stderr)
        self.assertIn("while True", result.stderr)

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            result,
            ParsedToolOutput(summary="raw"),
        )
        self.assertEqual(output.output_context["failure_kind"], "unbounded_loop_guard")

    def test_success_without_flag_has_structured_no_candidate_signal(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="decoded plaintext did not match expected format",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")
        self.assertEqual(output.output_context["failure_kind"], "no_candidate")

    def test_success_without_flag_keeps_guardrail_signal_from_output(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=(
                    "Round 1 started\n"
                    "Error during interaction: script.exec Python time limit exceeded "
                    "at line 64; use bounded loops or fast-forward math\n"
                    "No flag captured.\n"
                ),
                stderr="Traceback omitted\n",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")
        self.assertEqual(output.output_context["failure_kind"], "unbounded_loop_guard")
        self.assertIn("Python runtime guard", str(output.output_context["failure_detail"]))

    def test_readable_ascii_art_without_flag_is_near_miss(self) -> None:
        ascii_art = "\n".join(
            [
                "  _  __ _____ __   __   _____  ______  __  __  _____ ",
                " | |/ /| ____|\\ \\ / /  |  ___||  ____||  \\/  || ____|",
                " | ' / |  _|   \\ V /   | |_   | |_   | |\\/| ||  _|  ",
                " | . \\ | |___   | |    |  _|  |  _|  | |  | || |___ ",
                " |_|\\_\\|_____|  |_|    |_|    |_|    |_|  |_||_____|",
            ]
            * 6
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=ascii_art,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["result_quality"], "near_miss")
        self.assertIn("near_miss_candidates", output.output_context)
        self.assertNotIn("failure_kind", output.output_context)

    def test_labeled_decoded_plaintext_block_is_near_miss(self) -> None:
        stdout = "Plaintext:\n" + "\n".join(
            [
                "The recovered readable text is coherent but lacks a final validated token line.",
                "It includes enough natural language structure to be useful for follow-up analysis.",
                "The next step should inspect surrounding context rather than discard this text.",
            ]
            * 3
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["result_quality"], "near_miss")
        self.assertIn("near_miss_candidates", output.output_context)

    def test_network_transcript_is_not_near_miss(self) -> None:
        stdout = "\n".join(
            [
                "[*] Connecting to service.local:31337...",
                "[+] Connected successfully to service.local:31337",
                "[*] Received banner (102 bytes):",
                "b'welcome to the interactive service\\nchoose an option below\\n'",
                "[*] Sent probe: b'\\n'",
                "[*] Received response (957 bytes):",
                "b'  ,88888,,88888,                                      \\n"
                "  ,88\\'   \\\"menu\\\"  \\\"88,   THIS IS A LONG DECORATIVE BANNER \\n"
                "  88,    88 88   ,88   WITH STATUS TEXT AND NO RECOVERED SECRET\\n"
                "  -----------------------------                         \\n'",
                "[*] Connection closed",
                "[*] Running basic port check...",
                "[!] scanner unavailable or timed out after 30 seconds",
            ]
            * 3
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_symbol_table_report_is_not_near_miss(self) -> None:
        stdout = "\n".join(
            [
                "Symbol table '.dynsym' contains 33 entries:",
                "   Num:    Value          Size Type    Bind   Vis      Ndx Name",
                "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND",
                "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts",
                "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf",
                "Disassembly of section .text:",
                "0000000000401000 <main>:",
                "  401000: 55                    push   %rbp",
                "  401001: 48 89 e5              mov    %rsp,%rbp",
                "  401004: e8 27 ff ff ff        callq  401030 <puts@plt>",
            ]
            * 4
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_artifact_manifest_is_not_near_miss(self) -> None:
        stdout = "\n".join(
            [
                "Done.",
                "__KILLCHAIN_SCRIPT_ARTIFACTS__",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/payload_001.bin\t7247\tscratch\tpayload_001.bin\tb32172",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/payload_002.bin\t8192\tscratch\tpayload_002.bin\t65ac21",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/payload_003.bin\t16384\tscratch\tpayload_003.bin\t5bb837",
                "__KILLCHAIN_SCRIPT_ARTIFACTS_END__",
            ]
            * 4
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_path_listing_and_reference_report_is_not_near_miss(self) -> None:
        stdout = "\n".join(
            [
                "Looking for interesting string reference",
                "Line 103:   400f40: ff 25 52 31 20 00     jmp *0x203152(%rip)",
                "Line 168:   401010: ff 25 ea 30 20 00     jmp *0x2030ea(%rip)",
                "Context around offset 1091: H<.i.r.g.$M.~..1.a{.k.6..H+.2.%X)",
                "Searching for brace patterns.",
                "extracted/package/README.md",
                "extracted/package/static/generated_bundle.js",
                "extracted/package/test/results/sample_output.js.gz",
            ]
            * 4
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_hex_and_string_dump_report_is_not_near_miss(self) -> None:
        stdout = (
            "Context around offset 0x3460:\n"
            "Hex dump (first 128 bytes):\n"
            "3432362054435020636f6e6e656374696f6e207761732065737461626c697368656420627574207468656e2062726f6b656e210d0a005573657220257320646f776e6c6f616465642066696c65202573\n"
            "\n"
            "String dump:\n"
            "426 TCP connection was established but then broken!.User %s downloaded file %s.\n"
            "226 Transfer complete.sorry port isnt working.FTP listen_fd == %d.\n"
            "error opening socket.error binding socket.(SOCKET ERROR).PASV successful.\n"
            "recovered_name.txt.Error reading result please contact an organizer.\n"
            "\n"
            "--- XOR with candidate key ---\n"
            "No flag pattern found in XOR result\n"
            "Decoded preview: V^WN?41L\\x0f\\r\\x02\\x0f\\x0b\\x08\\x03\\x08\\x03\\x02B\n"
            "=== No flag found with simple approaches ===\n"
        )

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_candidate_score_report_is_not_near_miss(self) -> None:
        report = "\n".join(
            [
                "File size: 25316 bytes",
                "Header hex: 535446556aab0223201f1e0a00008540",
                "CT size: 25300 bytes",
                "Testing 6 seeds x 14 skips = 84 combos",
                "=== Top candidates ===",
                "1. Seed=0x6aab0224, Skip=34112",
                "Ratio=38.30%, Flags=0, LongStrings=0, MaxLong=0",
                "Braces=86, Score=38.3",
                "First bytes: bytearray(b'\\xcd.:\\xb8\\xf0h\\x9f\\xa5G')",
                "2. Seed=0x6aab0223, Skip=34112",
                "Ratio=37.55%, Flags=0, LongStrings=0, MaxLong=0",
                "Braces=113, Score=37.6",
                "First bytes: bytearray(b'\\x93\\x0d\\x89H\\xf9\\xb6t')",
            ]
            * 3
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=report,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_solver_self_test_report_is_not_near_miss(self) -> None:
        report = "\n".join(
            [
                "=== LOCAL SELF-TEST OF GREEDY ALGORITHM ===",
                "Test 1: cents=1",
                "Result: 1 pennies (1c)",
                "Sum verification: 1 == 1 -> PASS",
                "=== DIFFERENTIAL TEST (greedy_change vs reference) ===",
                "Tier 1 (small): PASS (50 random tests)",
                "ALL TESTS PASSED - Greedy algorithm matches reference implementation.",
                "Solver function for network use:",
                "def solve_for_cents(cents):",
                "    return counts",
            ]
            * 5
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=report,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_socket_timeout_phrase_is_classified_as_timeout(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=1,
                stdout="Connected.\nSocket timeout during communication.\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["failure_kind"], "timeout")

    def test_successful_script_socket_timeout_diagnostic_is_not_tool_timeout(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="Connected.\nSocket timeout after receiving data\nDone.\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["failure_kind"], "no_candidate")
        self.assertNotEqual(output.output_context["partial_reason"], "script exceeded its execution or socket timeout")

    def test_successful_subdiagnostic_timeout_phrase_is_not_tool_timeout(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="Running bounded subprocess...\nProcess timed out\nContinuing with fallback.\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["failure_kind"], "no_candidate")
        self.assertNotEqual(output.output_context["partial_reason"], "script exceeded its execution or socket timeout")

    def test_gibberish_decoded_plaintext_does_not_emit_flag_candidates(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="Decrypted text: \ufffd\ufffdkNy7{O8sGw}\ufffd\ufffd\ufffdmore-noise\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.flag_candidates, [])
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_escaped_python_repr_does_not_emit_flag_candidates(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=(
                    "First 200 bytes: "
                    "b'\\x96\\\\\\\\\\x96{\\x9e\\x9e{\\r\\xff\\xff\\r6\\xcf\\xcf6|}'\n"
                ),
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.flag_candidates, [])
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_diagnostic_all_space_preview_is_not_near_miss(self) -> None:
        stdout = (
            "Magic: b'STFU'\n"
            "Seed bytes: 6aab0223\n"
            "Skip bytes: 00008540\n"
            "Printable ratio (first 200 bytes): 200/200 = 1.00\n"
            "First 200 chars: '" + (" " * 220) + "'\n"
            "============================================================\n"
            "BEST RESULT:\n"
            "============================================================\n"
            + (" " * 500)
            + "\nNo flag pattern found\n"
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_png_chunk_diagnostic_report_is_not_near_miss(self) -> None:
        stdout = (
            "Decoded data length: 126909 bytes\n"
            "PNG magic header matches!\n"
            "No 'flag' string found in decrypted data\n\n"
            "=== PNG CHUNK ANALYSIS ===\n"
            "Chunk 'IHDR' at offset 8: length=13, CRC stored=0x053a5c46, computed=0x053a5c46, match=True\n"
            "Chunk 'iTXt' at offset 114: length=345, CRC stored=0x4cc22759, computed=0x4cc22759, match=True\n"
            "  Text content: XML:com.adobe.xmp\\x00<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 5.4.0\">\n"
            "   <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
            "      <rdf:Description rdf:about=\"\" xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\">\n"
            "         <tiff:Orientation>1</tiff:Orientation>\n"
            "      </rdf:Description>\n"
            "   </rdf:RDF>\n"
            "</x:xmpmeta>\n"
            "Chunk 'IDAT' at offset 471: length=16384, CRC stored=0xaa19c865, computed=0xaa19c865, match=True\n"
            "Chunk 'IEND' at offset 126897: length=0, CRC stored=0xae426082, computed=0xae426082, match=True\n\n"
            "=== STRING SEARCH IN DECRYPTED PNG ===\n"
            "Found 14 printable strings of length >= 10\n"
            "  0: b'YiTXtXML:com.adobe.xmp'\n"
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_printable_strings_report_is_not_near_miss(self) -> None:
        stdout = (
            "[*] Recovered key (ascii): WoAh_A_Key!?\n"
            "[+] Decrypted starts with PNG header!\n"
            "[*] Searching for flag in decrypted PNG...\n"
            "[-] No flag pattern found in decrypted PNG\n"
            "[*] Extracting printable strings from decrypted PNG...\n"
            "[*] Found 40 printable strings (showing top 10):\n"
            "  offset 206:    <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
            "  offset 144: <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 5.4.0\">\n"
            "  offset 311:             xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\">\n"
            "  offset 367:          <tiff:Orientation>1</tiff:Orientation>\n"
            "  offset 275:       <rdf:Description rdf:about=\"\"\n"
            "  offset 55970: SP?8mPC1y\\\n"
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_hexdump_preview_report_is_not_near_miss(self) -> None:
        stdout = (
            "readable/plaintext-or-ascii-art preview:\n"
            "0: 88 04 00 4d 53 42 31 00 10 00 00 00 38 45 32 39\n"
            "010: 02 00 07 00 00 00 ff 00 6a ab 02 23 20 1f 1e 0a\n"
            "020: 00 00 85 40 8f d1 3a 11 2a b7 c0 0d 7e 80 41 22\n"
            "030: 10 99 65 20 4a 91 e0 02 00 10 00 00 00 f1 e2 d3 c4\n"
            "040: 7a 61 58 48 0d 0a ff ee 18 29 34 55 66 77 88 99\n"
            "050: 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00\n"
            "060: ca fe ba be 00 11 22 33 44 55 66 77 88 99 aa bb\n"
            "070: 30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46\n"
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("near_miss_candidates", output.output_context)
        self.assertEqual(output.output_context["result_quality"], "partial_no_candidate")

    def test_labeled_candidate_survives_script_context_filter(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="FLAG FOUND: flag{real_candidate_123}\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["flag{real_candidate_123}"],
        )

    def test_labeled_bare_token_survives_script_context_filter(self) -> None:
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="FLAG FOUND: STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME\n",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"],
        )

    def test_source_identifier_tokens_do_not_survive_script_context_filter(self) -> None:
        stdout = (
            "Key management references: [\"private $key =  '13somerandomkey2';\", "
            "'$plaintext = mcrypt_decrypt($this->CIPHER, $this->key, $ciphertext, "
            "$this->MODE);']\n"
            "IV/nonce references: ['private $CIPHER = MCRYPT_RIJNDAEL_128;', "
            "'private $MODE = MCRYPT_MODE_ECB;']\n"
        )
        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual([candidate.value for candidate in output.flag_candidates], [])
        self.assertEqual(output.output_context["failure_kind"], "no_candidate")

    def test_derived_ascii_art_candidate_survives_script_context_filter(self) -> None:
        line = (
            "HHHHH     HHHHH EEEEEEEEE LLLLL     LLLLL OOOOOOOOO"
            "                         WWWWW     WWWWW OOOOOOOOO RRRRRRRR"
            " LLLLL DDDDDDDD                         OOOOOOOOO KKKKKKKK"
        )
        stdout = "\n".join([line, line, line])

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertNotIn("HELLO_WORLD_OK", stdout)
        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["HELLO_WORLD_OK"],
        )

    def test_visual_ascii_art_candidate_ranks_before_bare_noise(self) -> None:
        line = (
            "HHHHH     HHHHH EEEEEEEEE LLLLL     LLLLL OOOOOOOOO"
            "                         WWWWW     WWWWW OOOOOOOOO RRRRRRRR"
            " LLLLL DDDDDDDD                         OOOOOOOOO KKKKKKKK"
        )
        stdout = "\n".join([line, line, line, "FLAG CANDIDATE: WRONG_SHORT_X"])

        output = build_script_output(
            ToolExecutionRequest(tool_name="script_exec", metadata={"script_language": "python"}),
            ToolExecutionResult(
                tool_name="script_exec",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.flag_candidates[0].value, "HELLO_WORLD_OK")


if __name__ == "__main__":
    unittest.main()
