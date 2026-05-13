"""Guardrails for solver execution (flag plausibility + challenge file metadata)."""

from __future__ import annotations

import json
import unittest

from killchain_docker.agents._helpers.flag import (
    _bracket_span_candidates,
    extract_flag_candidates,
)
from killchain_docker.state.constants import plausible_flag
from killchain_docker.state.task_factory import is_validatable_flag_candidate
from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins import solver_execution


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
        # csawpad-style: real CTF flag has spaces in body.  Previous validator
        # used ``[!-z|~]`` and silently dropped these.
        self.assertTrue(plausible_flag("key{And yes the nsa can read this to}"))
        self.assertTrue(plausible_flag("flag{multiple words allowed}"))

    def test_rejects_single_char_prefix(self) -> None:
        # historypeats-style noise: ``t{pagination}`` from CSS class echoes.
        self.assertFalse(plausible_flag("t{pagination}"))
        self.assertFalse(plausible_flag("t{link}"))
        self.assertFalse(plausible_flag("f{x:08x}"))

    def test_rejects_template_noise_bodies(self) -> None:
        # The body itself is a template-echo word, not a real flag.
        self.assertFalse(plausible_flag("flag{pagination}"))
        self.assertFalse(plausible_flag("key{link}"))
        self.assertFalse(plausible_flag("ctf{description}"))

    def test_rejects_python_dump_style_prefixes(self) -> None:
        self.assertFalse(plausible_flag("repr{byte_dump_preview}"))
        self.assertFalse(plausible_flag("ascii{garbage}"))
        self.assertFalse(plausible_flag("foo(bar{not_real}"))


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

    def test_rejects_python_exception_token(self) -> None:
        self.assertFalse(is_validatable_flag_candidate("FileNotFoundError"))


class TestBracketSpanFallback(unittest.TestCase):
    """csawpad regression: solver output `... is {And yes the nsa ...}` must yield candidates."""

    def test_emits_candidates_with_common_prefixes(self) -> None:
        text = (
            "Message 7:\nMY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = _bracket_span_candidates(text)
        self.assertIn("key{And yes the nsa can read this to}", candidates)
        self.assertIn("flag{And yes the nsa can read this to}", candidates)

    def test_glue_word_prefix_is_skipped(self) -> None:
        # The word immediately before "{" is "is" — that's English glue,
        # not a flag prefix.  ``key{...}`` should rank ahead of any
        # ``is{...}`` candidate.
        text = (
            "Message 7:\nMY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = _bracket_span_candidates(text)
        self.assertNotIn("is{And yes the nsa can read this to}", candidates)
        # And ``key{...}`` should be near the top because the literal word
        # ``key`` appears in the local context.
        self.assertEqual(
            candidates[0], "key{And yes the nsa can read this to}",
            f"unexpected first candidate: {candidates[:5]}",
        )

    def test_local_context_word_promotes_prefix(self) -> None:
        # When the bracket is mentioned next to "flag", flag{...} ranks first.
        text = "Found flag value: {hello_world_12345}"
        candidates = _bracket_span_candidates(text)
        self.assertEqual(candidates[0], "flag{hello_world_12345}")

    def test_flag_format_prefix_wins(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = _bracket_span_candidates(
            text, flag_format_prefix="key"
        )
        # When flag_format_prefix is set, it ranks first.
        self.assertEqual(
            candidates[0], "key{And yes the nsa can read this to}"
        )

    def test_extract_uses_fallback_when_canonical_misses(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        # The flag_format_prefix wins first; common prefixes follow.
        self.assertTrue(any("key{And yes" in c for c in candidates))

    def test_canonical_match_blocks_fallback(self) -> None:
        text = "found flag{abc123_real_one} in output"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        # When canonical extraction succeeds, fallback should not fire.
        self.assertEqual(candidates, ["flag{abc123_real_one}"])


class TestSolverExecutionPayload(unittest.TestCase):
    def test_challenge_files_in_json_payload(self) -> None:
        req = ToolExecutionRequest(
            tool_name="solver_execution",
            parser_name="jsonl_signals",
            timeout_s=60,
            metadata={
                "solver_code": "print(1)",
                "files_root": "/home/ctfplayer/ctf_files",
                "timeout_s": 30,
                "flag_format": "",
                "solver_language": "python",
                "challenge_files": ["stfu", "flag.stfu", ""],
            },
        )
        argv = solver_execution.build_arguments(req)
        self.assertEqual(argv[0], "-c")
        payload = json.loads(argv[2])
        self.assertEqual(payload["challenge_files"], ["stfu", "flag.stfu"])

    def test_challenge_files_default_empty(self) -> None:
        req = ToolExecutionRequest(
            tool_name="solver_execution",
            parser_name="jsonl_signals",
            timeout_s=60,
            metadata={"solver_code": "x"},
        )
        argv = solver_execution.build_arguments(req)
        payload = json.loads(argv[2])
        self.assertEqual(payload["challenge_files"], [])


class TestChallengeFileSnapshotRestore(unittest.TestCase):
    """stfu regression: solver script clobbering challenge file must be restored."""

    def _run_inline(
        self, *, files_root, solver_code, challenge_files
    ):
        import subprocess as _sp
        payload = {
            "solver_code": solver_code,
            "files_root": str(files_root),
            "timeout_s": 10,
            "flag_format": "",
            "solver_language": "python",
            "challenge_files": list(challenge_files),
        }
        result = _sp.run(
            ["python3", "-c", solver_execution.SCRIPT, json.dumps(payload)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result

    def test_overwrite_is_restored_from_snapshot(self) -> None:
        import tempfile
        original = b"ORIGINAL_CHALLENGE_BYTES_DO_NOT_TRUNCATE"
        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path as _P
            cfile = _P(tmpdir) / "flag.bin"
            cfile.write_bytes(original)
            solver_code = (
                "with open('flag.bin', 'wb') as f: f.write(b'GARBAGE')\n"
                "print('overwrote')\n"
            )
            self._run_inline(
                files_root=tmpdir,
                solver_code=solver_code,
                challenge_files=["flag.bin"],
            )
            # Even though the solver *did* overwrite the file (it has writable
            # mode while running as the test user, which can chmod itself
            # back), the snapshot+restore must put the original bytes back.
            self.assertEqual(cfile.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
