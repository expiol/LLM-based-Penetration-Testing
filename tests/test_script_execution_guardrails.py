"""Guardrails for script execution (flag plausibility + challenge file metadata).

Updated for 2-capability architecture — tests that validated the deleted
script_execution plugin payload format are removed; flag plausibility and
bracket-span tests are preserved as-is since they test state/constants.
"""

from __future__ import annotations

import unittest

from killchain_docker.reasoning.flag import (
    _bracket_span_candidates,
    extract_flag_candidates,
)
from killchain_docker.state.constants import plausible_flag, validatable_flag_candidate as is_validatable_flag_candidate


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
    """csawpad regression: script output `{And yes the nsa ...}` yields candidates."""

    def test_emits_candidates_with_common_prefixes(self) -> None:
        text = (
            "Message 7:\nMY key for you is "
            "{And yes the nsa can read this to}\n"
        )
        candidates = _bracket_span_candidates(text)
        self.assertIn("key{And yes the nsa can read this to}", candidates)
        self.assertIn("flag{And yes the nsa can read this to}", candidates)

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
        text = "Found flag value: {hello_world_12345}"
        candidates = _bracket_span_candidates(text)
        self.assertEqual(candidates[0], "flag{hello_world_12345}")

    def test_flag_format_prefix_wins(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = _bracket_span_candidates(
            text, flag_format_prefix="key"
        )
        self.assertEqual(
            candidates[0], "key{And yes the nsa can read this to}"
        )

    def test_extract_uses_fallback_when_canonical_misses(self) -> None:
        text = "decrypted: {And yes the nsa can read this to}"
        candidates = extract_flag_candidates(text, flag_format_prefix="key")
        self.assertTrue(any("key{And yes" in c for c in candidates))

    def test_canonical_match_blocks_fallback(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
