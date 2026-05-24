"""Tests for artifact triage — updated for 2-capability architecture.

The old test ran the deleted artifact_triage plugin directly via subprocess.
This test now validates the shell-based equivalent approach.
"""

from __future__ import annotations

import binascii
import struct
import tempfile
import unittest
from pathlib import Path

from killchain_docker.tools import ToolExecutionRequest, ToolExecutionResult
from killchain_docker.tools.core import ExecutionMode, ParsedToolOutput
from killchain_docker.tools.core import extract_flags_from_text
from killchain_docker.tools.plugins.artifact_triage import (
    ArtifactTriagePlugin,
    _BINWALK_MARKER,
    _END_MARKER,
    _FILE_CMD_MARKER,
    _FILE_MARKER,
    _PNG_MARKER,
    _STRINGS_MARKER,
)
from killchain_docker.tools.plugins.artifact_triage import build_output


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

    def test_build_output_registers_artifacts_and_candidates(self) -> None:
        path = "/home/ctfplayer/ctf_files/out.png"
        stdout = "\n".join(
            [
                f"{_FILE_MARKER}\t{path}\t128",
                _FILE_CMD_MARKER,
                "PNG image data, 100 x 40, 8-bit/color RGB, non-interlaced",
                "image/png",
                _STRINGS_MARKER,
                "comment=FLAG FOUND: flag{from_triage}",
                _BINWALK_MARKER,
                "0             0x0             PNG image, 100 x 40, 8-bit/color RGB",
                _END_MARKER,
            ]
        )

        output = build_output(
            ToolExecutionRequest(
                tool_name="artifact_triage",
                capability="artifact.triage",
                metadata={"path": path},
            ),
            ToolExecutionResult(
                tool_name="artifact_triage",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.artifacts[0].path, path)
        self.assertEqual(output.artifacts[0].kind, "image")
        self.assertEqual(output.artifacts[0].size, 128)
        self.assertEqual(output.flag_candidates[0].value, "flag{from_triage}")
        self.assertEqual(output.output_context["records"][0]["signature_count"], 1)

    def test_build_output_registers_png_payload_artifacts(self) -> None:
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/script/out.png"
        chunk_path = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "png_triage/out.png/001_qfme.bin"
        )
        trailing_path = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "png_triage/out.png/trailing_after_iend.bin"
        )
        stdout = "\n".join(
            [
                f"{_FILE_MARKER}\t{path}\t256",
                _FILE_CMD_MARKER,
                "PNG image data, 100 x 40, 8-bit/color RGB, non-interlaced",
                "image/png",
                _STRINGS_MARKER,
                "qfme",
                _PNG_MARKER,
                "chunk\t0\tIHDR\t13\t1\t1\t\t......\t0000000d",
                f"chunk\t1\tqfme\t101\t1\t0\t{chunk_path}\tencoded payload\t41424344",
                "chunk\t2\tIEND\t0\t1\t1\t\t\t",
                f"trailing\t12\t{trailing_path}\tmore bytes\t01020304",
                _END_MARKER,
            ]
        )

        output = build_output(
            ToolExecutionRequest(
                tool_name="artifact_triage",
                capability="artifact.triage",
                metadata={"path": path},
            ),
            ToolExecutionResult(
                tool_name="artifact_triage",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        record = output.output_context["records"][0]
        self.assertEqual(record["png"]["chunk_count"], 3)
        self.assertEqual(record["png"]["nonstandard_chunks"][0]["type"], "qfme")
        child_artifacts = [
            artifact for artifact in output.artifacts
            if artifact.source == "artifact_triage_png"
        ]
        self.assertEqual([artifact.path for artifact in child_artifacts], [chunk_path, trailing_path])
        self.assertEqual(child_artifacts[0].kind, "png_chunk_qfme")
        self.assertEqual(child_artifacts[1].kind, "png_trailing_data")
        self.assertIn("2 png payload artifact(s)", output.summary)

    def test_png_binary_previews_do_not_emit_flag_candidates(self) -> None:
        path = "/home/ctfplayer/ctf_files/noisy.png"
        stdout = "\n".join(
            [
                f"{_FILE_MARKER}\t{path}\t256",
                _FILE_CMD_MARKER,
                "PNG image data, 100 x 40, 8-bit/color RGB, non-interlaced",
                "image/png",
                _STRINGS_MARKER,
                "qfme",
                _PNG_MARKER,
                "chunk\t0\tIHDR\t13\t1\t1\t\t......\t0000000d",
                "chunk\t1\tIDAT\t101\t1\t1\t\tflag{binary_preview_noise}\t41424344",
                "chunk\t2\tIEND\t0\t1\t1\t\t\t",
                _END_MARKER,
            ]
        )

        output = build_output(
            ToolExecutionRequest(
                tool_name="artifact_triage",
                capability="artifact.triage",
                metadata={"path": path},
            ),
            ToolExecutionResult(
                tool_name="artifact_triage",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.flag_candidates, [])

    def test_png_text_chunks_can_emit_literal_flag_candidates(self) -> None:
        path = "/home/ctfplayer/ctf_files/comment.png"
        stdout = "\n".join(
            [
                f"{_FILE_MARKER}\t{path}\t256",
                _FILE_CMD_MARKER,
                "PNG image data, 100 x 40, 8-bit/color RGB, non-interlaced",
                "image/png",
                _STRINGS_MARKER,
                "tEXt",
                _PNG_MARKER,
                "chunk\t0\tIHDR\t13\t1\t1\t\t......\t0000000d",
                "chunk\t1\ttEXt\t32\t1\t1\t\tComment flag{png_text_chunk}\t41424344",
                "chunk\t2\tIEND\t0\t1\t1\t\t\t",
                _END_MARKER,
            ]
        )

        output = build_output(
            ToolExecutionRequest(
                tool_name="artifact_triage",
                capability="artifact.triage",
                metadata={"path": path},
            ),
            ToolExecutionResult(
                tool_name="artifact_triage",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout=stdout,
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["flag{png_text_chunk}"],
        )

    def test_plugin_extracts_png_payload_artifacts_to_durable_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "out.png"
            path.write_bytes(_png_with_nonstandard_chunk_and_trailer())

            request = ToolExecutionRequest(
                tool_name="artifact_triage",
                capability="artifact.triage",
                timeout_s=10,
                metadata={"files_root": str(root), "path": str(path)},
            )
            result = ArtifactTriagePlugin().execute(request)
            output = build_output(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            child_artifacts = [
                artifact for artifact in output.artifacts
                if artifact.source == "artifact_triage_png"
            ]
            self.assertEqual(len(child_artifacts), 2)
            for artifact in child_artifacts:
                self.assertTrue(Path(artifact.path).exists(), artifact.path)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(chunk_type)
    crc = binascii.crc32(payload, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def _png_with_nonstandard_chunk_and_trailer() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"qfme", b"encoded payload"),
            _png_chunk(b"IEND", b""),
            b"tail-bytes",
        ]
    )


if __name__ == "__main__":
    unittest.main()
