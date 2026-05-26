from __future__ import annotations

import binascii
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from killchain_docker.tools.core import ToolExecutionRequest, ToolExecutionResult
from killchain_docker.tools.core import ExecutionMode, ParsedToolOutput
from killchain_docker.tools.plugins.png_inspect import (
    PngInspectPlugin,
    _ARTIFACT_MARKER,
    _CHUNK_MARKER,
    _LSB_MARKER,
    _PNG_MARKER,
    _TEXT_MARKER,
    _VISUAL_MARKER,
    build_output,
)


class PngInspectTests(unittest.TestCase):
    def test_build_output_registers_artifacts_and_literal_candidates(self) -> None:
        artifact_path = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "png_inspect_out/lsb_all_1_msb.bin"
        )
        digest = hashlib.sha256(b"flag{png_lsb_literal}").hexdigest()
        stdout = "\n".join(
            [
                f"{_PNG_MARKER}\t64\t8\t8\t2\t0\t3",
                f"{_CHUNK_MARKER}\t0\tIHDR\t8\t13\t1\t1",
                f"{_TEXT_MARKER}\ttEXt\tComment\tflag{{png_text_literal}}",
                f"{_VISUAL_MARKER}\tluma\t64\t8\t255\t0.500\t##..\\n..##",
                (
                    f"{_LSB_MARKER}\tall\t1\tmsb\t21\t0.800\t{artifact_path}\t"
                    "flag{png_lsb_literal}\tflag{png_lsb_literal}"
                ),
                f"{_ARTIFACT_MARKER}\t{artifact_path}\t21\tlsb\tall:1:msb\t{digest}",
            ]
        )
        request = ToolExecutionRequest(
            tool_name="png_inspect",
            capability="png.inspect",
            metadata={"path": "/home/ctfplayer/ctf_files/image.png"},
        )
        result = ToolExecutionResult(
            tool_name="png_inspect",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["width"], 64)
        self.assertEqual(output.output_context["chunks"][0]["type"], "IHDR")
        self.assertEqual(output.output_context["visual_previews"][0]["plane"], "luma")
        self.assertEqual(
            output.output_context["visual_previews"][0]["preview"], "##..\n..##"
        )
        self.assertEqual(output.artifacts[0].path, artifact_path)
        self.assertEqual(output.artifacts[0].source, "png_inspect")
        self.assertEqual(output.artifacts[0].digest, digest)
        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["flag{png_text_literal}", "flag{png_lsb_literal}"],
        )

    def test_plugin_extracts_text_chunks_and_lsb_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "hidden.png"
            image.write_bytes(_png_with_text_and_lsb_flag("flag{lsb_png_ok_123}"))

            request = ToolExecutionRequest(
                tool_name="png_inspect",
                capability="png.inspect",
                timeout_s=15,
                metadata={
                    "files_root": str(root),
                    "path": str(image),
                    "max_extract_mb": 4,
                    "max_lsb_bytes": 4096,
                },
            )
            result = PngInspectPlugin().execute(request)
            output = build_output(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(output.output_context["width"], 64)
            self.assertTrue(output.output_context["lsb"])
            self.assertTrue(output.output_context["visual_previews"])
            self.assertIn(
                "comment text", output.output_context["text_items"][0]["text"]
            )
            self.assertIn(
                "flag{lsb_png_ok_123}", [c.value for c in output.flag_candidates]
            )
            self.assertTrue(output.artifacts)
            self.assertTrue(
                Path(output.artifacts[0].path).exists(), output.artifacts[0].path
            )

    def test_plugin_preserves_durable_artifact_directory(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(
            name: str, argv: list[str], timeout_s: int, **_: object
        ) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(
                tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0
            )

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "killchain_docker.tools.plugins.png_inspect._run", side_effect=fake_run
            ):
                PngInspectPlugin(
                    argv_prefix=["docker", "exec", "-i", "container"]
                ).execute(
                    ToolExecutionRequest(
                        tool_name="png_inspect",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "path": f"{tmp}/image.png",
                            "output_dir": "/tmp/png_out",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("__KILLCHAIN_PNG_INSPECT_LSB__", command)
        self.assertIn(".autopentest_artifacts/png_inspect_image_png_out_", command)
        self.assertIn("_kc_preserve_paths=.autopentest_artifacts", command)
        self.assertNotIn("_kc_out=/tmp/png_out", command)

    def test_lsb_noise_does_not_emit_derived_or_low_entropy_candidates(self) -> None:
        stdout = "\n".join(
            [
                f"{_PNG_MARKER}\t64\t8\t8\t2\t0\t1",
                f"{_LSB_MARKER}\tall\t1\tmsb\t32\t0.900\t\t7_{{Y | y}} | flag{{UUUUUUUUUUUUUUUUUUUUU_}}\t7_{{Y | y}}",
            ]
        )
        request = ToolExecutionRequest(
            tool_name="png_inspect",
            capability="png.inspect",
            metadata={"path": "/home/ctfplayer/ctf_files/image.png"},
        )
        result = ToolExecutionResult(
            tool_name="png_inspect",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.flag_candidates, [])

    def test_expected_flag_prefix_filters_wrong_literal_prefixes(self) -> None:
        stdout = "\n".join(
            [
                f"{_PNG_MARKER}\t64\t8\t8\t2\t0\t1",
                f"{_LSB_MARKER}\tall\t1\tmsb\t32\t0.900\t\tH3w{{noise_body}} | flag{{valid_body_123}}\tpreview",
            ]
        )
        request = ToolExecutionRequest(
            tool_name="png_inspect",
            capability="png.inspect",
            metadata={
                "path": "/home/ctfplayer/ctf_files/image.png",
                "flag_format": "flag{...}",
            },
        )
        result = ToolExecutionResult(
            tool_name="png_inspect",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["flag{valid_body_123}"],
        )


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(chunk_type)
    crc = binascii.crc32(payload, crc) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)
    )


def _png_with_text_and_lsb_flag(message: str) -> bytes:
    width = 64
    height = 8
    channels = 3
    pixels = bytearray([0xFE] * (width * height * channels))
    bits: list[int] = []
    for byte in message.encode("ascii"):
        bits.extend((byte >> bit) & 1 for bit in range(7, -1, -1))
    for index, bit in enumerate(bits):
        pixels[index] = (pixels[index] & 0xFE) | bit
    rows = bytearray()
    stride = width * channels
    for row in range(height):
        rows.append(0)
        start = row * stride
        rows.extend(pixels[start : start + stride])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"tEXt", b"Comment\x00comment text"),
            _png_chunk(b"IDAT", zlib.compress(bytes(rows))),
            _png_chunk(b"IEND", b""),
        ]
    )


if __name__ == "__main__":
    unittest.main()
