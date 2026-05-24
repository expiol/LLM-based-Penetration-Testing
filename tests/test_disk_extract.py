from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from killchain_docker.tools import ToolExecutionRequest, ToolExecutionResult
from killchain_docker.tools.core import ExecutionMode, ParsedToolOutput
from killchain_docker.tools.plugins.disk_extract import (
    DiskExtractPlugin,
    _ENTRY_MARKER,
    _FILE_MARKER,
    _PARTITION_MARKER,
    _SKIP_MARKER,
    _SUMMARY_MARKER,
    build_output,
)


class DiskExtractTests(unittest.TestCase):
    def test_build_output_registers_durable_extracted_artifacts(self) -> None:
        ppt = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "disk_extract_out_123/offset_0/slides.pptx"
        )
        image = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "disk_extract_out_123/offset_0/media/image.png"
        )
        stdout = "\n".join(
            [
                f"{_PARTITION_MARKER}\t0\toffset_0",
                f"{_ENTRY_MARKER}\t0\tr/r\t12\tSLIDES.PPTX",
                (
                    f"{_FILE_MARKER}\t{ppt}\t4096\tfilesystem\t0\t12\t"
                    f"SLIDES.PPTX\t{'a' * 64}\tMicrosoft PowerPoint 2007+\t"
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                ),
                (
                    f"{_FILE_MARKER}\t{image}\t512\tembedded_zip\t304128\t"
                    f"embedded_zip@304128\t304128\t{'b' * 64}\tPNG image data\t"
                    "image/png"
                ),
                f"{_SKIP_MARKER}\tbudget\t0\tlarge.bin\t104857600",
                "FLAG FOUND: flag{from_disk_extract}",
                f"{_SUMMARY_MARKER}\t2\t4608\t1",
            ]
        )
        request = ToolExecutionRequest(
            tool_name="disk_extract",
            capability="disk.extract",
            metadata={"path": "/home/ctfplayer/ctf_files/out.img"},
        )
        result = ToolExecutionResult(
            tool_name="disk_extract",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["extracted_count"], 2)
        self.assertTrue(output.output_context["extracted_files_durable"])
        self.assertEqual(output.artifacts[0].path, ppt)
        self.assertEqual(output.artifacts[0].kind, "disk_extract_document")
        self.assertEqual(output.artifacts[0].source, "disk_extract")
        self.assertEqual(output.artifacts[0].digest, "a" * 64)
        self.assertEqual(
            output.artifacts[0].metadata["mime_type"],
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        self.assertEqual(output.artifacts[1].metadata["file_type"], "PNG image data")
        self.assertEqual(output.artifacts[1].kind, "disk_extract_image")
        self.assertEqual(output.output_context["extracted_file_records"][1]["digest"], "b" * 64)
        self.assertEqual(output.flag_candidates[0].value, "flag{from_disk_extract}")
        self.assertIn("2 durable file(s)", output.summary)

    def test_plugin_preserves_durable_artifact_directory(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(name: str, argv: list[str], timeout_s: int, **_: object) -> ToolExecutionResult:
            captured["argv"] = argv
            captured["timeout_s"] = timeout_s
            return ToolExecutionResult(tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=0)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("killchain_docker.tools.plugins.disk_extract._run", side_effect=fake_run):
                DiskExtractPlugin(argv_prefix=["docker", "exec", "-i", "container"]).execute(
                    ToolExecutionRequest(
                        tool_name="disk_extract",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "path": f"{tmp}/out.img",
                            "output_dir": "/tmp/disk_out",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("__KILLCHAIN_DISK_EXTRACT_FILE__", command)
        self.assertIn(".autopentest_artifacts/disk_extract_out_disk_out_", command)
        self.assertIn("_kc_preserve_paths=.autopentest_artifacts", command)
        self.assertNotIn("_kc_out=/tmp/disk_out", command)

    def test_plugin_carves_embedded_ooxml_zip_to_durable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as zf:
                zf.writestr("[Content_Types].xml", "<Types/>")
                zf.writestr("ppt/presentation.xml", "<presentation/>")
            source = root / "image.bin"
            source.write_bytes(b"header" + payload.getvalue() + b"tail")

            request = ToolExecutionRequest(
                tool_name="disk_extract",
                capability="disk.extract",
                timeout_s=15,
                metadata={
                    "files_root": str(root),
                    "path": str(source),
                    "max_files": 4,
                    "max_extract_mb": 4,
                },
            )
            result = DiskExtractPlugin().execute(request)
            output = build_output(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(output.output_context["extracted_count"], 1)
            artifact = output.artifacts[0]
            self.assertTrue(artifact.path.endswith(".pptx"), artifact.path)
            self.assertEqual(artifact.kind, "disk_extract_document")
            self.assertEqual(len(artifact.digest or ""), 64)
            self.assertTrue(Path(artifact.path).exists(), artifact.path)


if __name__ == "__main__":
    unittest.main()
