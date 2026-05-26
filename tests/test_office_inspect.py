from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from killchain_docker.tools.core import ToolExecutionRequest, ToolExecutionResult
from killchain_docker.tools.core import ExecutionMode, ParsedToolOutput
from killchain_docker.tools.plugins.office_inspect import (
    OfficeInspectPlugin,
    _ARTIFACT_MARKER,
    _DOC_MARKER,
    _ENTRY_MARKER,
    _TEXT_MARKER,
    build_output,
)


class OfficeInspectTests(unittest.TestCase):
    def test_build_output_registers_text_artifacts_and_literal_flags(self) -> None:
        image = (
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/"
            "office_inspect_deck_123/ppt/media/image1.png"
        )
        digest = hashlib.sha256(b"payload").hexdigest()
        stdout = "\n".join(
            [
                f"{_DOC_MARKER}\tpptx\t4",
                f"{_ENTRY_MARKER}\tppt/slides/slide1.xml\t200\t80\tslide",
                f"{_TEXT_MARKER}\tppt/slides/slide1.xml\tslide\tCreated 2012-05-07T19 flag{{office_literal}} CAPTION_ONLY",
                f"{_ARTIFACT_MARKER}\t{image}\t7\tmedia\tppt/media/image1.png\t{digest}",
            ]
        )
        request = ToolExecutionRequest(
            tool_name="office_inspect",
            capability="office.inspect",
            metadata={"path": "/home/ctfplayer/ctf_files/deck.pptx"},
        )
        result = ToolExecutionResult(
            tool_name="office_inspect",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["document_type"], "pptx")
        self.assertEqual(output.output_context["text_items"][0]["role"], "slide")
        self.assertEqual(output.artifacts[0].path, image)
        self.assertEqual(output.artifacts[0].kind, "office_media_image")
        self.assertEqual(output.artifacts[0].source, "office_inspect")
        self.assertEqual(output.artifacts[0].digest, digest)
        self.assertEqual(
            [candidate.value for candidate in output.flag_candidates],
            ["flag{office_literal}"],
        )
        self.assertEqual(
            output.flag_candidates[0].metadata["zip_part"], "ppt/slides/slide1.xml"
        )

    def test_plugin_extracts_ooxml_text_and_embedded_media_to_durable_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deck = root / "deck.pptx"
            with zipfile.ZipFile(deck, "w") as zf:
                zf.writestr("[Content_Types].xml", "<Types/>")
                zf.writestr("ppt/presentation.xml", "<presentation/>")
                zf.writestr(
                    "ppt/slides/slide1.xml",
                    (
                        "<p:sld xmlns:p='p' xmlns:a='a'>"
                        "<p:cNvPr descr='hidden flag{from_alt_text}'/>"
                        "<a:t>Hello slide text</a:t>"
                        "</p:sld>"
                    ),
                )
                zf.writestr(
                    "ppt/notesSlides/notesSlide1.xml",
                    "<p:notes xmlns:p='p' xmlns:a='a'><a:t>Speaker notes</a:t></p:notes>",
                )
                zf.writestr("ppt/media/image1.png", b"\x89PNG\r\n\x1a\npayload")

            request = ToolExecutionRequest(
                tool_name="office_inspect",
                capability="office.inspect",
                timeout_s=15,
                metadata={
                    "files_root": str(root),
                    "path": str(deck),
                    "max_entries": 20,
                    "max_extract_mb": 4,
                },
            )
            result = OfficeInspectPlugin().execute(request)
            output = build_output(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(output.output_context["document_type"], "pptx")
            text = "\n".join(
                item["text"] for item in output.output_context["text_items"]
            )
            self.assertIn("Hello slide text", text)
            self.assertIn("Speaker notes", text)
            self.assertEqual(
                [candidate.value for candidate in output.flag_candidates],
                ["flag{from_alt_text}"],
            )
            self.assertEqual(len(output.artifacts), 1)
            self.assertIsNotNone(output.artifacts[0].digest)
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
                "killchain_docker.tools.plugins.office_inspect._run",
                side_effect=fake_run,
            ):
                OfficeInspectPlugin(
                    argv_prefix=["docker", "exec", "-i", "container"]
                ).execute(
                    ToolExecutionRequest(
                        tool_name="office_inspect",
                        timeout_s=5,
                        metadata={
                            "files_root": tmp,
                            "path": f"{tmp}/deck.pptx",
                            "output_dir": "/tmp/office_out",
                        },
                    )
                )

        command = captured["argv"][-1]
        self.assertIn("__KILLCHAIN_OFFICE_INSPECT_TEXT__", command)
        self.assertIn(".autopentest_artifacts/office_inspect_deck_office_out_", command)
        self.assertIn("_kc_preserve_paths=.autopentest_artifacts", command)
        self.assertNotIn("_kc_out=/tmp/office_out", command)


if __name__ == "__main__":
    unittest.main()
