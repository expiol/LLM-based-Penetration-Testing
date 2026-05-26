from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.core import ParsedToolOutput
from killchain_docker.tools.plugins.media_scan import MediaScanPlugin, build_output


class MediaScanTests(unittest.TestCase):
    def test_plugin_extracts_appended_payload_and_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "image0.gif"
            payload = b"flag{media_scan_appended_ok_123}"
            image.write_bytes(_one_pixel_gif() + payload)

            request = ToolExecutionRequest(
                tool_name="media_scan",
                capability="media.scan",
                timeout_s=15,
                metadata={
                    "files_root": str(root),
                    "paths": [str(image)],
                    "max_extract_mb": 4,
                },
            )
            result = MediaScanPlugin().execute(request)
            output = build_output(request, result, ParsedToolOutput(summary="raw"))

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(output.output_context["media"][0]["kind"], "gif")
            self.assertEqual(
                output.output_context["media"][0]["appended_size"], len(payload)
            )
            self.assertEqual(
                [candidate.value for candidate in output.flag_candidates],
                ["flag{media_scan_appended_ok_123}"],
            )
            self.assertEqual(len(output.artifacts), 1)
            self.assertEqual(output.artifacts[0].source, "media_scan")
            self.assertEqual(
                output.artifacts[0].digest, hashlib.sha256(payload).hexdigest()
            )
            self.assertTrue(Path(output.artifacts[0].path).exists())


def _one_pixel_gif() -> bytes:
    return (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
        b"\x00\x00\x00\xff\xff\xff"
        b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        b"\x02\x02D\x01\x00;"
    )


if __name__ == "__main__":
    unittest.main()
