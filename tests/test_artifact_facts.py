from __future__ import annotations

import unittest

from killchain_docker.state import Artifact
from killchain_docker.state.artifact_facts import (
    artifact_followup_capability,
    artifact_followup_priority,
    facts_from_artifact,
)


class ArtifactFactsTests(unittest.TestCase):
    def test_same_content_with_different_names_gets_same_capability(self) -> None:
        metadata = {
            "file_type": "PNG image data, 1 x 1, 8-bit/color RGBA",
            "mime_type": "image/png",
        }
        paths = [
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/a/out.png",
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/a/out",
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/a/out.random",
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/a/out with spaces",
        ]

        artifacts = [
            Artifact(
                path=path,
                kind="script_artifact",
                source="script_exec",
                metadata=dict(metadata),
            )
            for path in paths
        ]

        self.assertEqual(
            {artifact_followup_capability(artifact) for artifact in artifacts},
            {"png.inspect"},
        )
        self.assertEqual(
            {artifact_followup_priority(artifact) for artifact in artifacts},
            {85},
        )

    def test_unknown_generated_content_is_triaged_without_name_signal(self) -> None:
        artifacts = [
            Artifact(
                path=f"/home/ctfplayer/ctf_files/.autopentest_artifacts/a/{name}",
                kind="script_artifact",
                source="script_exec",
            )
            for name in ("out", "out.random", "out with spaces")
        ]

        self.assertEqual(
            {artifact_followup_capability(artifact) for artifact in artifacts},
            {"artifact.triage"},
        )

    def test_low_signal_font_comes_from_content_metadata(self) -> None:
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/a/bootstrap.asset",
            kind="script_artifact",
            source="script_exec",
            metadata={"file_type": "Web Open Font Format, TrueType"},
        )

        facts = facts_from_artifact(artifact)

        self.assertTrue(facts.is_low_signal)
        self.assertEqual(artifact_followup_priority(artifact), 0)

    def test_tool_source_prefix_does_not_make_child_artifact_a_disk_image(self) -> None:
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk/offset_0/store",
            kind="disk_extract_database",
            source="disk_extract",
            metadata={"file_type": "data"},
        )

        facts = facts_from_artifact(artifact)

        self.assertFalse(facts.is_disk_image)
        self.assertNotEqual(artifact_followup_capability(artifact), "disk.extract")


if __name__ == "__main__":
    unittest.main()
