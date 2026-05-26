"""Artifact follow-up capability normalization."""

from __future__ import annotations

from typing import Any


def artifact_dispatch_profile(capability: str) -> str:
    if capability == "disk.extract":
        return "container_extraction"
    if capability == "office.inspect":
        return "office_inspection"
    if capability == "media.scan":
        return "media_inspection"
    if capability == "png.inspect":
        return "image_inspection"
    return "artifact_analysis"


def requested_capability_is_abstract(value: object) -> bool:
    requested = str(value or "").strip().lower().replace("_", ".")
    return requested in {
        "",
        "analyze",
        "analysis",
        "artifact.analyze",
        "artifact.extract",
        "artifact.inspect",
        "artifact.parse",
        "disk.rawscan",
        "file.analyze",
        "forensics.analyze",
        "forensics.extract",
        "media.analyze",
        "media.inspect",
    }


def requested_capability_targets_artifact(value: object, artifact: Any) -> bool:
    if requested_capability_is_abstract(value):
        return True
    requested = str(value or "").strip().lower().replace("_", ".")
    canonical = artifact.followup_capability
    if canonical == "office.inspect":
        return requested in {
            "document.analyze",
            "document.extract",
            "document.inspect",
            "office.analyze",
            "office.extract",
            "openxml.extract",
            "ppt.extract",
            "pptx.extract",
            "presentation.extract",
        }
    if canonical == "png.inspect":
        return requested in {
            "image.analyze",
            "image.extract",
            "image.inspect",
            "png.analyze",
            "png.extract",
            "stego.analyze",
            "steganalysis",
        }
    if canonical == "media.scan":
        return requested in {
            "media.analyze",
            "media.extract",
            "media.inspect",
            "video.analyze",
            "video.extract",
        }
    return False


__all__ = [
    "artifact_dispatch_profile",
    "requested_capability_is_abstract",
    "requested_capability_targets_artifact",
]
