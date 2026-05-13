"""Static / artifact-stage worker group.

All workers that process bundled challenge files - inventory, decode,
disassemble, extract.  Each task type maps to exactly one worker class.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.artifact import (
    ArchiveTriageAgent,
    ArtifactTriageAgent,
    BinaryTriageAgent,
    ComputationAnalysisAgent,
    DeepReviewAgent,
    PcapReviewAgent,
    RepoReviewAgent,
    RuntimeProbeAgent,
    SourceReviewAgent,
    SqliteReviewAgent,
)

STATIC_ANALYSIS_WORKERS: tuple[type, ...] = (
    ArtifactTriageAgent,
    BinaryTriageAgent,
    ArchiveTriageAgent,
    SqliteReviewAgent,
    PcapReviewAgent,
    RepoReviewAgent,
    SourceReviewAgent,
    ComputationAnalysisAgent,
    RuntimeProbeAgent,
    DeepReviewAgent,
)


__all__ = [
    "ArchiveTriageAgent",
    "ArtifactTriageAgent",
    "BinaryTriageAgent",
    "ComputationAnalysisAgent",
    "DeepReviewAgent",
    "PcapReviewAgent",
    "RepoReviewAgent",
    "RuntimeProbeAgent",
    "SourceReviewAgent",
    "SqliteReviewAgent",
    "STATIC_ANALYSIS_WORKERS",
]
