"""Artifact-stage workers, one per task type.

Replaces the monolithic ``ArtifactWorker`` aggregator with single-purpose
classes the orchestrator can route to individually.
"""

from nyuctf_mutil_killchain.agents.artifact.archive import ArchiveTriageAgent
from nyuctf_mutil_killchain.agents.artifact.binary import BinaryTriageAgent
from nyuctf_mutil_killchain.agents.artifact.computation import ComputationAnalysisAgent
from nyuctf_mutil_killchain.agents.artifact.deep_review import DeepReviewAgent
from nyuctf_mutil_killchain.agents.artifact.pcap import PcapReviewAgent
from nyuctf_mutil_killchain.agents.artifact.repo import RepoReviewAgent
from nyuctf_mutil_killchain.agents.artifact.runtime import RuntimeProbeAgent
from nyuctf_mutil_killchain.agents.artifact.source_review import SourceReviewAgent
from nyuctf_mutil_killchain.agents.artifact.sqlite import SqliteReviewAgent
from nyuctf_mutil_killchain.agents.artifact.triage import ArtifactTriageAgent

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
]
