"""Artifact-stage workers, one per task type.

Replaces the monolithic ``ArtifactWorker`` aggregator with single-purpose
classes the orchestrator can route to individually.
"""

from killchain_docker.agents.artifact.archive import ArchiveTriageAgent
from killchain_docker.agents.artifact.binary import BinaryTriageAgent
from killchain_docker.agents.artifact.computation import ComputationAnalysisAgent
from killchain_docker.agents.artifact.deep_review import DeepReviewAgent
from killchain_docker.agents.artifact.pcap import PcapReviewAgent
from killchain_docker.agents.artifact.repo import RepoReviewAgent
from killchain_docker.agents.artifact.runtime import RuntimeProbeAgent
from killchain_docker.agents.artifact.source_review import SourceReviewAgent
from killchain_docker.agents.artifact.sqlite import SqliteReviewAgent
from killchain_docker.agents.artifact.triage import ArtifactTriageAgent

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
