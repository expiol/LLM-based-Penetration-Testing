"""Artifact-stage workers, one per task type.

Replaces the monolithic ``ArtifactWorker`` aggregator with single-purpose
classes the orchestrator can route to individually.
"""

from killchain_docker.workers.artifact.archive import ArchiveTriageAgent
from killchain_docker.workers.artifact.binary import BinaryTriageAgent
from killchain_docker.workers.artifact.computation import ComputationAnalysisAgent
from killchain_docker.workers.artifact.deep_review import DeepReviewAgent
from killchain_docker.workers.artifact.pcap import PcapReviewAgent
from killchain_docker.workers.artifact.repo import RepoReviewAgent
from killchain_docker.workers.artifact.runtime import RuntimeProbeAgent
from killchain_docker.workers.artifact.source_review import SourceReviewAgent
from killchain_docker.workers.artifact.sqlite import SqliteReviewAgent
from killchain_docker.workers.artifact.triage import ArtifactTriageAgent
from killchain_docker.workers.specs import worker_specs

GROUP = "artifact"

WORKER_CLASSES: tuple[type, ...] = (
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

WORKER_SPECS = worker_specs(GROUP, WORKER_CLASSES)

__all__ = [
    "ArchiveTriageAgent",
    "ArtifactTriageAgent",
    "BinaryTriageAgent",
    "ComputationAnalysisAgent",
    "DeepReviewAgent",
    "GROUP",
    "PcapReviewAgent",
    "RepoReviewAgent",
    "RuntimeProbeAgent",
    "SourceReviewAgent",
    "SqliteReviewAgent",
    "WORKER_CLASSES",
    "WORKER_SPECS",
]
