"""Worker agents.

Each worker class targets exactly one ``task_type``.  Workers are organized
into capability groups under :mod:`agents.groups`; the orchestrator
discovers them via ``groups.all_worker_classes()``.
"""

from killchain_docker.agents.artifact import (
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
from killchain_docker.agents.base import WorkerAgent
from killchain_docker.agents.credential import CredentialHuntAgent
from killchain_docker.agents.enrichment import (
    ServiceBannerAgent,
    WebPathProbeAgent,
)
from killchain_docker.agents.exploit import (
    CredentialExploitAgent,
    WebPwnExploitAgent,
)
from killchain_docker.agents.exploit_reasoning import ExploitReasoningAgent
from killchain_docker.agents.flag import FlagValidationAgent
from killchain_docker.agents.flag_hunt import FlagHuntAgent
from killchain_docker.agents.groups import all_worker_classes
from killchain_docker.agents.host import HostAuditAgent
from killchain_docker.agents.recon import ReconAgent
from killchain_docker.agents.solver import SolverAgent
from killchain_docker.agents.vuln import VulnScanAgent
from killchain_docker.agents.web import WebAssessmentAgent
from killchain_docker.agents.web_content import WebContentAgent
from killchain_docker.agents.web_form import WebFormProbeAgent

__all__ = [
    "ArchiveTriageAgent",
    "ArtifactTriageAgent",
    "BinaryTriageAgent",
    "ComputationAnalysisAgent",
    "CredentialExploitAgent",
    "CredentialHuntAgent",
    "DeepReviewAgent",
    "ExploitReasoningAgent",
    "FlagHuntAgent",
    "FlagValidationAgent",
    "HostAuditAgent",
    "PcapReviewAgent",
    "ReconAgent",
    "RepoReviewAgent",
    "RuntimeProbeAgent",
    "ServiceBannerAgent",
    "SolverAgent",
    "SourceReviewAgent",
    "SqliteReviewAgent",
    "VulnScanAgent",
    "WebAssessmentAgent",
    "WebContentAgent",
    "WebFormProbeAgent",
    "WebPathProbeAgent",
    "WebPwnExploitAgent",
    "WorkerAgent",
    "all_worker_classes",
]
