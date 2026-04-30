"""Worker agents.

Each worker class targets exactly one ``task_type``.  Workers are organized
into capability groups under :mod:`agents.groups`; the orchestrator
discovers them via ``groups.all_worker_classes()``.
"""

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
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.credential import CredentialHuntAgent
from nyuctf_mutil_killchain.agents.enrichment import (
    ServiceBannerAgent,
    WebPathProbeAgent,
)
from nyuctf_mutil_killchain.agents.exploit import (
    CredentialExploitAgent,
    WebPwnExploitAgent,
)
from nyuctf_mutil_killchain.agents.exploit_reasoning import ExploitReasoningAgent
from nyuctf_mutil_killchain.agents.flag import FlagValidationAgent
from nyuctf_mutil_killchain.agents.flag_hunt import FlagHuntAgent
from nyuctf_mutil_killchain.agents.groups import all_worker_classes
from nyuctf_mutil_killchain.agents.host import HostAuditAgent
from nyuctf_mutil_killchain.agents.recon import ReconAgent
from nyuctf_mutil_killchain.agents.solver import SolverAgent
from nyuctf_mutil_killchain.agents.vuln import VulnScanAgent
from nyuctf_mutil_killchain.agents.web import WebAssessmentAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.agents.web_form import WebFormProbeAgent

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
