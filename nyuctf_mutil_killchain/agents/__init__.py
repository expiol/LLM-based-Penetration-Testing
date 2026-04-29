"""Worker agents.

The runtime registers one stage worker per kill-chain phase:

  - :class:`ReconAgent` (recon stage)
  - :class:`ArtifactWorker` (artifact stage; consolidates 9 former agents)
  - :class:`SurfaceWorker` (recon-surface stage; web + host)
  - :class:`CredentialWorker` (credential harvest stage)
  - :class:`ExploitWorker` (exploitation stage; credential reuse, CVE probe,
    hypothesis reasoning, flag hunt)
  - :class:`VulnScanAgent` (vulnerability scan stage)
  - :class:`SolverAgent` (LLM solver stage)
  - :class:`FlagValidationAgent` (flag validation stage)

Existing per-task-type classes (``ArtifactTriageAgent``, ``WebContentAgent``,
``WebFormProbeAgent``, etc.) remain importable as backwards-compat aliases
or as inner delegates for the stage workers.
"""

# Per-task-type classes (still importable for tests and backwards compatibility).
from nyuctf_mutil_killchain.agents.artifact import ArtifactTriageAgent
from nyuctf_mutil_killchain.agents.artifact_worker import ArtifactWorker
from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.binary_triage import BinaryTriageAgent
from nyuctf_mutil_killchain.agents.computation import ComputationAnalysisAgent
from nyuctf_mutil_killchain.agents.credential import CredentialHuntAgent
from nyuctf_mutil_killchain.agents.credential_worker import CredentialWorker
from nyuctf_mutil_killchain.agents.enrichment import (
    ArchiveTriageAgent,
    PcapReviewAgent,
    RepoReviewAgent,
    ServiceBannerAgent,
    SQLiteReviewAgent,
    WebPathProbeAgent,
)
from nyuctf_mutil_killchain.agents.exploit import CredentialExploitAgent, WebPwnExploitAgent
from nyuctf_mutil_killchain.agents.exploit_reasoning import ExploitReasoningAgent
from nyuctf_mutil_killchain.agents.exploit_worker import ExploitWorker
from nyuctf_mutil_killchain.agents.flag import FlagValidationAgent
from nyuctf_mutil_killchain.agents.flag_hunt import FlagHuntAgent
from nyuctf_mutil_killchain.agents.host import HostAuditAgent
from nyuctf_mutil_killchain.agents.recon import ReconAgent
from nyuctf_mutil_killchain.agents.runtime import RuntimeProbeAgent
from nyuctf_mutil_killchain.agents.solver import SolverAgent
from nyuctf_mutil_killchain.agents.source_review import SourceReviewAgent
from nyuctf_mutil_killchain.agents.surface import SurfaceWorker
from nyuctf_mutil_killchain.agents.vuln import VulnScanAgent
from nyuctf_mutil_killchain.agents.web import WebAssessmentAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.agents.web_form import WebFormProbeAgent

__all__ = [
    # Stage workers (preferred for orchestrator registration).
    "ArtifactWorker",
    "CredentialWorker",
    "ExploitWorker",
    "FlagValidationAgent",
    "ReconAgent",
    "SolverAgent",
    "SurfaceWorker",
    "VulnScanAgent",
    "WorkerAgent",
    # Per-task-type classes (backwards compatibility).
    "ArchiveTriageAgent",
    "ArtifactTriageAgent",
    "BinaryTriageAgent",
    "ComputationAnalysisAgent",
    "CredentialExploitAgent",
    "CredentialHuntAgent",
    "ExploitReasoningAgent",
    "FlagHuntAgent",
    "HostAuditAgent",
    "PcapReviewAgent",
    "RepoReviewAgent",
    "RuntimeProbeAgent",
    "ServiceBannerAgent",
    "SourceReviewAgent",
    "SQLiteReviewAgent",
    "WebAssessmentAgent",
    "WebContentAgent",
    "WebFormProbeAgent",
    "WebPathProbeAgent",
    "WebPwnExploitAgent",
]
