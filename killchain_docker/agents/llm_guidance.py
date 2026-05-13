"""Backwards-compat shim: schemas now live in ``agents.reasoning.schemas``.

This module is kept so existing imports (``from
nyuctf_mutil_killchain.agents.llm_guidance import ...``) keep working during
and after the refactor.  New code should import directly from
:mod:`nyuctf_mutil_killchain.agents.reasoning`.
"""

from nyuctf_mutil_killchain.agents.reasoning.schemas import (  # noqa: F401
    ArtifactTriageGuidance,
    CredentialHarvestGuidance,
    CredentialTestGuidance,
    EvidenceReviewGuidance,
    ExploitHypothesisGuidance,
    ExploitProbeGuidance,
    FormProbeGuidance,
    SolverCodeGuidance,
    StageAnalysisGuidance,
    boost_prioritized_tasks,
)

__all__ = [
    "ArtifactTriageGuidance",
    "CredentialHarvestGuidance",
    "CredentialTestGuidance",
    "EvidenceReviewGuidance",
    "ExploitHypothesisGuidance",
    "ExploitProbeGuidance",
    "FormProbeGuidance",
    "SolverCodeGuidance",
    "StageAnalysisGuidance",
    "boost_prioritized_tasks",
]
