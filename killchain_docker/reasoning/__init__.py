"""Centralized LLM-reasoning glue for workers.

Each module here owns the prompt construction, schema selection, and result
post-processing for one stage.  Workers call these as plain functions,
keeping LLM concerns out of the worker control flow.

The schemas (Pydantic ``BaseModel`` subclasses) live in :mod:`schemas` so
they can be imported without pulling in the prompt text or state types.
"""

from killchain_docker.reasoning.schemas import (
    ArtifactTriageGuidance,
    CredentialHarvestGuidance,
    CredentialTestGuidance,
    EvidenceReviewGuidance,
    ExploitHypothesisGuidance,
    ExploitProbeGuidance,
    FormProbeGuidance,
    ScriptCodeGuidance,
    StageAnalysisGuidance,
    ToolUseDecision,
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
    "ScriptCodeGuidance",
    "StageAnalysisGuidance",
    "ToolUseDecision",
    "boost_prioritized_tasks",
]
