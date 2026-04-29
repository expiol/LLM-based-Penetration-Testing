"""Backwards-compat shim — see :mod:`agents.artifact_worker` for the implementation."""

from nyuctf_mutil_killchain.agents.artifact_worker import ArtifactWorker

ArtifactTriageAgent = ArtifactWorker

__all__ = ["ArtifactTriageAgent", "ArtifactWorker"]
