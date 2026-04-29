"""Backwards-compat shim — see :mod:`agents.artifact_worker` for the implementation."""

from nyuctf_mutil_killchain.agents.artifact_worker import ArtifactWorker

RuntimeProbeAgent = ArtifactWorker

__all__ = ["RuntimeProbeAgent"]
