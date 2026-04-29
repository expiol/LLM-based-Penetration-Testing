"""Consolidated credential-stage worker.

The credential stage currently has only one task type (``credential.hunt``),
so the stage worker is just a renamed alias of :class:`CredentialHuntAgent`.
This module exists so the orchestrator and the layering tests can refer to a
stable per-stage worker name even when there is only one task type.
"""

from nyuctf_mutil_killchain.agents.credential import CredentialHuntAgent

CredentialWorker = CredentialHuntAgent

__all__ = ["CredentialWorker"]
