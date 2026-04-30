"""Credential-stage worker group."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.credential import CredentialHuntAgent

CREDENTIAL_WORKERS: tuple[type, ...] = (CredentialHuntAgent,)


__all__ = [
    "CREDENTIAL_WORKERS",
    "CredentialHuntAgent",
]
