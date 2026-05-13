"""Credential-stage worker group."""

from __future__ import annotations

from killchain_docker.agents.credential import CredentialHuntAgent

CREDENTIAL_WORKERS: tuple[type, ...] = (CredentialHuntAgent,)


__all__ = [
    "CREDENTIAL_WORKERS",
    "CredentialHuntAgent",
]
