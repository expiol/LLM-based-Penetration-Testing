"""Host / recon worker group."""

from __future__ import annotations

from killchain_docker.agents.enrichment import ServiceBannerAgent
from killchain_docker.agents.host import HostAuditAgent
from killchain_docker.agents.recon import ReconAgent

HOST_WORKERS: tuple[type, ...] = (
    ReconAgent,
    HostAuditAgent,
    ServiceBannerAgent,
)


__all__ = [
    "HOST_WORKERS",
    "HostAuditAgent",
    "ReconAgent",
    "ServiceBannerAgent",
]
