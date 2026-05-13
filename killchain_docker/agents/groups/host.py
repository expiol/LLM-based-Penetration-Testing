"""Host / recon worker group."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.enrichment import ServiceBannerAgent
from nyuctf_mutil_killchain.agents.host import HostAuditAgent
from nyuctf_mutil_killchain.agents.recon import ReconAgent

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
