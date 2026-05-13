"""Vuln-scan worker group."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.vuln import VulnScanAgent

VULN_WORKERS: tuple[type, ...] = (VulnScanAgent,)


__all__ = [
    "VULN_WORKERS",
    "VulnScanAgent",
]
