"""Recon fact stores for assets, findings, credentials, and graph edges."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from killchain_docker.state.fact_merges import (
    merge_asset,
    merge_credential,
    merge_finding,
)
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import Asset, Credential, Finding, NetworkEdge
    from killchain_docker.state.run_state import RunState


class ReconFactStore:
    """Mutable store for recon-derived state facts."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def asset(self, asset: "Asset", *, touch: bool = True) -> None:
        if asset.asset_id in self.state.assets:
            merge_asset(self.state.assets[asset.asset_id], asset)
        else:
            self.state.assets[asset.asset_id] = asset
        if touch:
            self.maintenance.touch()

    def finding(self, finding: "Finding", *, touch: bool = True) -> None:
        if finding.finding_id in self.state.findings:
            merge_finding(self.state.findings[finding.finding_id], finding)
        else:
            self.state.findings[finding.finding_id] = finding
        if touch:
            self.maintenance.touch()

    def credential(self, credential: "Credential", *, touch: bool = True) -> None:
        if credential.credential_id in self.state.credentials:
            merge_credential(
                self.state.credentials[credential.credential_id], credential
            )
        else:
            self.state.credentials[credential.credential_id] = credential
        if touch:
            self.maintenance.touch()

    def network_edges(
        self, edges: "Iterable[NetworkEdge]", *, touch: bool = True
    ) -> None:
        appended = list(edges)
        if not appended:
            return
        self.state.network_edges.extend(appended)
        if touch:
            self.maintenance.touch()
