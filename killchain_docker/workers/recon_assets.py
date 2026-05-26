"""Recon-worker asset synthesis."""

from __future__ import annotations

from urllib.parse import urlparse

from killchain_docker.state.domain import Asset, AssetKind, Service
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult


def inject_recon_asset(task: TodoItem, state: RunState, result: WorkerResult) -> None:
    scope = str(
        task.context.get("scope")
        or (state.authorized_scope[0] if state.authorized_scope else "")
    )
    parsed = urlparse(scope)
    if result.success and scope and (parsed.scheme in {"http", "https"}):
        asset_id = str(task.context.get("asset_id") or "seed-asset")
        asset = Asset(
            asset_id=asset_id,
            kind=AssetKind.WEB_APPLICATION,
            hostname=parsed.hostname,
            base_url=scope,
            services=[
                Service(
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    name=parsed.scheme,
                )
            ],
            tags={"seed", "recon"},
        )
        result.asset_updates.append(asset)
