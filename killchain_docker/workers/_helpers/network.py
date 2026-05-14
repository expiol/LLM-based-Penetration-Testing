"""Network / web context inference helpers for workers."""

from __future__ import annotations

from collections.abc import Iterable

from killchain_docker.state import GlobalState, Service, Task

COMMON_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 5601, 9200})
DEFAULT_WEB_PORTS = frozenset({80, 443})
TLS_WEB_PORTS = frozenset({443, 8443})
WEB_SERVICE_NAMES = frozenset(
    {
        "http",
        "https",
        "http-proxy",
        "ssl/http",
        "sun-answerbook",
    }
)
AMBIGUOUS_WEB_SERVICE_NAMES = frozenset({"http-alt"})
WEB_SERVICE_TOKENS = (
    "apache",
    "caddy",
    "django",
    "express",
    "flask",
    "gunicorn",
    "http",
    "https",
    "iis",
    "jetty",
    "nginx",
    "tomcat",
    "uvicorn",
    "werkzeug",
    "web",
)


def infer_web_urls(
    *,
    hostname: str | None,
    ip_address: str | None,
    services: Iterable[Service],
) -> list[str]:
    """Infer candidate web URLs from service fingerprints."""

    target_host = hostname or ip_address
    if not target_host:
        return []

    urls: list[str] = []
    for service in services:
        if not service_looks_like_web(service):
            continue

        scheme = infer_web_scheme(port=service.port, service_name=service.name)
        candidate = f"{scheme}://{target_host}:{service.port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


def service_looks_like_web(service: Service) -> bool:
    """Return True when service metadata is strong enough to justify HTTP probing."""

    service_name = (service.name or "").strip().lower()
    service_fingerprint = " ".join(
        part.strip().lower()
        for part in (service.name, service.product, service.version)
        if part
    )

    if service_name in WEB_SERVICE_NAMES:
        return True
    if (
        service_name in AMBIGUOUS_WEB_SERVICE_NAMES
        and not (service.product or "").strip()
        and not (service.version or "").strip()
        and service.port not in DEFAULT_WEB_PORTS
    ):
        return False
    if any(token in service_fingerprint for token in WEB_SERVICE_TOKENS):
        return True
    return service.port in DEFAULT_WEB_PORTS


def infer_web_scheme(*, port: int, service_name: str | None = None) -> str:
    """Infer the most likely HTTP scheme for a service."""

    normalized_name = (service_name or "").strip().lower()
    if normalized_name == "https" or port in TLS_WEB_PORTS:
        return "https"
    return "http"


def banner_looks_like_http(banner: str) -> bool:
    """Return True if a captured banner looks like an HTTP response."""

    text = banner.strip()
    if not text:
        return False

    lowered = text.lower()
    if text.startswith(("HTTP/1.", "HTTP/2", "HTTP/3")):
        return True
    if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        return True
    if "content-type:" in lowered and "server:" in lowered:
        return True
    return False


def infer_web_urls_from_banners(
    *,
    hostname: str | None,
    ip_address: str | None,
    banner_hits: dict[str, str] | None,
) -> list[str]:
    """Infer candidate web URLs from TCP banner captures."""

    target_host = hostname or ip_address
    if not target_host or not banner_hits:
        return []

    urls: list[str] = []
    for raw_port, banner in banner_hits.items():
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if not banner_looks_like_http(str(banner)):
            continue

        scheme = infer_web_scheme(port=port)
        candidate = f"{scheme}://{target_host}:{port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


def infer_web_context(
    task: Task,
    state: GlobalState,
) -> tuple[str | None, str | None]:
    """Resolve (asset_id, base_url) from task context and state.

    Only performs deterministic lookups:
    - Both present: return as-is.
    - asset_id given: look up base_url from that specific asset.
    - base_url given: find the exact-matching asset.
    - Neither present: return (None, None). Does NOT guess.
    """
    asset_id = task.input_context.get("asset_id")
    base_url = task.input_context.get("base_url")

    if asset_id and base_url:
        return asset_id, base_url

    if asset_id and not base_url:
        asset = state.assets.get(asset_id)
        if asset is not None and asset.base_url:
            return asset_id, asset.base_url

    if base_url and not asset_id:
        for asset in state.assets.values():
            if asset.base_url == base_url:
                return asset.asset_id, base_url

    return asset_id, base_url


def infer_host_context(
    task: Task,
    state: GlobalState,
) -> tuple[str | None, str | None]:
    """Resolve (asset_id, hostname) from task context and state.

    Only performs deterministic lookups. Does NOT iterate all assets
    as a wildcard fallback when both fields are missing.
    """
    asset_id = task.input_context.get("asset_id")
    hostname = task.input_context.get("hostname")

    if asset_id and hostname:
        return asset_id, hostname

    if asset_id and not hostname:
        asset = state.assets.get(asset_id)
        if asset is not None and asset.hostname:
            return asset_id, asset.hostname

    if hostname and not asset_id:
        for asset in state.assets.values():
            if asset.hostname == hostname:
                return asset.asset_id, hostname

    return asset_id, hostname
