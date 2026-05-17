"""nmap — port scanning and service detection.

Supports:
  - Service version detection (-sV), OS detection, script scanning
  - Rich output parsing: open ports, services, OS, hostnames
  - Typed state signals: Asset, Endpoint per open port, NetworkEdge
"""

from __future__ import annotations

import re
from typing import Any

from killchain_docker.state import Asset, AssetKind, Endpoint, NetworkEdge, Service
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
    _truncate,
)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?")
_OS_RE = re.compile(r"OS details?:\s*(.+)", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"Nmap scan report for\s+(\S+?)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?$", re.MULTILINE)
_MAC_RE = re.compile(r"MAC Address:\s*([0-9A-Fa-f:]+)(?:\s+\((.+?)\))?")


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class NmapPlugin:
    name = "nmap"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        target = _require(request.metadata, "target", self.name)
        ports = str(request.metadata.get("ports") or "")
        scan_type = str(request.metadata.get("scan_type") or "-sV")
        extra = str(request.metadata.get("extra_args") or "")
        cmd = f"nmap {scan_type}"
        if ports:
            cmd += f" -p {ports}"
        if extra:
            cmd += f" {extra}"
        cmd += f" {target}"
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s)


# ---------------------------------------------------------------------------
# Output builder
# ---------------------------------------------------------------------------

def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    target = str(request.metadata.get("target") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)

    # -- Parse open ports and services --------------------------------------
    services: list[Service] = []
    open_ports: list[dict[str, Any]] = []
    for m in _PORT_RE.finditer(stdout):
        port = int(m.group(1))
        proto = m.group(2)
        svc = m.group(3)
        ver = (m.group(4) or "").strip()
        # Split version into product/version when possible
        product, version = "", ver
        if ver and " " in ver:
            parts = ver.split(" ", 1)
            product, version = parts[0], parts[1]
        services.append(Service(
            port=port, protocol=proto, name=svc,
            product=product or None, version=version or None,
        ))
        open_ports.append({
            "port": port, "protocol": proto, "service": svc, "version": ver,
        })

    # -- Parse hostname / IP -------------------------------------------------
    hostname: str | None = None
    ip_address: str | None = None
    m = _HOSTNAME_RE.search(stdout)
    if m:
        host_or_ip = m.group(1)
        resolved_ip = m.group(2)
        if resolved_ip:
            hostname = host_or_ip
            ip_address = resolved_ip
        elif re.match(r"\d+\.\d+\.\d+\.\d+", host_or_ip):
            ip_address = host_or_ip
        else:
            hostname = host_or_ip

    # -- Parse OS detection --------------------------------------------------
    os_info = ""
    m = _OS_RE.search(stdout)
    if m:
        os_info = m.group(1).strip()

    # -- Parse MAC address ---------------------------------------------------
    mac_address = ""
    mac_vendor = ""
    m = _MAC_RE.search(stdout)
    if m:
        mac_address = m.group(1)
        mac_vendor = (m.group(2) or "").strip()

    # -- Detect filtered/closed counts for summary --------------------------
    filtered_count = stdout.lower().count("filtered")

    # -- Assets --------------------------------------------------------------
    assets: list[Asset] = []
    if services:
        asset_meta: dict[str, Any] = {}
        if os_info:
            asset_meta["os"] = os_info
        if mac_address:
            asset_meta["mac_address"] = mac_address
        if mac_vendor:
            asset_meta["mac_vendor"] = mac_vendor

        # Detect if this looks like a web application
        web_ports = {s.port for s in services if s.name in ("http", "https", "http-proxy")}
        kind = AssetKind.WEB_APPLICATION if web_ports else AssetKind.HOST

        assets.append(Asset(
            asset_id=f"nmap-{target}",
            kind=kind,
            hostname=hostname or target,
            ip_address=ip_address,
            services=services,
            tags={"nmap"},
            metadata=asset_meta,
        ))

    # -- Endpoints (one per open port) ---------------------------------------
    endpoints: list[Endpoint] = []
    for svc in services:
        host = hostname or ip_address or target
        if svc.name in ("http", "https", "http-proxy"):
            scheme = "https" if svc.name == "https" or svc.port == 443 else "http"
            port_suffix = "" if (scheme == "http" and svc.port == 80) or (scheme == "https" and svc.port == 443) else f":{svc.port}"
            ep_url = f"{scheme}://{host}{port_suffix}"
            endpoints.append(Endpoint(
                url=ep_url,
                hostname=hostname or host,
                port=svc.port,
                protocol=scheme,
                metadata={"service": svc.name, "product": svc.product, "version": svc.version},
            ))
        else:
            endpoints.append(Endpoint(
                hostname=hostname or host,
                port=svc.port,
                protocol=svc.protocol,
                metadata={"service": svc.name, "product": svc.product, "version": svc.version},
            ))

    # -- Network edges -------------------------------------------------------
    network_edges: list[NetworkEdge] = []
    if ip_address and hostname and hostname != ip_address:
        network_edges.append(NetworkEdge(
            source=hostname,
            target=ip_address,
            relationship="resolves_to",
        ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="nmap")

    # -- Summary -------------------------------------------------------------
    summary = f"nmap {target}: {len(open_ports)} open port(s)"
    if os_info:
        summary += f" [{os_info[:60]}]"
    if filtered_count > 5:
        summary += f", {filtered_count} filtered"
    if status.value == "failure":
        summary = f"nmap {target} failed (exit {result.exit_code})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "target": target,
        "open_ports": open_ports,
        "port_count": len(open_ports),
    }
    if hostname:
        output_context["hostname"] = hostname
    if ip_address:
        output_context["ip_address"] = ip_address
    if os_info:
        output_context["os"] = os_info
    if mac_address:
        output_context["mac_address"] = mac_address

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        assets=assets,
        endpoints=endpoints,
        network_edges=network_edges,
    )
