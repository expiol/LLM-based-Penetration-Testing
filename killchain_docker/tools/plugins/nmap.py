"""nmap — port scanning and service detection.

Supports:
  - Service version detection (-sV), OS detection, script scanning
  - Rich output parsing: open ports, services, OS, hostnames
  - Typed state signals: Asset, Endpoint per open port, NetworkEdge
"""

from __future__ import annotations
import re
from typing import Any
from killchain_docker.state.domain import (
    Asset,
    AssetKind,
    Endpoint,
    NetworkEdge,
    Service,
)
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)

_PORT_RE = re.compile("(\\d+)/(\\w+)\\s+open\\s+(\\S+)(?:\\s+(.*))?")
_OS_RE = re.compile("OS details?:\\s*(.+)", re.IGNORECASE)
_HOSTNAME_RE = re.compile(
    "Nmap scan report for\\s+(\\S+?)(?:\\s+\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\))?$",
    re.MULTILINE,
)
_MAC_RE = re.compile("MAC Address:\\s*([0-9A-Fa-f:]+)(?:\\s+\\((.+?)\\))?")
_HOST_TIMEOUT_RE = re.compile(
    "(?:skipping host .+? due to host timeout|host timeout)", re.IGNORECASE
)
_DEFAULT_HOST_TIMEOUT_CAP_S = 45
_DEFAULT_NMAP_TIMEOUT_SLACK_S = 15


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
        timeout_s = request.timeout_s
        timing_args, bounded_timeout = _default_timing_args(
            scan_type=scan_type, extra=extra, timeout_s=request.timeout_s
        )
        if timing_args:
            cmd += f" {timing_args}"
            timeout_s = bounded_timeout
        if ports:
            cmd += f" -p {ports}"
        if extra:
            cmd += f" {extra}"
        cmd += f" {target}"
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], timeout_s)


def _default_timing_args(
    *, scan_type: str, extra: str, timeout_s: int
) -> tuple[str, int]:
    existing = f"{scan_type} {extra}".lower()
    if "--host-timeout" in existing or "--max-retries" in existing:
        return ("", timeout_s)
    host_timeout = max(5, min(_DEFAULT_HOST_TIMEOUT_CAP_S, max(1, timeout_s - 5)))
    bounded_timeout = min(timeout_s, host_timeout + _DEFAULT_NMAP_TIMEOUT_SLACK_S)
    return (f"--host-timeout {host_timeout}s --max-retries 1", bounded_timeout)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    target = str(request.metadata.get("target") or "")
    requested_ports = str(request.metadata.get("ports") or "").strip()
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = "\n".join((part for part in (stdout, stderr) if part))
    status = _status(result)
    timeout_signal = _HOST_TIMEOUT_RE.search(combined) is not None
    if timeout_signal:
        status = ToolOutputStatus.FAILURE
    services: list[Service] = []
    open_ports: list[dict[str, Any]] = []
    for m in _PORT_RE.finditer(stdout):
        port = int(m.group(1))
        proto = m.group(2)
        svc = m.group(3)
        ver = (m.group(4) or "").strip()
        product, version = ("", ver)
        if ver and " " in ver:
            parts = ver.split(" ", 1)
            product, version = (parts[0], parts[1])
        services.append(
            Service(
                port=port,
                protocol=proto,
                name=svc,
                product=product or None,
                version=version or None,
            )
        )
        open_ports.append(
            {"port": port, "protocol": proto, "service": svc, "version": ver}
        )
    hostname: str | None = None
    ip_address: str | None = None
    m = _HOSTNAME_RE.search(stdout)
    if m:
        host_or_ip = m.group(1)
        resolved_ip = m.group(2)
        if resolved_ip:
            hostname = host_or_ip
            ip_address = resolved_ip
        elif re.match("\\d+\\.\\d+\\.\\d+\\.\\d+", host_or_ip):
            ip_address = host_or_ip
        else:
            hostname = host_or_ip
    os_info = ""
    m = _OS_RE.search(stdout)
    if m:
        os_info = m.group(1).strip()
    mac_address = ""
    mac_vendor = ""
    m = _MAC_RE.search(stdout)
    if m:
        mac_address = m.group(1)
        mac_vendor = (m.group(2) or "").strip()
    filtered_count = stdout.lower().count("filtered")
    assets: list[Asset] = []
    if services:
        asset_meta: dict[str, Any] = {}
        if os_info:
            asset_meta["os"] = os_info
        if mac_address:
            asset_meta["mac_address"] = mac_address
        if mac_vendor:
            asset_meta["mac_vendor"] = mac_vendor
        web_ports = {
            s.port for s in services if s.name in ("http", "https", "http-proxy")
        }
        kind = AssetKind.WEB_APPLICATION if web_ports else AssetKind.HOST
        assets.append(
            Asset(
                asset_id=f"nmap-{target}",
                kind=kind,
                hostname=hostname or target,
                ip_address=ip_address,
                services=services,
                tags={"nmap"},
                metadata=asset_meta,
            )
        )
    endpoints: list[Endpoint] = []
    for svc in services:
        host = hostname or ip_address or target
        if svc.name in ("http", "https", "http-proxy"):
            scheme = "https" if svc.name == "https" or svc.port == 443 else "http"
            port_suffix = (
                ""
                if scheme == "http"
                and svc.port == 80
                or (scheme == "https" and svc.port == 443)
                else f":{svc.port}"
            )
            ep_url = f"{scheme}://{host}{port_suffix}"
            endpoints.append(
                Endpoint(
                    url=ep_url,
                    hostname=hostname or host,
                    port=svc.port,
                    protocol=scheme,
                    metadata={
                        "service": svc.name,
                        "product": svc.product,
                        "version": svc.version,
                    },
                )
            )
        else:
            endpoints.append(
                Endpoint(
                    hostname=hostname or host,
                    port=svc.port,
                    protocol=svc.protocol,
                    metadata={
                        "service": svc.name,
                        "product": svc.product,
                        "version": svc.version,
                    },
                )
            )
    network_edges: list[NetworkEdge] = []
    if ip_address and hostname and (hostname != ip_address):
        network_edges.append(
            NetworkEdge(source=hostname, target=ip_address, relationship="resolves_to")
        )
    flags = _flag_candidates_from(combined, source="nmap")
    summary = f"nmap {target}: {len(open_ports)} open port(s)"
    if os_info:
        summary += f" [{os_info[:60]}]"
    if filtered_count > 5:
        summary += f", {filtered_count} filtered"
    if timeout_signal:
        summary = f"nmap {target} timed out before completing scan"
    if status.value == "failure":
        if timeout_signal:
            summary = f"nmap {target} timed out before completing scan"
        else:
            summary = f"nmap {target} failed (exit {result.exit_code})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "target": target,
        "open_ports": open_ports,
        "port_count": len(open_ports),
    }
    if requested_ports:
        output_context["requested_ports"] = requested_ports
    if hostname:
        output_context["hostname"] = hostname
    if ip_address:
        output_context["ip_address"] = ip_address
    if os_info:
        output_context["os"] = os_info
    if mac_address:
        output_context["mac_address"] = mac_address
    if timeout_signal:
        output_context["failure_kind"] = "scan_timeout"
        output_context["failure_detail"] = (
            "nmap reported that the host scan exceeded its host timeout"
        )
        output_context["result_quality"] = "scan_incomplete"
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(combined, 4000),
        raw_log=_truncate(combined, 6000),
        output_context=output_context,
        flag_candidates=flags,
        assets=assets,
        endpoints=endpoints,
        network_edges=network_edges,
    )
