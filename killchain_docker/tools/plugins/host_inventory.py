"""Host audit and service inventory tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "local_host_inventory"

SCRIPT = r"""
import json
import shutil
import socket
import subprocess
import sys
from xml.etree import ElementTree

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "host-asset")
hostname = payload.get("hostname") or asset_id
timeout_s = int(payload.get("timeout_s", 60))
default_scan_ports = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,"
    "3306,3389,5432,5900,8080,8443,8888,9200,27017"
)
raw_scan_ports = payload.get("ports")
if isinstance(raw_scan_ports, list):
    normalized_ports = [str(int(port)) for port in raw_scan_ports if str(port).strip().isdigit()]
    scan_ports = ",".join(normalized_ports) if normalized_ports else default_scan_ports
elif isinstance(raw_scan_ports, str) and raw_scan_ports.strip():
    scan_ports = raw_scan_ports.strip()
else:
    scan_ports = default_scan_ports

records = []
services = []
open_ports = []
notes_list = []
scan_method = "none"

ip_address = None
try:
    ip_address = socket.gethostbyname(hostname)
except socket.gaierror as exc:
    notes_list.append(f"DNS resolution failed for {hostname}: {exc}")

target = ip_address or hostname
nmap_bin = shutil.which("nmap")

if nmap_bin:
    scan_method = "nmap"
    try:
        result = subprocess.run(
            [
                nmap_bin, "-sV", "--version-intensity", "3", "-T4",
                "-p", scan_ports, "--open", "-oX", "-", target,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                root = ElementTree.fromstring(result.stdout)
                for host_elem in root.findall("host"):
                    status_elem = host_elem.find("status")
                    if status_elem is not None and status_elem.get("state") != "up":
                        continue
                    addr_elem = host_elem.find("address[@addrtype='ipv4']")
                    if addr_elem is not None and addr_elem.get("addr"):
                        ip_address = addr_elem.get("addr", ip_address)
                    ports_elem = host_elem.find("ports")
                    if ports_elem is not None:
                        for port_elem in ports_elem.findall("port"):
                            state_elem = port_elem.find("state")
                            if state_elem is None or state_elem.get("state") != "open":
                                continue
                            portid = int(port_elem.get("portid", 0))
                            protocol = port_elem.get("protocol", "tcp")
                            svc_elem = port_elem.find("service")
                            svc_name = svc_elem.get("name") if svc_elem is not None else None
                            svc_product = svc_elem.get("product") if svc_elem is not None else None
                            svc_version = svc_elem.get("version") if svc_elem is not None else None
                            open_ports.append(portid)
                            services.append({
                                "port": portid,
                                "protocol": protocol,
                                "name": svc_name,
                                "product": svc_product,
                                "version": svc_version,
                            })
            except ElementTree.ParseError as exc:
                notes_list.append(f"nmap XML parse error: {exc}")
                scan_method = "socket"
        else:
            if result.stderr:
                notes_list.append(f"nmap error output: {result.stderr[:500]}")
            if result.returncode != 0:
                notes_list.append(f"nmap exited with code {result.returncode}; falling back to socket scan")
                scan_method = "socket"
    except subprocess.TimeoutExpired:
        notes_list.append(f"nmap timed out after {timeout_s}s; falling back to socket scan")
        scan_method = "socket"
    except Exception as exc:
        notes_list.append(f"nmap error ({type(exc).__name__}): {exc}; falling back to socket scan")
        scan_method = "socket"
else:
    notes_list.append("nmap not found in PATH; using socket TCP connect scan as fallback")
    scan_method = "socket"

if scan_method == "socket":
    port_list = [int(p.strip()) for p in scan_ports.split(",") if p.strip().isdigit()]
    sock_timeout = min(2.0, timeout_s / max(len(port_list), 1))
    for port in port_list:
        try:
            with socket.create_connection((target, port), timeout=sock_timeout):
                open_ports.append(port)
                services.append({
                    "port": port,
                    "protocol": "tcp",
                    "name": None,
                    "product": None,
                    "version": None,
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    notes_list.append(f"Socket scan on {target}: {len(open_ports)} open port(s) found")

high_risk = []
port_set = {s["port"] for s in services}
if port_set & {21, 23, 110, 143}:
    high_risk.append("unencrypted protocol exposed (FTP/Telnet/POP3/IMAP)")
if port_set & {139, 445}:
    high_risk.append("SMB/NetBIOS exposed — lateral movement risk")
if 3389 in port_set:
    high_risk.append("RDP (3389) exposed — brute-force and exploitation risk")
if port_set & {5900, 5901, 5902}:
    high_risk.append("VNC exposed — unauthenticated desktop access risk")
if 27017 in port_set:
    high_risk.append("MongoDB (27017) may be exposed without authentication")
if 9200 in port_set:
    high_risk.append("Elasticsearch (9200) may be exposed without authentication")
if 5432 in port_set:
    high_risk.append("PostgreSQL (5432) network-exposed")
if 3306 in port_set:
    high_risk.append("MySQL/MariaDB (3306) network-exposed")

severity = "high" if high_risk else ("medium" if open_ports else "info")
description = f"Host audit for {hostname} (resolved: {ip_address or 'unresolved'}) via {scan_method}. "
if open_ports:
    description += f"Open ports: {sorted(open_ports)}. "
else:
    description += "No open ports found in scanned range. "
if high_risk:
    description += "High-risk: " + "; ".join(high_risk) + "."

asset_rec = {
    "type": "asset",
    "asset_id": asset_id,
    "kind": "host",
    "hostname": hostname,
    "services": services,
    "tags": ["observed", f"tool:host_audit_{scan_method}"],
    "metadata": {
        "source": "host_audit_probe",
        "scan_method": scan_method,
        "open_ports": sorted(open_ports),
        "high_risk_services": high_risk,
    },
}
if ip_address:
    asset_rec["ip_address"] = ip_address

records.append({
    "type": "summary",
    "text": (
        f"Host audit for {hostname}: {len(open_ports)} open port(s), "
        f"{len(high_risk)} high-risk service(s) via {scan_method}."
    ),
})
records.append(asset_rec)
records.append({
    "type": "finding",
    "finding_id": f"finding-{asset_id}-host-audit",
    "title": (
        f"Host inventory: {len(open_ports)} open port(s)"
        + (" — high-risk services detected" if high_risk else "")
    ),
    "severity": severity,
    "description": description,
    "asset_refs": [asset_id],
    "metadata": {
        "source": "host_audit_probe",
        "scan_method": scan_method,
        "open_ports": sorted(open_ports),
        "high_risk_services": high_risk,
    },
})
for note in notes_list:
    records.append({"type": "note", "text": note})
for risk in high_risk:
    records.append({"type": "note", "text": f"High-risk service detected: {risk}"})

records.append({
    "type": "output_context",
    "audited_host": hostname,
    "ip_address": ip_address,
    "open_ports": sorted(open_ports),
    "services": services,
    "high_risk_services": high_risk,
    "scan_method": scan_method,
    "manual_checks": (
        [
            f"Verify all {len(open_ports)} open port(s) on {hostname} are intentionally exposed",
            "Test default credentials on all exposed services",
            "Review firewall rules for unnecessary service exposure",
        ]
        + [f"Investigate high-risk service: {r}" for r in high_risk]
    ),
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "hostname": request.metadata.get("hostname"),
        "timeout_s": request.timeout_s,
        "ports": request.metadata.get("ports"),
    }
    if not payload["hostname"] and not payload["asset_id"]:
        raise ToolExecutionError("local_host_inventory requires metadata.hostname or metadata.asset_id")
    return ["-c", SCRIPT, json.dumps(payload)]

def build_tool_output(request, result, parsed):
    from killchain_docker.tools.output_builder import base_output
    return base_output(request, result, parsed)
