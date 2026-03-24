"""Vulnerability scanning tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "vuln_scan"

SCRIPT = r"""
import json
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
target = payload.get("target") or payload.get("base_url") or payload.get("hostname", asset_id)
base_url = payload.get("base_url")
timeout_s = int(payload.get("timeout_s", 120))

records = []
findings = []
notes_list = []
scan_method = "none"
vuln_count = 0

parsed_url = urlparse(target) if target.startswith(("http://", "https://")) else None
is_web_target = parsed_url is not None and parsed_url.scheme in {"http", "https"}

nuclei_bin = shutil.which("nuclei")
if nuclei_bin and is_web_target:
    scan_method = "nuclei"
    try:
        result = subprocess.run(
            [nuclei_bin, "-u", target, "-jsonl", "-silent",
             "-severity", "low,medium,high,critical",
             "-timeout", str(max(5, timeout_s // 10))],
            capture_output=True, text=True, timeout=timeout_s, check=False,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            info = item.get("info", {})
            sev = (info.get("severity") or "info").lower()
            name = info.get("name", item.get("template-id", "nuclei-finding"))
            matched_at = item.get("matched-at", target)
            description = info.get("description", f"Nuclei matched template {item.get('template-id', '')} at {matched_at}.")
            finding_id = f"finding-{asset_id}-nuclei-{vuln_count}"
            vuln_count += 1
            findings.append({
                "type": "finding",
                "finding_id": finding_id,
                "title": name,
                "severity": sev if sev in {"info", "low", "medium", "high", "critical"} else "medium",
                "description": description,
                "asset_refs": [asset_id],
                "evidence_refs": [matched_at],
                "metadata": {
                    "source": "nuclei",
                    "template_id": item.get("template-id"),
                    "template": item.get("template"),
                    "matched_at": matched_at,
                    "curl_command": item.get("curl-command"),
                },
            })
        if result.returncode not in {0, 1}:
            notes_list.append(f"nuclei exited with code {result.returncode}")
        if result.stderr:
            for err_line in result.stderr.splitlines()[:5]:
                if err_line.strip():
                    notes_list.append(f"nuclei: {err_line.strip()}")
    except subprocess.TimeoutExpired:
        notes_list.append(f"nuclei timed out after {timeout_s}s")
    except Exception as exc:
        notes_list.append(f"nuclei error ({type(exc).__name__}): {exc}")
elif not nuclei_bin:
    notes_list.append("nuclei not found in PATH")

nikto_bin = shutil.which("nikto")
if nikto_bin and is_web_target and scan_method != "nuclei":
    scan_method = "nikto"
    try:
        result = subprocess.run(
            [nikto_bin, "-h", target, "-Format", "json", "-output", "/dev/stdout", "-nointeractive"],
            capture_output=True, text=True, timeout=timeout_s, check=False,
        )
        try:
            nikto_data = json.loads(result.stdout)
            for vuln in (nikto_data.get("vulnerabilities") or []):
                sev = "medium"
                if vuln.get("OSVDB") and vuln["OSVDB"] != "0":
                    sev = "medium"
                finding_id = f"finding-{asset_id}-nikto-{vuln_count}"
                vuln_count += 1
                findings.append({
                    "type": "finding",
                    "finding_id": finding_id,
                    "title": vuln.get("msg", "nikto finding"),
                    "severity": sev,
                    "description": vuln.get("msg", ""),
                    "asset_refs": [asset_id],
                    "evidence_refs": [vuln.get("url", target)],
                    "metadata": {"source": "nikto", "osvdb": vuln.get("OSVDB")},
                })
        except json.JSONDecodeError:
            for line in result.stdout.splitlines():
                if line.strip().startswith("+"):
                    finding_id = f"finding-{asset_id}-nikto-{vuln_count}"
                    vuln_count += 1
                    msg = line.strip().lstrip("+ ")
                    findings.append({
                        "type": "finding",
                        "finding_id": finding_id,
                        "title": msg[:80],
                        "severity": "medium",
                        "description": msg,
                        "asset_refs": [asset_id],
                        "evidence_refs": [target],
                        "metadata": {"source": "nikto"},
                    })
    except subprocess.TimeoutExpired:
        notes_list.append(f"nikto timed out after {timeout_s}s")
    except Exception as exc:
        notes_list.append(f"nikto error ({type(exc).__name__}): {exc}")

if scan_method == "none" and is_web_target:
    scan_method = "http_basic"
    ctx = None
    if parsed_url.scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    check_paths = [
        ("/.git/config", "Git repository exposed"),
        ("/.env", ".env file exposed"),
        ("/wp-login.php", "WordPress admin login exposed"),
        ("/admin", "Admin interface potentially exposed"),
        ("/phpmyadmin", "phpMyAdmin potentially exposed"),
        ("/manager/html", "Tomcat manager potentially exposed"),
        ("/.DS_Store", "macOS .DS_Store file exposed"),
        ("/server-status", "Apache server-status potentially exposed"),
        ("/actuator/env", "Spring Boot actuator env endpoint potentially exposed"),
        ("/api/swagger.json", "Swagger API docs potentially exposed"),
        ("/api/openapi.json", "OpenAPI spec potentially exposed"),
    ]
    base = base_url or target
    for path, title in check_paths:
        probe_url = base.rstrip("/") + path
        try:
            req = urllib.request.Request(
                probe_url,
                headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)"},
            )
            open_args = {"timeout": 5}
            if ctx is not None:
                open_args["context"] = ctx
            with urllib.request.urlopen(req, **open_args) as resp:
                if resp.status in {200, 206}:
                    finding_id = f"finding-{asset_id}-exposed-{vuln_count}"
                    vuln_count += 1
                    findings.append({
                        "type": "finding",
                        "finding_id": finding_id,
                        "title": title,
                        "severity": "high",
                        "description": f"{title} at {probe_url} (HTTP {resp.status}).",
                        "asset_refs": [asset_id],
                        "evidence_refs": [probe_url],
                        "metadata": {"source": "http_basic_check", "probe_url": probe_url},
                    })
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                notes_list.append(f"{path} returned {exc.code} (access controlled)")
        except Exception as exc:
            notes_list.append(f"Probe {path} failed: {type(exc).__name__}: {exc}")

sev_count = {s: sum(1 for f in findings if f.get("severity") == s) for s in ("critical", "high", "medium", "low")}
summary_parts = [f"{v} {k}" for k, v in sev_count.items() if v]
summary_text = (
    f"Vuln scan for {target} via {scan_method}: "
    + (", ".join(summary_parts) if summary_parts else "no issues found")
    + f" ({vuln_count} finding(s) total)."
)

records.append({"type": "summary", "text": summary_text})
records.extend(findings)
for note in notes_list:
    records.append({"type": "note", "text": note})
records.append({
    "type": "output_context",
    "scan_method": scan_method,
    "vuln_count": vuln_count,
    "scanned_target": target,
    "severity_counts": sev_count,
    "manual_checks": [
        f"Manually verify all {vuln_count} finding(s) before exploitation",
        f"Review scan coverage — {scan_method} may not cover all attack vectors",
        "Prioritize critical and high findings for exploitation attempts",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "target": request.metadata.get("target"),
        "base_url": request.metadata.get("base_url"),
        "hostname": request.metadata.get("hostname"),
        "timeout_s": request.timeout_s,
    }
    if not payload["target"]:
        raise ToolExecutionError("vuln_scan requires metadata.target")
    return ["-c", SCRIPT, json.dumps(payload)]
