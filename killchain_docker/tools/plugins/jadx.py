"""jadx — Android APK/DEX decompilation.

Supports:
  - Full APK and DEX decompilation to Java source
  - Rich output parsing: class/activity detection, manifest info, hardcoded secrets
  - Typed state signals: Artifact per decompiled source file
"""

from __future__ import annotations
import re
from typing import Any
from killchain_docker.state.domain import Artifact, Credential
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)

_ACTIVITY_RE = re.compile("Activity\\.java$", re.IGNORECASE)
_SERVICE_RE = re.compile("Service\\.java$", re.IGNORECASE)
_RECEIVER_RE = re.compile("Receiver\\.java$", re.IGNORECASE)
_PROVIDER_RE = re.compile("Provider\\.java$", re.IGNORECASE)


class JadxPlugin:
    name = "jadx"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        output_dir = str(request.metadata.get("output_dir") or "/tmp/jadx_out")
        cmd = f"jadx -d {output_dir} {path} 2>&1 && find {output_dir} -name '*.java' -o -name '*.xml' | head -80 && echo '---MANIFEST---' && cat {output_dir}/resources/AndroidManifest.xml 2>/dev/null | head -60 || true"
        return _run(
            self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    output_dir = str(request.metadata.get("output_dir") or "/tmp/jadx_out")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    java_files: list[str] = []
    xml_files: list[str] = []
    for line in stdout.splitlines():
        line_s = line.strip()
        if line_s.endswith(".java"):
            java_files.append(line_s)
        elif line_s.endswith(".xml") and (not line_s.startswith("---")):
            xml_files.append(line_s)
    activities: list[str] = [f for f in java_files if _ACTIVITY_RE.search(f)]
    services: list[str] = [f for f in java_files if _SERVICE_RE.search(f)]
    receivers: list[str] = [f for f in java_files if _RECEIVER_RE.search(f)]
    providers: list[str] = [f for f in java_files if _PROVIDER_RE.search(f)]
    manifest_text = ""
    in_manifest = False
    for line in stdout.splitlines():
        if "---MANIFEST---" in line:
            in_manifest = True
            continue
        if in_manifest:
            manifest_text += line + "\n"
    package_name = ""
    m = re.search('package="([^"]+)"', manifest_text)
    if m:
        package_name = m.group(1)
    permissions: list[str] = re.findall(
        'android:name="([^"]*permission[^"]*)"', manifest_text, re.IGNORECASE
    )
    artifacts: list[Artifact] = []
    for fpath in java_files[:30]:
        kind = "java_source"
        if _ACTIVITY_RE.search(fpath):
            kind = "android_activity"
        elif _SERVICE_RE.search(fpath):
            kind = "android_service"
        artifacts.append(
            Artifact(path=fpath, kind=kind, source="jadx", metadata={"apk": path})
        )
    flags = _flag_candidates_from(stdout, source="jadx")
    credentials: list[Credential] = []
    for m in re.finditer(
        '(?:api[_-]?key|secret|token|password)\\s*[=:]\\s*"([^"]{8,})"',
        stdout,
        re.IGNORECASE,
    ):
        credentials.append(
            Credential(
                credential_id=f"jadx-{m.group(1)[:20]}",
                username="(hardcoded)",
                secret_ref=f"jadx:{m.group(1)}",
                credential_type="hardcoded",
                source="jadx",
                metadata={"apk": path},
            )
        )
    summary = f"jadx {path}: {len(java_files)} Java source(s)"
    if xml_files:
        summary += f", {len(xml_files)} XML(s)"
    parts: list[str] = []
    if activities:
        parts.append(f"{len(activities)} activity")
    if services:
        parts.append(f"{len(services)} service")
    if parts:
        summary += f" ({', '.join(parts)})"
    if package_name:
        summary += f" [{package_name}]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "java_file_count": len(java_files),
        "xml_file_count": len(xml_files),
        "java_files": java_files[:50],
    }
    if activities:
        output_context["activities"] = activities[:20]
    if services:
        output_context["services"] = services[:10]
    if package_name:
        output_context["package_name"] = package_name
    if permissions:
        output_context["permissions"] = permissions[:20]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
        credentials=credentials,
    )
