"""Execution-plane factory — registers all plugins."""

from __future__ import annotations

from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.tools.plugins.artifact_triage import ArtifactTriagePlugin
from killchain_docker.tools.plugins.artifact_triage import (
    build_output as build_artifact_triage_output,
)
from killchain_docker.tools.plugins.binwalk import BinwalkPlugin
from killchain_docker.tools.plugins.binwalk import build_output as build_binwalk_output
from killchain_docker.tools.plugins.checksec import ChecksecPlugin
from killchain_docker.tools.plugins.checksec import (
    build_output as build_checksec_output,
)
from killchain_docker.tools.plugins.curl import CurlPlugin
from killchain_docker.tools.plugins.curl import build_output as build_curl_output
from killchain_docker.tools.plugins.disk_extract import DiskExtractPlugin
from killchain_docker.tools.plugins.disk_extract import (
    build_output as build_disk_extract_output,
)
from killchain_docker.tools.plugins.exiftool import ExiftoolPlugin
from killchain_docker.tools.plugins.exiftool import (
    build_output as build_exiftool_output,
)
from killchain_docker.tools.plugins.fcrackzip import FcrackzipPlugin
from killchain_docker.tools.plugins.fcrackzip import (
    build_output as build_fcrackzip_output,
)
from killchain_docker.tools.plugins.file_cmd import FilePlugin
from killchain_docker.tools.plugins.file_cmd import build_output as build_file_output
from killchain_docker.tools.plugins.foremost import ForemostPlugin
from killchain_docker.tools.plugins.foremost import (
    build_output as build_foremost_output,
)
from killchain_docker.tools.plugins.gdb import GdbPlugin
from killchain_docker.tools.plugins.gdb import build_output as build_gdb_output
from killchain_docker.tools.plugins.jadx import JadxPlugin
from killchain_docker.tools.plugins.jadx import build_output as build_jadx_output
from killchain_docker.tools.plugins.john import JohnPlugin
from killchain_docker.tools.plugins.john import build_output as build_john_output
from killchain_docker.tools.plugins.ltrace import LtracePlugin
from killchain_docker.tools.plugins.ltrace import build_output as build_ltrace_output
from killchain_docker.tools.plugins.media_scan import MediaScanPlugin
from killchain_docker.tools.plugins.media_scan import (
    build_output as build_media_scan_output,
)
from killchain_docker.tools.plugins.nikto import NiktoPlugin
from killchain_docker.tools.plugins.nikto import build_output as build_nikto_output
from killchain_docker.tools.plugins.nmap import NmapPlugin
from killchain_docker.tools.plugins.nmap import build_output as build_nmap_output
from killchain_docker.tools.plugins.objdump import ObjdumpPlugin
from killchain_docker.tools.plugins.objdump import build_output as build_objdump_output
from killchain_docker.tools.plugins.office_inspect import OfficeInspectPlugin
from killchain_docker.tools.plugins.office_inspect import (
    build_output as build_office_inspect_output,
)
from killchain_docker.tools.plugins.png_inspect import PngInspectPlugin
from killchain_docker.tools.plugins.png_inspect import (
    build_output as build_png_inspect_output,
)
from killchain_docker.tools.plugins.radare2 import RadarePlugin
from killchain_docker.tools.plugins.radare2 import build_output as build_radare2_output
from killchain_docker.tools.plugins.script import ScriptPlugin
from killchain_docker.tools.plugins.script import build_output as build_script_output
from killchain_docker.tools.plugins.shell import ShellPlugin
from killchain_docker.tools.plugins.shell_output import (
    build_output as build_shell_output,
)
from killchain_docker.tools.plugins.sqlmap import SqlmapPlugin
from killchain_docker.tools.plugins.sqlmap import build_output as build_sqlmap_output
from killchain_docker.tools.plugins.sqlite3_cmd import Sqlite3Plugin
from killchain_docker.tools.plugins.sqlite3_cmd import (
    build_output as build_sqlite3_output,
)
from killchain_docker.tools.plugins.steghide import SteghidePlugin
from killchain_docker.tools.plugins.steghide import (
    build_output as build_steghide_output,
)
from killchain_docker.tools.plugins.strace import StracePlugin
from killchain_docker.tools.plugins.strace import build_output as build_strace_output
from killchain_docker.tools.plugins.strings_cmd import StringsPlugin
from killchain_docker.tools.plugins.strings_cmd import (
    build_output as build_strings_output,
)
from killchain_docker.tools.plugins.tshark import TsharkPlugin
from killchain_docker.tools.plugins.tshark import build_output as build_tshark_output


DEFAULT_PLUGIN_FACTORIES = [
    (ShellPlugin, build_shell_output),
    (ScriptPlugin, build_script_output),
    (NmapPlugin, build_nmap_output),
    (CurlPlugin, build_curl_output),
    (SqlmapPlugin, build_sqlmap_output),
    (NiktoPlugin, build_nikto_output),
    (ArtifactTriagePlugin, build_artifact_triage_output),
    (DiskExtractPlugin, build_disk_extract_output),
    (OfficeInspectPlugin, build_office_inspect_output),
    (MediaScanPlugin, build_media_scan_output),
    (PngInspectPlugin, build_png_inspect_output),
    (FilePlugin, build_file_output),
    (StringsPlugin, build_strings_output),
    (BinwalkPlugin, build_binwalk_output),
    (RadarePlugin, build_radare2_output),
    (ObjdumpPlugin, build_objdump_output),
    (GdbPlugin, build_gdb_output),
    (TsharkPlugin, build_tshark_output),
    (ExiftoolPlugin, build_exiftool_output),
    (SteghidePlugin, build_steghide_output),
    (ForemostPlugin, build_foremost_output),
    (Sqlite3Plugin, build_sqlite3_output),
    (JohnPlugin, build_john_output),
    (FcrackzipPlugin, build_fcrackzip_output),
    (JadxPlugin, build_jadx_output),
    (ChecksecPlugin, build_checksec_output),
    (LtracePlugin, build_ltrace_output),
    (StracePlugin, build_strace_output),
]


def build_execution_plane(
    *,
    argv_prefix: list[str] | None = None,
    python_executable: str | None = None,
) -> ExecutionPlane:
    """Create the default execution plane with all plugins registered.

    Parameters
    ----------
    argv_prefix:
        Command prefix prepended to every subprocess invocation (e.g.
        ``["docker", "exec", "<container>"]``).
    python_executable:
        Override the Python interpreter used by :class:`ScriptPlugin`
        (default ``"python3"``).  Useful when the target container ships
        a non-standard interpreter name.
    """
    plane = ExecutionPlane()
    prefix = list(argv_prefix or [])
    for plugin_cls, output_builder in DEFAULT_PLUGIN_FACTORIES:
        kwargs: dict[str, object] = {"argv_prefix": prefix}
        if python_executable and hasattr(plugin_cls, "python_executable"):
            kwargs["python_executable"] = python_executable
        plane.register(plugin_cls(**kwargs), output_builder)
    return plane
