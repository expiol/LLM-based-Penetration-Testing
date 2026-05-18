"""Tool plugins — each file contains a plugin class + build_output function."""

from killchain_docker.tools.plugins.shell import ShellPlugin
from killchain_docker.tools.plugins.script import ScriptPlugin
from killchain_docker.tools.plugins.nmap import NmapPlugin
from killchain_docker.tools.plugins.curl import CurlPlugin
from killchain_docker.tools.plugins.sqlmap import SqlmapPlugin
from killchain_docker.tools.plugins.nikto import NiktoPlugin
from killchain_docker.tools.plugins.file_cmd import FilePlugin
from killchain_docker.tools.plugins.strings_cmd import StringsPlugin
from killchain_docker.tools.plugins.binwalk import BinwalkPlugin
from killchain_docker.tools.plugins.radare2 import RadarePlugin
from killchain_docker.tools.plugins.objdump import ObjdumpPlugin
from killchain_docker.tools.plugins.gdb import GdbPlugin
from killchain_docker.tools.plugins.tshark import TsharkPlugin
from killchain_docker.tools.plugins.exiftool import ExiftoolPlugin
from killchain_docker.tools.plugins.steghide import SteghidePlugin
from killchain_docker.tools.plugins.foremost import ForemostPlugin
from killchain_docker.tools.plugins.sqlite3_cmd import Sqlite3Plugin
from killchain_docker.tools.plugins.john import JohnPlugin
from killchain_docker.tools.plugins.fcrackzip import FcrackzipPlugin
from killchain_docker.tools.plugins.jadx import JadxPlugin
from killchain_docker.tools.plugins.checksec import ChecksecPlugin
from killchain_docker.tools.plugins.ltrace import LtracePlugin
from killchain_docker.tools.plugins.strace import StracePlugin

from killchain_docker.tools.plugins import (
    shell, script, nmap, curl, sqlmap, nikto, file_cmd, strings_cmd,
    binwalk, radare2, objdump, gdb, tshark, exiftool, steghide,
    foremost, sqlite3_cmd, john, fcrackzip, jadx,
    checksec, ltrace, strace,
)

# Ordered list of (PluginClass, build_output_function) for registry
ALL_PLUGINS = [
    (ShellPlugin, shell.build_output),
    (ScriptPlugin, script.build_output),
    (NmapPlugin, nmap.build_output),
    (CurlPlugin, curl.build_output),
    (SqlmapPlugin, sqlmap.build_output),
    (NiktoPlugin, nikto.build_output),
    (FilePlugin, file_cmd.build_output),
    (StringsPlugin, strings_cmd.build_output),
    (BinwalkPlugin, binwalk.build_output),
    (RadarePlugin, radare2.build_output),
    (ObjdumpPlugin, objdump.build_output),
    (GdbPlugin, gdb.build_output),
    (TsharkPlugin, tshark.build_output),
    (ExiftoolPlugin, exiftool.build_output),
    (SteghidePlugin, steghide.build_output),
    (ForemostPlugin, foremost.build_output),
    (Sqlite3Plugin, sqlite3_cmd.build_output),
    (JohnPlugin, john.build_output),
    (FcrackzipPlugin, fcrackzip.build_output),
    (JadxPlugin, jadx.build_output),
    (ChecksecPlugin, checksec.build_output),
    (LtracePlugin, ltrace.build_output),
    (StracePlugin, strace.build_output),
]

__all__ = [
    "ALL_PLUGINS",
    "BinwalkPlugin", "ChecksecPlugin", "CurlPlugin", "ExiftoolPlugin",
    "FcrackzipPlugin", "FilePlugin", "ForemostPlugin", "GdbPlugin",
    "JadxPlugin", "JohnPlugin", "LtracePlugin",
    "NiktoPlugin", "NmapPlugin", "ObjdumpPlugin", "RadarePlugin",
    "ScriptPlugin", "ShellPlugin", "SqlmapPlugin", "Sqlite3Plugin",
    "SteghidePlugin", "StracePlugin", "StringsPlugin", "TsharkPlugin",
]
