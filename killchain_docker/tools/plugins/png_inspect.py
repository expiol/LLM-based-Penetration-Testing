"""png.inspect — deterministic PNG structure and LSB inspection."""

from __future__ import annotations

import re
import shlex
from typing import Any

from killchain_docker.state import FlagCandidate
from killchain_docker.state import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT, FLAG_PATTERN, plausible_flag
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _require,
    _run,
    _status,
    _truncate,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command


_PNG_MARKER = "__KILLCHAIN_PNG_INSPECT_PNG__"
_CHUNK_MARKER = "__KILLCHAIN_PNG_INSPECT_CHUNK__"
_TEXT_MARKER = "__KILLCHAIN_PNG_INSPECT_TEXT__"
_IDAT_MARKER = "__KILLCHAIN_PNG_INSPECT_IDAT__"
_LSB_MARKER = "__KILLCHAIN_PNG_INSPECT_LSB__"
_VISUAL_MARKER = "__KILLCHAIN_PNG_INSPECT_VISUAL__"
_ARTIFACT_MARKER = "__KILLCHAIN_PNG_INSPECT_ARTIFACT__"
_ERROR_MARKER = "__KILLCHAIN_PNG_INSPECT_ERROR__"
_SUMMARY_MARKER = "__KILLCHAIN_PNG_INSPECT_SUMMARY__"
_DEFAULT_MAX_EXTRACT_MB = 32
_DEFAULT_MAX_LSB_BYTES = 2_000_000
_PNG_INSPECT_PY = r'''
import binascii
import hashlib
import os
import re
import string
import struct
import sys
import zlib
from pathlib import Path

PNG = "__KILLCHAIN_PNG_INSPECT_PNG__"
CHUNK = "__KILLCHAIN_PNG_INSPECT_CHUNK__"
TEXT = "__KILLCHAIN_PNG_INSPECT_TEXT__"
IDAT = "__KILLCHAIN_PNG_INSPECT_IDAT__"
LSB = "__KILLCHAIN_PNG_INSPECT_LSB__"
VISUAL = "__KILLCHAIN_PNG_INSPECT_VISUAL__"
ARTIFACT = "__KILLCHAIN_PNG_INSPECT_ARTIFACT__"
ERROR = "__KILLCHAIN_PNG_INSPECT_ERROR__"
SUMMARY = "__KILLCHAIN_PNG_INSPECT_SUMMARY__"
SIG = b"\x89PNG\r\n\x1a\n"
TEXTUAL = {"tEXt", "zTXt", "iTXt"}
STANDARD = {
    "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "bKGD",
    "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "pHYs", "sBIT",
    "sPLT", "sRGB", "sTER", "tIME", "tRNS",
}

def clean(value, limit=500):
    return re.sub(r"\s+", " ", str(value).replace("\t", " ").replace("\n", " ")).strip()[:limit]

def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))[:72].strip("._") or "artifact"

def printable_ratio(blob):
    if not blob:
        return 0.0
    printable = sum(1 for b in blob if b in b"\r\n\t" or 32 <= b < 127)
    return printable / len(blob)

def ascii_preview(blob, limit=240):
    return clean("".join(chr(b) if b in b"\r\n\t" or 32 <= b < 127 else "." for b in blob[:limit]), limit)

def escaped_preview(value, limit=2400):
    text = str(value).replace("\\", "\\\\").replace("\t", " ")
    text = text.replace("\r", "").replace("\n", "\\n")
    return text[:limit]

def string_runs(blob):
    text = "".join(chr(b) if 32 <= b < 127 else "\n" for b in blob)
    runs = [part for part in re.split(r"\n+", text) if len(part) >= 6]
    return runs[:12]

def write_artifact(out_root, name, payload, role, source, budget):
    if not payload or len(payload) > budget["remaining"] or budget["count"] >= 16:
        return ""
    rel = safe_name(name)
    dest = out_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    budget["remaining"] -= len(payload)
    budget["count"] += 1
    digest = hashlib.sha256(payload).hexdigest()
    print(f"{ARTIFACT}\t{dest}\t{len(payload)}\t{role}\t{clean(source)}\t{digest}")
    return str(dest)

def parse_chunks(data):
    if not data.startswith(SIG):
        raise ValueError("not a PNG file")
    pos = len(SIG)
    chunks = []
    while pos + 8 <= len(data) and len(chunks) < 1024:
        length = int.from_bytes(data[pos:pos + 4], "big")
        raw_type = data[pos + 4:pos + 8]
        ctype = raw_type.decode("latin1", "replace")
        start = pos + 8
        end = start + length
        crc_end = end + 4
        if end > len(data) or crc_end > len(data):
            chunks.append({"type": ctype, "offset": pos, "length": length, "payload": b"", "crc_ok": False, "truncated": True})
            break
        payload = data[start:end]
        stored = int.from_bytes(data[end:crc_end], "big")
        crc = binascii.crc32(raw_type)
        crc = binascii.crc32(payload, crc) & 0xFFFFFFFF
        chunks.append({"type": ctype, "offset": pos, "length": length, "payload": payload, "crc_ok": crc == stored, "truncated": False})
        pos = crc_end
        if ctype == "IEND":
            break
    return chunks

def parse_ihdr(payload):
    if len(payload) < 13:
        raise ValueError("IHDR too short")
    width, height, bit_depth, color_type, compression, flt, interlace = struct.unpack(">IIBBBBB", payload[:13])
    return width, height, bit_depth, color_type, compression, flt, interlace

def text_chunk(ctype, payload):
    try:
        if ctype == "tEXt":
            key, _, value = payload.partition(b"\x00")
            return key.decode("latin1", "replace"), value.decode("latin1", "replace")
        if ctype == "zTXt":
            key, _, rest = payload.partition(b"\x00")
            if len(rest) < 2:
                return key.decode("latin1", "replace"), ""
            value = zlib.decompress(rest[1:], max_length=2_000_000)
            return key.decode("latin1", "replace"), value.decode("utf-8", "replace")
        if ctype == "iTXt":
            parts = payload.split(b"\x00", 5)
            if len(parts) < 6:
                return "", payload.decode("utf-8", "replace")
            key, comp_flag, _comp_method, _lang, _translated, value = parts
            if comp_flag == b"\x01":
                value = zlib.decompress(value, max_length=2_000_000)
            return key.decode("utf-8", "replace"), value.decode("utf-8", "replace")
    except Exception as exc:
        return "error", f"{type(exc).__name__}: {exc}"
    return "", ""

def paeth(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c

def unfilter(raw, width, height, bit_depth, color_type):
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
    if channels is None:
        raise ValueError(f"unsupported color type {color_type}")
    if bit_depth != 8:
        raise ValueError(f"unsupported bit depth {bit_depth}")
    bpp = channels
    stride = width * channels
    expected = height * (stride + 1)
    if len(raw) < expected:
        raise ValueError(f"decompressed IDAT too short: {len(raw)} < {expected}")
    rows = []
    pos = 0
    prev = bytearray(stride)
    for _row in range(height):
        ftype = raw[pos]
        pos += 1
        cur = bytearray(raw[pos:pos + stride])
        pos += stride
        if ftype == 1:
            for i in range(stride):
                cur[i] = (cur[i] + (cur[i - bpp] if i >= bpp else 0)) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                cur[i] = (cur[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((left + prev[i]) // 2)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                left = cur[i - bpp] if i >= bpp else 0
                up = prev[i]
                up_left = prev[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + paeth(left, up, up_left)) & 0xFF
        elif ftype != 0:
            raise ValueError(f"unsupported filter type {ftype}")
        rows.append(bytes(cur))
        prev = cur
    return b"".join(rows), channels

def channel_bytes(pixels, channels, mode):
    if mode == "all" or channels == 1:
        return pixels
    out = bytearray()
    for i in range(0, len(pixels), channels):
        px = pixels[i:i + channels]
        if mode == "rgb":
            out.extend(px[:3])
        elif mode == "alpha" and channels in {2, 4}:
            out.append(px[-1])
    return bytes(out)

def plane_bytes(pixels, channels, plane):
    if plane == "luma" or plane == "luma_inv":
        out = bytearray()
        for i in range(0, len(pixels), channels):
            px = pixels[i:i + channels]
            if channels == 1:
                value = px[0]
            else:
                r = px[0]
                g = px[1] if len(px) > 1 else r
                b = px[2] if len(px) > 2 else g
                value = (299 * r + 587 * g + 114 * b) // 1000
            out.append(255 - value if plane == "luma_inv" else value)
        return bytes(out)
    if plane == "alpha":
        if channels not in {2, 4}:
            return b""
        return bytes(pixels[i + channels - 1] for i in range(0, len(pixels), channels))
    match = re.match(r"([rgba])([0-7])$", plane)
    if not match:
        return b""
    channel_name, bit_text = match.groups()
    channel_index = {"r": 0, "g": 1, "b": 2, "a": channels - 1}[channel_name]
    if channel_index >= channels or (channel_name == "a" and channels not in {2, 4}):
        return b""
    bit = int(bit_text)
    return bytes(
        255 if pixels[i + channel_index] & (1 << bit) else 0
        for i in range(0, len(pixels), channels)
    )

def plane_stats(values):
    if not values:
        return 0, 0.0
    min_v = min(values)
    max_v = max(values)
    dark_ratio = sum(1 for value in values if value < 128) / len(values)
    return max_v - min_v, dark_ratio

def ascii_plane(values, width, height, max_width=64, max_height=20):
    if not values or width <= 0 or height <= 0:
        return ""
    out_w = min(width, max_width)
    # Console characters are taller than pixels. Keep enough rows for text
    # while avoiding giant prompt payloads.
    out_h = min(height, max(1, int(height * (out_w / width) * 0.55)), max_height)
    ramp = " .:-=+*#%@"
    lines = []
    for oy in range(out_h):
        y0 = int(oy * height / out_h)
        y1 = max(y0 + 1, int((oy + 1) * height / out_h))
        chars = []
        for ox in range(out_w):
            x0 = int(ox * width / out_w)
            x1 = max(x0 + 1, int((ox + 1) * width / out_w))
            total = 0
            count = 0
            for yy in range(y0, min(y1, height)):
                row = yy * width
                for xx in range(x0, min(x1, width)):
                    total += values[row + xx]
                    count += 1
            avg = total // max(1, count)
            chars.append(ramp[min(len(ramp) - 1, avg * len(ramp) // 256)])
        lines.append("".join(chars).rstrip())
    return "\n".join(lines).rstrip()

def inspect_visual_planes(pixels, width, height, channels):
    channel_names = "rgba" if channels == 4 else ("rgb" if channels >= 3 else "g")
    planes = ["luma"]
    if channels in {2, 4}:
        planes.append("alpha")
    for bit in (0, 1):
        for channel in channel_names:
            if channel == "g" and channels == 1:
                planes.append(f"r{bit}")
            elif channel in "rgba":
                planes.append(f"{channel}{bit}")
    seen = set()
    emitted = 0
    for plane in planes:
        if plane in seen:
            continue
        seen.add(plane)
        values = plane_bytes(pixels, channels, plane)
        contrast, dark_ratio = plane_stats(values)
        if contrast < 16:
            continue
        if plane not in {"luma", "luma_inv", "alpha"} and not (0.01 <= dark_ratio <= 0.99):
            continue
        preview = ascii_plane(values, width, height)
        if not preview:
            continue
        print(f"{VISUAL}\t{plane}\t{width}\t{height}\t{contrast}\t{dark_ratio:.3f}\t{escaped_preview(preview)}")
        emitted += 1
        if emitted >= 4:
            break
    return emitted

def pack_lsb(data, bit_count, bit_order):
    bits = []
    mask = (1 << bit_count) - 1
    for byte in data:
        value = byte & mask
        rng = range(bit_count - 1, -1, -1) if bit_order == "msb" else range(bit_count)
        for bit in rng:
            bits.append((value >> bit) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)

def inspect_lsb(pixels, channels, out_root, budget, max_lsb_bytes):
    modes = ["all"]
    if channels >= 3:
        modes.append("rgb")
    if channels in {2, 4}:
        modes.append("alpha")
    count = 0
    for mode in modes:
        selected = channel_bytes(pixels, channels, mode)
        for bit_count in (1, 2, 4):
            for order in ("msb", "lsb"):
                decoded = pack_lsb(selected, bit_count, order)
                if max_lsb_bytes > 0:
                    decoded = decoded[:max_lsb_bytes]
                ratio = printable_ratio(decoded[:4096])
                runs = string_runs(decoded[:200000])
                preview = ascii_preview(decoded)
                artifact = ""
                if runs or ratio >= 0.35:
                    artifact = write_artifact(
                        out_root,
                        f"lsb_{mode}_{bit_count}_{order}.bin",
                        decoded,
                        "lsb",
                        f"{mode}:{bit_count}:{order}",
                        budget,
                    )
                print(f"{LSB}\t{mode}\t{bit_count}\t{order}\t{len(decoded)}\t{ratio:.3f}\t{artifact}\t{clean(' | '.join(runs), 700)}\t{preview}")
                count += 1
    return count

def main():
    src = Path(sys.argv[1])
    out_root = Path(sys.argv[2])
    max_extract_mb = int(sys.argv[3])
    max_lsb_bytes = int(sys.argv[4])
    out_root.mkdir(parents=True, exist_ok=True)
    budget = {"remaining": max_extract_mb * 1024 * 1024, "count": 0}
    try:
        data = src.read_bytes()
        chunks = parse_chunks(data)
        ihdr = next(chunk for chunk in chunks if chunk["type"] == "IHDR")
        width, height, bit_depth, color_type, compression, flt, interlace = parse_ihdr(ihdr["payload"])
    except Exception as exc:
        print(f"{ERROR}\topen\t{clean(exc)}")
        print(f"{SUMMARY}\t0\t0\t0\t0")
        return
    print(f"{PNG}\t{width}\t{height}\t{bit_depth}\t{color_type}\t{interlace}\t{len(chunks)}")
    text_count = 0
    idat_count = 0
    lsb_count = 0
    visual_count = 0
    errors = 0
    idat_payloads = []
    for index, chunk in enumerate(chunks):
        ctype = chunk["type"]
        print(f"{CHUNK}\t{index}\t{ctype}\t{chunk['offset']}\t{chunk['length']}\t{int(chunk['crc_ok'])}\t{int(ctype in STANDARD)}")
        if ctype in TEXTUAL:
            key, value = text_chunk(ctype, chunk["payload"])
            if value:
                text_count += 1
                print(f"{TEXT}\t{ctype}\t{clean(key)}\t{clean(value, 1000)}")
        if ctype == "IDAT":
            idat_payloads.append(chunk["payload"])
    if idat_payloads:
        compressed = b"".join(idat_payloads)
        try:
            raw = zlib.decompress(compressed)
            idat_count = 1
            print(f"{IDAT}\t{len(compressed)}\t{len(raw)}\t{printable_ratio(raw[:4096]):.3f}\t{ascii_preview(raw)}")
            if interlace == 0 and width * height <= 25_000_000:
                pixels, channels = unfilter(raw, width, height, bit_depth, color_type)
                visual_count = inspect_visual_planes(pixels, width, height, channels)
                lsb_count = inspect_lsb(pixels, channels, out_root, budget, max_lsb_bytes)
        except Exception as exc:
            errors += 1
            print(f"{ERROR}\tidat\t{clean(exc)}")
    print(f"{SUMMARY}\t{len(chunks)}\t{text_count}\t{idat_count}\t{lsb_count}\t{visual_count}\t{errors}")

if __name__ == "__main__":
    main()
'''


class PngInspectPlugin:
    name = "png_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        max_extract_mb = _positive_int(request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB)
        max_lsb_bytes = _positive_int(request.metadata.get("max_lsb_bytes"), _DEFAULT_MAX_LSB_BYTES)
        output_expr = _durable_output_expr(
            source_path=path,
            requested_output_dir=output_dir,
            files_root=files_root,
        )
        cmd = (
            f"_kc_src={shlex.quote(path)}; "
            f"_kc_out={output_expr}; "
            f"python3 -c {shlex.quote(_PNG_INSPECT_PY)} "
            f'"$_kc_src" "$_kc_out" {max_extract_mb} {max_lsb_bytes}'
        )
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd,
                    files_root,
                    preserve_relative_paths=(".autopentest_artifacts",),
                ),
            ],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    source_path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    records = _parse_records(stdout)
    records["expected_prefix"] = _expected_prefix(request.metadata.get("flag_format"))
    artifacts = [
        Artifact(
            path=record["path"],
            kind=f"png_inspect_{record.get('role') or 'artifact'}",
            source="png_inspect",
            size=record.get("size"),
            digest=record.get("digest"),
            metadata={
                "source_file": source_path,
                "source_entry": record.get("source_entry"),
                "png_role": record.get("role"),
            },
        )
        for record in records["artifacts"][:80]
    ]
    flags = _literal_flag_candidates(records)
    summary = (
        f"png.inspect {source_path}: "
        f"{records.get('width') or '?'}x{records.get('height') or '?'}, "
        f"{len(records['chunks'])} chunk(s), "
        f"{len(records['texts'])} text item(s), "
        f"{len(records['visual'])} visual preview(s), "
        f"{len(records['lsb'])} LSB probe(s)"
    )
    if records["artifacts"]:
        summary += f", {len(records['artifacts'])} artifact(s)"
    if records["errors"]:
        summary += f", {len(records['errors'])} error(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    return ToolOutput(
        status=_status(result),
        summary=summary,
        output_text=_truncate(stdout, 5000),
        raw_log=_truncate(stdout + stderr, 8000),
        output_context={
            "path": source_path,
            "width": records.get("width"),
            "height": records.get("height"),
            "bit_depth": records.get("bit_depth"),
            "color_type": records.get("color_type"),
            "chunks": records["chunks"][:120],
            "text_items": records["texts"][:60],
            "idat": records["idat"][:10],
            "visual_previews": records["visual"][:6],
            "lsb": records["lsb"][:80],
            "artifact_records": records["artifacts"][:80],
            "extracted_artifacts_durable": True,
            "errors": records["errors"][:20],
        },
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _safe_stem(path: str) -> str:
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or "artifact"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *,
    source_path: str,
    requested_output_dir: str,
    files_root: str,
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return (
        '"$CTF_FILES_ROOT/.autopentest_artifacts/png_inspect_'
        f'{_safe_stem(source_path)}{suffix}_$$"'
    )


def _parse_records(stdout: str) -> dict[str, Any]:
    records: dict[str, Any] = {
        "chunks": [],
        "texts": [],
        "idat": [],
        "visual": [],
        "lsb": [],
        "artifacts": [],
        "errors": [],
    }
    for line in stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        marker = parts[0]
        if marker == _PNG_MARKER and len(parts) >= 7:
            records.update({
                "width": _int_or_none(parts[1]),
                "height": _int_or_none(parts[2]),
                "bit_depth": _int_or_none(parts[3]),
                "color_type": _int_or_none(parts[4]),
                "interlace": _int_or_none(parts[5]),
                "chunk_count": _int_or_none(parts[6]),
            })
        elif marker == _CHUNK_MARKER and len(parts) >= 7:
            records["chunks"].append({
                "index": _int_or_none(parts[1]),
                "type": parts[2],
                "offset": _int_or_none(parts[3]),
                "size": _int_or_none(parts[4]),
                "crc_ok": parts[5] == "1",
                "standard": parts[6] == "1",
            })
        elif marker == _TEXT_MARKER and len(parts) >= 4:
            records["texts"].append({
                "chunk_type": parts[1],
                "keyword": parts[2],
                "text": parts[3],
            })
        elif marker == _IDAT_MARKER and len(parts) >= 5:
            records["idat"].append({
                "compressed_size": _int_or_none(parts[1]),
                "decompressed_size": _int_or_none(parts[2]),
                "printable_ratio": _float_or_none(parts[3]),
                "preview": parts[4],
            })
        elif marker == _VISUAL_MARKER and len(parts) >= 7:
            records["visual"].append({
                "plane": parts[1],
                "width": _int_or_none(parts[2]),
                "height": _int_or_none(parts[3]),
                "contrast": _int_or_none(parts[4]),
                "dark_ratio": _float_or_none(parts[5]),
                "preview": _unescape_preview(parts[6]),
            })
        elif marker == _LSB_MARKER and len(parts) >= 9:
            records["lsb"].append({
                "mode": parts[1],
                "bits": _int_or_none(parts[2]),
                "bit_order": parts[3],
                "size": _int_or_none(parts[4]),
                "printable_ratio": _float_or_none(parts[5]),
                "artifact_path": parts[6] or None,
                "strings": parts[7],
                "preview": parts[8],
            })
        elif marker == _ARTIFACT_MARKER and len(parts) >= 6:
            records["artifacts"].append({
                "path": parts[1],
                "size": _int_or_none(parts[2]),
                "role": parts[3],
                "source_entry": parts[4],
                "digest": parts[5],
            })
        elif marker == _ERROR_MARKER and len(parts) >= 3:
            records["errors"].append({"stage": parts[1], "detail": parts[2]})
    return records


def _literal_flag_candidates(records: dict[str, Any]) -> list[FlagCandidate]:
    candidates: list[FlagCandidate] = []
    seen: set[str] = set()
    expected_prefix = str(records.get("expected_prefix") or "").strip()
    sources: list[tuple[str, str, str]] = []
    for item in records["texts"]:
        sources.append((
            str(item.get("text") or ""),
            "text",
            str(item.get("chunk_type") or ""),
        ))
    for item in records["lsb"]:
        sources.append((
            str(item.get("strings") or ""),
            "lsb",
            ":".join(
                str(part)
                for part in (
                    item.get("mode"),
                    item.get("bits"),
                    item.get("bit_order"),
                )
                if part not in (None, "")
            ),
        ))
    for text, role, source_entry in sources:
        for match in FLAG_PATTERN.findall(text):
            if expected_prefix and not match.startswith(f"{expected_prefix}{{"):
                continue
            if match in seen or not _high_signal_literal_flag(match):
                continue
            seen.add(match)
            candidates.append(
                FlagCandidate(
                    value=match,
                    source="png_inspect",
                    confidence=0.7 if role == "text" else 0.55,
                    metadata={
                        "literal_match": True,
                        "png_role": role,
                        "source_entry": source_entry,
                    },
                )
            )
    return candidates


def _high_signal_literal_flag(candidate: str) -> bool:
    if not plausible_flag(candidate):
        return False
    prefix, _, body_with_brace = candidate.partition("{")
    body = body_with_brace[:-1] if body_with_brace.endswith("}") else body_with_brace
    if not prefix or not prefix[0].isalpha():
        return False
    alnum = [ch for ch in body if ch.isalnum()]
    if len(alnum) < 4:
        return False
    if not alnum:
        return False
    counts = {ch: alnum.count(ch) for ch in set(alnum)}
    if max(counts.values()) / len(alnum) > 0.75:
        return False
    return True


def _expected_prefix(flag_format: object) -> str:
    match = re.match(r"^([A-Za-z0-9_]+)(?:\\?\{|\{)", str(flag_format or "").strip())
    if not match:
        return ""
    prefix = match.group(1)
    return prefix if prefix.replace("_", "").isalnum() else ""


def _unescape_preview(value: str) -> str:
    return value.replace("\\n", "\n").replace("\\\\", "\\")


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _float_or_none(value: object) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


__all__ = [
    "PngInspectPlugin",
    "_ARTIFACT_MARKER",
    "_CHUNK_MARKER",
    "_ERROR_MARKER",
    "_IDAT_MARKER",
    "_LSB_MARKER",
    "_PNG_MARKER",
    "_SUMMARY_MARKER",
    "_TEXT_MARKER",
    "_VISUAL_MARKER",
    "build_output",
]
