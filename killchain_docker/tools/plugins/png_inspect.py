"""png.inspect — deterministic PNG structure and LSB inspection."""

from __future__ import annotations
import re
import shlex
from typing import Any
from killchain_docker.state.domain import FlagCandidate
from killchain_docker.state.domain import Artifact
from killchain_docker.state.constants import (
    DEFAULT_FILES_ROOT,
    FLAG_PATTERN,
    plausible_flag,
)
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import _require, _run, _status
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
_DEFAULT_MAX_LSB_BYTES = 2000000
_PNG_INSPECT_PY = '\nimport binascii\nimport hashlib\nimport os\nimport re\nimport string\nimport struct\nimport sys\nimport zlib\nfrom pathlib import Path\n\nPNG = "__KILLCHAIN_PNG_INSPECT_PNG__"\nCHUNK = "__KILLCHAIN_PNG_INSPECT_CHUNK__"\nTEXT = "__KILLCHAIN_PNG_INSPECT_TEXT__"\nIDAT = "__KILLCHAIN_PNG_INSPECT_IDAT__"\nLSB = "__KILLCHAIN_PNG_INSPECT_LSB__"\nVISUAL = "__KILLCHAIN_PNG_INSPECT_VISUAL__"\nARTIFACT = "__KILLCHAIN_PNG_INSPECT_ARTIFACT__"\nERROR = "__KILLCHAIN_PNG_INSPECT_ERROR__"\nSUMMARY = "__KILLCHAIN_PNG_INSPECT_SUMMARY__"\nSIG = b"\\x89PNG\\r\\n\\x1a\\n"\nTEXTUAL = {"tEXt", "zTXt", "iTXt"}\nSTANDARD = {\n    "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "bKGD",\n    "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "pHYs", "sBIT",\n    "sPLT", "sRGB", "sTER", "tIME", "tRNS",\n}\n\ndef clean(value, limit=500):\n    return re.sub(r"\\s+", " ", str(value).replace("\\t", " ").replace("\\n", " ")).strip()[:limit]\n\ndef safe_name(value):\n    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))[:72].strip("._") or "artifact"\n\ndef printable_ratio(blob):\n    if not blob:\n        return 0.0\n    printable = sum(1 for b in blob if b in b"\\r\\n\\t" or 32 <= b < 127)\n    return printable / len(blob)\n\ndef ascii_preview(blob, limit=240):\n    return clean("".join(chr(b) if b in b"\\r\\n\\t" or 32 <= b < 127 else "." for b in blob[:limit]), limit)\n\ndef escaped_preview(value, limit=2400):\n    text = str(value).replace("\\\\", "\\\\\\\\").replace("\\t", " ")\n    text = text.replace("\\r", "").replace("\\n", "\\\\n")\n    return text[:limit]\n\ndef string_runs(blob):\n    text = "".join(chr(b) if 32 <= b < 127 else "\\n" for b in blob)\n    runs = [part for part in re.split(r"\\n+", text) if len(part) >= 6]\n    return runs[:12]\n\ndef write_artifact(out_root, name, payload, role, source, budget):\n    if not payload or len(payload) > budget["remaining"] or budget["count"] >= 16:\n        return ""\n    rel = safe_name(name)\n    dest = out_root / rel\n    dest.parent.mkdir(parents=True, exist_ok=True)\n    dest.write_bytes(payload)\n    budget["remaining"] -= len(payload)\n    budget["count"] += 1\n    digest = hashlib.sha256(payload).hexdigest()\n    print(f"{ARTIFACT}\\t{dest}\\t{len(payload)}\\t{role}\\t{clean(source)}\\t{digest}")\n    return str(dest)\n\ndef parse_chunks(data):\n    if not data.startswith(SIG):\n        raise ValueError("not a PNG file")\n    pos = len(SIG)\n    chunks = []\n    while pos + 8 <= len(data) and len(chunks) < 1024:\n        length = int.from_bytes(data[pos:pos + 4], "big")\n        raw_type = data[pos + 4:pos + 8]\n        ctype = raw_type.decode("latin1", "replace")\n        start = pos + 8\n        end = start + length\n        crc_end = end + 4\n        if end > len(data) or crc_end > len(data):\n            chunks.append({"type": ctype, "offset": pos, "length": length, "payload": b"", "crc_ok": False, "truncated": True})\n            break\n        payload = data[start:end]\n        stored = int.from_bytes(data[end:crc_end], "big")\n        crc = binascii.crc32(raw_type)\n        crc = binascii.crc32(payload, crc) & 0xFFFFFFFF\n        chunks.append({"type": ctype, "offset": pos, "length": length, "payload": payload, "crc_ok": crc == stored, "truncated": False})\n        pos = crc_end\n        if ctype == "IEND":\n            break\n    return chunks\n\ndef parse_ihdr(payload):\n    if len(payload) < 13:\n        raise ValueError("IHDR too short")\n    width, height, bit_depth, color_type, compression, flt, interlace = struct.unpack(">IIBBBBB", payload[:13])\n    return width, height, bit_depth, color_type, compression, flt, interlace\n\ndef text_chunk(ctype, payload):\n    try:\n        if ctype == "tEXt":\n            key, _, value = payload.partition(b"\\x00")\n            return key.decode("latin1", "replace"), value.decode("latin1", "replace")\n        if ctype == "zTXt":\n            key, _, rest = payload.partition(b"\\x00")\n            if len(rest) < 2:\n                return key.decode("latin1", "replace"), ""\n            value = zlib.decompress(rest[1:], max_length=2_000_000)\n            return key.decode("latin1", "replace"), value.decode("utf-8", "replace")\n        if ctype == "iTXt":\n            parts = payload.split(b"\\x00", 5)\n            if len(parts) < 6:\n                return "", payload.decode("utf-8", "replace")\n            key, comp_flag, _comp_method, _lang, _translated, value = parts\n            if comp_flag == b"\\x01":\n                value = zlib.decompress(value, max_length=2_000_000)\n            return key.decode("utf-8", "replace"), value.decode("utf-8", "replace")\n    except Exception as exc:\n        return "error", f"{type(exc).__name__}: {exc}"\n    return "", ""\n\ndef paeth(a, b, c):\n    p = a + b - c\n    pa = abs(p - a)\n    pb = abs(p - b)\n    pc = abs(p - c)\n    if pa <= pb and pa <= pc:\n        return a\n    if pb <= pc:\n        return b\n    return c\n\ndef unfilter(raw, width, height, bit_depth, color_type):\n    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)\n    if channels is None:\n        raise ValueError(f"unsupported color type {color_type}")\n    if bit_depth != 8:\n        raise ValueError(f"unsupported bit depth {bit_depth}")\n    bpp = channels\n    stride = width * channels\n    expected = height * (stride + 1)\n    if len(raw) < expected:\n        raise ValueError(f"decompressed IDAT too short: {len(raw)} < {expected}")\n    rows = []\n    pos = 0\n    prev = bytearray(stride)\n    for _row in range(height):\n        ftype = raw[pos]\n        pos += 1\n        cur = bytearray(raw[pos:pos + stride])\n        pos += stride\n        if ftype == 1:\n            for i in range(stride):\n                cur[i] = (cur[i] + (cur[i - bpp] if i >= bpp else 0)) & 0xFF\n        elif ftype == 2:\n            for i in range(stride):\n                cur[i] = (cur[i] + prev[i]) & 0xFF\n        elif ftype == 3:\n            for i in range(stride):\n                left = cur[i - bpp] if i >= bpp else 0\n                cur[i] = (cur[i] + ((left + prev[i]) // 2)) & 0xFF\n        elif ftype == 4:\n            for i in range(stride):\n                left = cur[i - bpp] if i >= bpp else 0\n                up = prev[i]\n                up_left = prev[i - bpp] if i >= bpp else 0\n                cur[i] = (cur[i] + paeth(left, up, up_left)) & 0xFF\n        elif ftype != 0:\n            raise ValueError(f"unsupported filter type {ftype}")\n        rows.append(bytes(cur))\n        prev = cur\n    return b"".join(rows), channels\n\ndef channel_bytes(pixels, channels, mode):\n    if mode == "all" or channels == 1:\n        return pixels\n    out = bytearray()\n    for i in range(0, len(pixels), channels):\n        px = pixels[i:i + channels]\n        if mode == "rgb":\n            out.extend(px[:3])\n        elif mode == "alpha" and channels in {2, 4}:\n            out.append(px[-1])\n    return bytes(out)\n\ndef plane_bytes(pixels, channels, plane):\n    if plane == "luma" or plane == "luma_inv":\n        out = bytearray()\n        for i in range(0, len(pixels), channels):\n            px = pixels[i:i + channels]\n            if channels == 1:\n                value = px[0]\n            else:\n                r = px[0]\n                g = px[1] if len(px) > 1 else r\n                b = px[2] if len(px) > 2 else g\n                value = (299 * r + 587 * g + 114 * b) // 1000\n            out.append(255 - value if plane == "luma_inv" else value)\n        return bytes(out)\n    if plane == "alpha":\n        if channels not in {2, 4}:\n            return b""\n        return bytes(pixels[i + channels - 1] for i in range(0, len(pixels), channels))\n    match = re.match(r"([rgba])([0-7])$", plane)\n    if not match:\n        return b""\n    channel_name, bit_text = match.groups()\n    channel_index = {"r": 0, "g": 1, "b": 2, "a": channels - 1}[channel_name]\n    if channel_index >= channels or (channel_name == "a" and channels not in {2, 4}):\n        return b""\n    bit = int(bit_text)\n    return bytes(\n        255 if pixels[i + channel_index] & (1 << bit) else 0\n        for i in range(0, len(pixels), channels)\n    )\n\ndef plane_stats(values):\n    if not values:\n        return 0, 0.0\n    min_v = min(values)\n    max_v = max(values)\n    dark_ratio = sum(1 for value in values if value < 128) / len(values)\n    return max_v - min_v, dark_ratio\n\ndef ascii_plane(values, width, height, max_width=64, max_height=20):\n    if not values or width <= 0 or height <= 0:\n        return ""\n    out_w = min(width, max_width)\n    # Console characters are taller than pixels. Keep enough rows for text\n    # while avoiding giant prompt payloads.\n    out_h = min(height, max(1, int(height * (out_w / width) * 0.55)), max_height)\n    ramp = " .:-=+*#%@"\n    lines = []\n    for oy in range(out_h):\n        y0 = int(oy * height / out_h)\n        y1 = max(y0 + 1, int((oy + 1) * height / out_h))\n        chars = []\n        for ox in range(out_w):\n            x0 = int(ox * width / out_w)\n            x1 = max(x0 + 1, int((ox + 1) * width / out_w))\n            total = 0\n            count = 0\n            for yy in range(y0, min(y1, height)):\n                row = yy * width\n                for xx in range(x0, min(x1, width)):\n                    total += values[row + xx]\n                    count += 1\n            avg = total // max(1, count)\n            chars.append(ramp[min(len(ramp) - 1, avg * len(ramp) // 256)])\n        lines.append("".join(chars).rstrip())\n    return "\\n".join(lines).rstrip()\n\ndef inspect_visual_planes(pixels, width, height, channels):\n    channel_names = "rgba" if channels == 4 else ("rgb" if channels >= 3 else "g")\n    planes = ["luma"]\n    if channels in {2, 4}:\n        planes.append("alpha")\n    for bit in (0, 1):\n        for channel in channel_names:\n            if channel == "g" and channels == 1:\n                planes.append(f"r{bit}")\n            elif channel in "rgba":\n                planes.append(f"{channel}{bit}")\n    seen = set()\n    emitted = 0\n    for plane in planes:\n        if plane in seen:\n            continue\n        seen.add(plane)\n        values = plane_bytes(pixels, channels, plane)\n        contrast, dark_ratio = plane_stats(values)\n        if contrast < 16:\n            continue\n        if plane not in {"luma", "luma_inv", "alpha"} and not (0.01 <= dark_ratio <= 0.99):\n            continue\n        preview = ascii_plane(values, width, height)\n        if not preview:\n            continue\n        print(f"{VISUAL}\\t{plane}\\t{width}\\t{height}\\t{contrast}\\t{dark_ratio:.3f}\\t{escaped_preview(preview)}")\n        emitted += 1\n        if emitted >= 4:\n            break\n    return emitted\n\ndef pack_lsb(data, bit_count, bit_order):\n    bits = []\n    mask = (1 << bit_count) - 1\n    for byte in data:\n        value = byte & mask\n        rng = range(bit_count - 1, -1, -1) if bit_order == "msb" else range(bit_count)\n        for bit in rng:\n            bits.append((value >> bit) & 1)\n    out = bytearray()\n    for i in range(0, len(bits) - 7, 8):\n        value = 0\n        for bit in bits[i:i + 8]:\n            value = (value << 1) | bit\n        out.append(value)\n    return bytes(out)\n\ndef inspect_lsb(pixels, channels, out_root, budget, max_lsb_bytes):\n    modes = ["all"]\n    if channels >= 3:\n        modes.append("rgb")\n    if channels in {2, 4}:\n        modes.append("alpha")\n    count = 0\n    for mode in modes:\n        selected = channel_bytes(pixels, channels, mode)\n        for bit_count in (1, 2, 4):\n            for order in ("msb", "lsb"):\n                decoded = pack_lsb(selected, bit_count, order)\n                if max_lsb_bytes > 0:\n                    decoded = decoded[:max_lsb_bytes]\n                ratio = printable_ratio(decoded[:4096])\n                runs = string_runs(decoded[:200000])\n                preview = ascii_preview(decoded)\n                artifact = ""\n                if runs or ratio >= 0.35:\n                    artifact = write_artifact(\n                        out_root,\n                        f"lsb_{mode}_{bit_count}_{order}.bin",\n                        decoded,\n                        "lsb",\n                        f"{mode}:{bit_count}:{order}",\n                        budget,\n                    )\n                print(f"{LSB}\\t{mode}\\t{bit_count}\\t{order}\\t{len(decoded)}\\t{ratio:.3f}\\t{artifact}\\t{clean(\' | \'.join(runs), 700)}\\t{preview}")\n                count += 1\n    return count\n\ndef main():\n    src = Path(sys.argv[1])\n    out_root = Path(sys.argv[2])\n    max_extract_mb = int(sys.argv[3])\n    max_lsb_bytes = int(sys.argv[4])\n    out_root.mkdir(parents=True, exist_ok=True)\n    budget = {"remaining": max_extract_mb * 1024 * 1024, "count": 0}\n    try:\n        data = src.read_bytes()\n        chunks = parse_chunks(data)\n        ihdr = next(chunk for chunk in chunks if chunk["type"] == "IHDR")\n        width, height, bit_depth, color_type, compression, flt, interlace = parse_ihdr(ihdr["payload"])\n    except Exception as exc:\n        print(f"{ERROR}\\topen\\t{clean(exc)}")\n        print(f"{SUMMARY}\\t0\\t0\\t0\\t0")\n        return\n    print(f"{PNG}\\t{width}\\t{height}\\t{bit_depth}\\t{color_type}\\t{interlace}\\t{len(chunks)}")\n    text_count = 0\n    idat_count = 0\n    lsb_count = 0\n    visual_count = 0\n    errors = 0\n    idat_payloads = []\n    for index, chunk in enumerate(chunks):\n        ctype = chunk["type"]\n        print(f"{CHUNK}\\t{index}\\t{ctype}\\t{chunk[\'offset\']}\\t{chunk[\'length\']}\\t{int(chunk[\'crc_ok\'])}\\t{int(ctype in STANDARD)}")\n        if ctype in TEXTUAL:\n            key, value = text_chunk(ctype, chunk["payload"])\n            if value:\n                text_count += 1\n                print(f"{TEXT}\\t{ctype}\\t{clean(key)}\\t{clean(value, 1000)}")\n        if ctype == "IDAT":\n            idat_payloads.append(chunk["payload"])\n    if idat_payloads:\n        compressed = b"".join(idat_payloads)\n        try:\n            raw = zlib.decompress(compressed)\n            idat_count = 1\n            print(f"{IDAT}\\t{len(compressed)}\\t{len(raw)}\\t{printable_ratio(raw[:4096]):.3f}\\t{ascii_preview(raw)}")\n            if interlace == 0 and width * height <= 25_000_000:\n                pixels, channels = unfilter(raw, width, height, bit_depth, color_type)\n                visual_count = inspect_visual_planes(pixels, width, height, channels)\n                lsb_count = inspect_lsb(pixels, channels, out_root, budget, max_lsb_bytes)\n        except Exception as exc:\n            errors += 1\n            print(f"{ERROR}\\tidat\\t{clean(exc)}")\n    print(f"{SUMMARY}\\t{len(chunks)}\\t{text_count}\\t{idat_count}\\t{lsb_count}\\t{visual_count}\\t{errors}")\n\nif __name__ == "__main__":\n    main()\n'


class PngInspectPlugin:
    name = "png_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        max_extract_mb = _positive_int(
            request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB
        )
        max_lsb_bytes = _positive_int(
            request.metadata.get("max_lsb_bytes"), _DEFAULT_MAX_LSB_BYTES
        )
        output_expr = _durable_output_expr(
            source_path=path, requested_output_dir=output_dir, files_root=files_root
        )
        cmd = f'_kc_src={shlex.quote(path)}; _kc_out={output_expr}; python3 -c {shlex.quote(_PNG_INSPECT_PY)} "$_kc_src" "$_kc_out" {max_extract_mb} {max_lsb_bytes}'
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd, files_root, preserve_relative_paths=(".autopentest_artifacts",)
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
    summary = f"png.inspect {source_path}: {records.get('width') or '?'}x{records.get('height') or '?'}, {len(records['chunks'])} chunk(s), {len(records['texts'])} text item(s), {len(records['visual'])} visual preview(s), {len(records['lsb'])} LSB probe(s)"
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
    return re.sub("[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *, source_path: str, requested_output_dir: str, files_root: str
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return f'"$CTF_FILES_ROOT/.autopentest_artifacts/png_inspect_{_safe_stem(source_path)}{suffix}_$$"'


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
            records.update(
                {
                    "width": _int_or_none(parts[1]),
                    "height": _int_or_none(parts[2]),
                    "bit_depth": _int_or_none(parts[3]),
                    "color_type": _int_or_none(parts[4]),
                    "interlace": _int_or_none(parts[5]),
                    "chunk_count": _int_or_none(parts[6]),
                }
            )
        elif marker == _CHUNK_MARKER and len(parts) >= 7:
            records["chunks"].append(
                {
                    "index": _int_or_none(parts[1]),
                    "type": parts[2],
                    "offset": _int_or_none(parts[3]),
                    "size": _int_or_none(parts[4]),
                    "crc_ok": parts[5] == "1",
                    "standard": parts[6] == "1",
                }
            )
        elif marker == _TEXT_MARKER and len(parts) >= 4:
            records["texts"].append(
                {"chunk_type": parts[1], "keyword": parts[2], "text": parts[3]}
            )
        elif marker == _IDAT_MARKER and len(parts) >= 5:
            records["idat"].append(
                {
                    "compressed_size": _int_or_none(parts[1]),
                    "decompressed_size": _int_or_none(parts[2]),
                    "printable_ratio": _float_or_none(parts[3]),
                    "preview": parts[4],
                }
            )
        elif marker == _VISUAL_MARKER and len(parts) >= 7:
            records["visual"].append(
                {
                    "plane": parts[1],
                    "width": _int_or_none(parts[2]),
                    "height": _int_or_none(parts[3]),
                    "contrast": _int_or_none(parts[4]),
                    "dark_ratio": _float_or_none(parts[5]),
                    "preview": _unescape_preview(parts[6]),
                }
            )
        elif marker == _LSB_MARKER and len(parts) >= 9:
            records["lsb"].append(
                {
                    "mode": parts[1],
                    "bits": _int_or_none(parts[2]),
                    "bit_order": parts[3],
                    "size": _int_or_none(parts[4]),
                    "printable_ratio": _float_or_none(parts[5]),
                    "artifact_path": parts[6] or None,
                    "strings": parts[7],
                    "preview": parts[8],
                }
            )
        elif marker == _ARTIFACT_MARKER and len(parts) >= 6:
            records["artifacts"].append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "role": parts[3],
                    "source_entry": parts[4],
                    "digest": parts[5],
                }
            )
        elif marker == _ERROR_MARKER and len(parts) >= 3:
            records["errors"].append({"stage": parts[1], "detail": parts[2]})
    return records


def _literal_flag_candidates(records: dict[str, Any]) -> list[FlagCandidate]:
    candidates: list[FlagCandidate] = []
    seen: set[str] = set()
    expected_prefix = str(records.get("expected_prefix") or "").strip()
    sources: list[tuple[str, str, str]] = []
    for item in records["texts"]:
        sources.append(
            (str(item.get("text") or ""), "text", str(item.get("chunk_type") or ""))
        )
    for item in records["lsb"]:
        sources.append(
            (
                str(item.get("strings") or ""),
                "lsb",
                ":".join(
                    (
                        str(part)
                        for part in (
                            item.get("mode"),
                            item.get("bits"),
                            item.get("bit_order"),
                        )
                        if part not in (None, "")
                    )
                ),
            )
        )
    for text, role, source_entry in sources:
        for match in FLAG_PATTERN.findall(text):
            if expected_prefix and (not match.startswith(f"{expected_prefix}{{")):
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
    match = re.match("^([A-Za-z0-9_]+)(?:\\\\?\\{|\\{)", str(flag_format or "").strip())
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
