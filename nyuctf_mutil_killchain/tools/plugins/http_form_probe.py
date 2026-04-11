"""Generic HTML form interaction and upload probing tool."""

from __future__ import annotations

import json
from urllib.parse import urlsplit, urlunsplit

from nyuctf_mutil_killchain.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "http_form_probe"


def _iter_query_variants(query_variants: list[str] | None) -> list[str]:
    """Return every non-empty query variant, or a single baseline empty variant."""

    normalized = [str(item).strip() for item in (query_variants or []) if str(item).strip()]
    return normalized or [""]


def _merge_query_variant_url(target: str, query_variant: str) -> str:
    """Apply a raw query variant while replacing conflicting keyed or bare query segments."""

    query_text = str(query_variant or "").strip()
    if not query_text:
        return target
    if query_text.startswith("?"):
        query_text = query_text[1:]

    variant_segments = [segment for segment in query_text.split("&") if segment]
    if not variant_segments:
        return target

    target_parts = urlsplit(target)
    existing_segments = [segment for segment in target_parts.query.split("&") if segment]
    override_keys = {
        segment.split("=", 1)[0]
        for segment in variant_segments
        if "=" in segment and segment.split("=", 1)[0]
    }
    has_bare_variant_segments = any("=" not in segment for segment in variant_segments)
    merged_segments = []
    for segment in existing_segments:
        if "=" in segment:
            if segment.split("=", 1)[0] in override_keys:
                continue
            merged_segments.append(segment)
            continue
        if has_bare_variant_segments:
            continue
        merged_segments.append(segment)
    merged_segments.extend(variant_segments)
    return urlunsplit(
        (
            target_parts.scheme,
            target_parts.netloc,
            target_parts.path,
            "&".join(merged_segments),
            target_parts.fragment,
        )
    )


def _split_query_variant_for_file_inputs(
    query_variant: str,
    file_field_names: list[str] | None,
) -> tuple[str, list[tuple[str, str]]]:
    """Lift same-name file-field assignments into multipart fields and leave the rest in the URL."""

    query_text = str(query_variant or "").strip()
    if not query_text:
        return "", []
    if query_text.startswith("?"):
        query_text = query_text[1:]

    file_names = {str(name).strip() for name in (file_field_names or []) if str(name).strip()}
    url_segments: list[str] = []
    duplicate_fields: list[tuple[str, str]] = []
    for segment in [item for item in query_text.split("&") if item]:
        if "=" not in segment:
            url_segments.append(segment)
            continue
        key, value = segment.split("=", 1)
        if key in file_names:
            duplicate_fields.append((key, value))
        else:
            url_segments.append(segment)
    return "&".join(url_segments), duplicate_fields

SCRIPT = r"""
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
page_url = payload.get("page_url")
forms = payload.get("forms") or []
text_payloads = payload.get("text_payloads") or ["autopentest-canary"]
filename_variants = payload.get("filename_variants") or ["autopentest.txt"]
query_variants = payload.get("query_variants") or [""]
timeout_s = int(payload.get("timeout_s", 30))

records = []
notes_list = []
flag_candidates = []
interesting_paths = []
submission_results = []
reflected_markers = []
reflected_filenames = []
action_urls = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
_FP_PREFIXES = frozenset({
    "html", "body", "div", "span", "input", "button", "textarea",
    "select", "label", "form", "table", "thead", "tbody", "tr", "td", "th",
    "ul", "ol", "li", "nav", "header", "footer", "section", "article",
    "aside", "main", "summary", "details", "dialog", "fieldset", "legend",
    "img", "video", "audio", "canvas", "svg", "path", "circle", "rect",
    "code", "pre", "blockquote", "cite", "abbr", "address", "figure",
    "var", "function", "return", "if", "else", "for", "while", "switch",
    "case", "class", "interface", "struct", "enum", "type", "export",
    "import", "from", "const", "let", "new", "delete", "typeof", "void",
    "null", "undefined", "true", "false", "try", "catch", "throw",
    "this", "self", "super", "def", "lambda", "yield", "async", "await",
    "create", "drop", "alter", "insert", "update",
})
_CSS_BODY = re.compile(
    r"^[\s]*([a-z\-]+\s*:\s*[a-z0-9#%.\"', \-()]+\s*;?[\s]*)+$",
    re.IGNORECASE,
)

def _plausible_flag(m):
    prefix, _, body = m.partition("{")
    body = body.rstrip("}")
    if not prefix or not body:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        return False
    if prefix.lower() in _FP_PREFIXES:
        return False
    if _CSS_BODY.match(body):
        return False
    return True


def iter_query_variants(items):
    normalized = [str(item).strip() for item in (items or []) if str(item).strip()]
    return normalized or [""]


def merge_query_variant_url(target, query_variant):
    query_text = str(query_variant or "").strip()
    if not query_text:
        return target
    if query_text.startswith("?"):
        query_text = query_text[1:]

    variant_segments = [segment for segment in query_text.split("&") if segment]
    if not variant_segments:
        return target

    target_parts = urlsplit(target)
    existing_segments = [segment for segment in target_parts.query.split("&") if segment]
    override_keys = {
        segment.split("=", 1)[0]
        for segment in variant_segments
        if "=" in segment and segment.split("=", 1)[0]
    }
    has_bare_variant_segments = any("=" not in segment for segment in variant_segments)
    merged_segments = []
    for segment in existing_segments:
        if "=" in segment:
            if segment.split("=", 1)[0] in override_keys:
                continue
            merged_segments.append(segment)
            continue
        if has_bare_variant_segments:
            continue
        merged_segments.append(segment)
    merged_segments.extend(variant_segments)
    return urlunsplit(
        (
            target_parts.scheme,
            target_parts.netloc,
            target_parts.path,
            "&".join(merged_segments),
            target_parts.fragment,
        )
    )


def split_query_variant_for_file_inputs(query_variant, file_field_names):
    query_text = str(query_variant or "").strip()
    if not query_text:
        return "", []
    if query_text.startswith("?"):
        query_text = query_text[1:]

    file_names = {str(name).strip() for name in (file_field_names or []) if str(name).strip()}
    url_segments = []
    duplicate_fields = []
    for segment in [item for item in query_text.split("&") if item]:
        if "=" not in segment:
            url_segments.append(segment)
            continue
        key, value = segment.split("=", 1)
        if key in file_names:
            duplicate_fields.append((key, value))
        else:
            url_segments.append(segment)
    return "&".join(url_segments), duplicate_fields


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs.get("action") or "",
                "method": (attrs.get("method") or "get").lower(),
                "enctype": (attrs.get("enctype") or "application/x-www-form-urlencoded").lower(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "button"} and self.current_form is not None:
            name = attrs.get("name") or attrs.get("id") or ""
            if not name:
                return
            self.current_form["inputs"].append(
                {
                    "name": name,
                    "type": (attrs.get("type") or "text").lower(),
                    "value": attrs.get("value") or "",
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def build_ssl_context(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)"},
        method="GET",
    )
    open_args = {"timeout": min(timeout_s, 8)}
    if ssl_ctx is not None:
        open_args["context"] = ssl_ctx
    with urllib.request.urlopen(req, **open_args) as resp:
        body = resp.read(20000).decode("utf-8", errors="ignore")
        return resp.status, resp.geturl(), body


def add_flags(text):
    for candidate in flag_re.findall(text or ""):
        if not _plausible_flag(candidate):
            continue
        if candidate not in flag_candidates:
            flag_candidates.append(candidate)


def add_interesting(url):
    if url and url not in interesting_paths:
        interesting_paths.append(url)


def add_reflected(container, value):
    if value and value not in container:
        container.append(value)


def normalize_forms():
    normalized = []
    for form in forms[:6]:
        if isinstance(form, dict):
            normalized.append(form)
    if normalized:
        return normalized
    if not page_url:
        return []
    try:
        _, _, body = fetch(page_url)
    except Exception as exc:
        notes_list.append(f"Failed to fetch page for form parsing {page_url}: {type(exc).__name__}: {exc}")
        return []
    parser = FormParser()
    try:
        parser.feed(body)
    except Exception as exc:
        notes_list.append(f"HTML form parsing error on {page_url}: {type(exc).__name__}: {exc}")
        return []
    return parser.forms[:6]


def form_target_url(base, action, query_variant):
    target = urljoin(base, action or "")
    return merge_query_variant_url(target, query_variant)


def choose_text_value(field_name, payload_text):
    lowered = field_name.lower()
    if "email" in lowered:
        return f"probe+{payload_text}@example.invalid"
    if "pass" in lowered:
        return payload_text + "-pass"
    if "user" in lowered or "login" in lowered or "name" in lowered:
        return payload_text + "-user"
    return payload_text


def encode_multipart(fields, files):
    boundary = "----autopentestboundary"
    body = bytearray()
    for key, value in fields:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")
    for file_item in files:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            (
                f'Content-Disposition: form-data; name="{file_item["name"]}"; '
                f'filename="{file_item["filename"]}"\r\n'
            ).encode("utf-8")
        )
        body.extend(b"Content-Type: text/plain\r\n\r\n")
        body.extend(file_item["content"])
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def submit(url, *, method, body=None, headers=None):
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)", **(headers or {})},
    )
    try:
        open_args = {"timeout": min(timeout_s, 8)}
        if ssl_ctx is not None:
            open_args["context"] = ssl_ctx
        with urllib.request.urlopen(req, **open_args) as resp:
            body_text = resp.read(16000).decode("utf-8", errors="ignore")
            return resp.status, resp.geturl(), body_text
    except urllib.error.HTTPError as exc:
        try:
            body_text = exc.read(16000).decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""
        return exc.code, url, body_text
    except Exception as exc:
        notes_list.append(f"Form submission failed for {url}: {type(exc).__name__}: {exc}")
        return None, url, ""


if not page_url:
    records.append({"type": "summary", "text": "HTTP form probe skipped: page_url not provided."})
else:
    ssl_ctx = build_ssl_context(page_url)
    normalized_forms = normalize_forms()
    if not normalized_forms:
        records.append({"type": "summary", "text": f"HTTP form probe found no forms on {page_url}."})
    else:
        submission_budget = 10
        for form_index, form in enumerate(normalized_forms[:4]):
            method = str(form.get("method") or "get").strip().upper() or "GET"
            enctype = str(form.get("enctype") or "application/x-www-form-urlencoded").strip().lower()
            inputs = [field for field in list(form.get("inputs") or []) if isinstance(field, dict)]
            has_file_input = any(str(field.get("type") or "").lower() == "file" for field in inputs)
            file_field_names = [
                str(field.get("name") or "").strip()
                for field in inputs
                if str(field.get("type") or "").lower() == "file" and str(field.get("name") or "").strip()
            ]
            payload_values = text_payloads[:1] if has_file_input else text_payloads[:2]
            file_values = filename_variants[:2] if has_file_input else [""]

            for query_variant in iter_query_variants(query_variants):
                url_query_variant, duplicate_field_pairs = split_query_variant_for_file_inputs(
                    query_variant,
                    file_field_names,
                )
                target_url = form_target_url(page_url, form.get("action") or "", url_query_variant)
                if target_url not in action_urls:
                    action_urls.append(target_url)
                for payload_text in payload_values:
                    for filename in file_values:
                        if submission_budget <= 0:
                            break
                        submission_budget -= 1

                        fields = []
                        files = []
                        marker = f"{payload_text}-form{form_index}"
                        for field in inputs:
                            field_name = str(field.get("name") or "").strip()
                            if not field_name:
                                continue
                            field_type = str(field.get("type") or "text").lower()
                            field_value = field.get("value") or ""
                            if field_type in {"hidden", "submit", "button"}:
                                fields.append((field_name, field_value))
                            elif field_type == "file":
                                file_bytes = (marker + "\n").encode("utf-8")
                                files.append(
                                    {
                                        "name": field_name,
                                        "filename": filename or "autopentest.txt",
                                        "content": file_bytes,
                                    }
                                )
                            else:
                                fields.append((field_name, choose_text_value(field_name, marker)))

                        for field_name, field_value in duplicate_field_pairs:
                            fields.append((field_name, field_value))

                        request_method = method
                        body = None
                        headers = {}
                        submission_url = target_url
                        if files or "multipart/form-data" in enctype:
                            request_method = "POST"
                            body, content_type = encode_multipart(fields, files)
                            headers["Content-Type"] = content_type
                        elif request_method == "GET":
                            encoded_fields = urllib.parse.urlencode(fields)
                            if encoded_fields:
                                separator = "&" if urlparse(submission_url).query else "?"
                                submission_url = submission_url + separator + encoded_fields
                        else:
                            body = urllib.parse.urlencode(fields).encode("utf-8")
                            headers["Content-Type"] = "application/x-www-form-urlencoded"

                        status, final_url, body_text = submit(
                            submission_url,
                            method=request_method,
                            body=body,
                            headers=headers,
                        )
                        add_flags(body_text)
                        if status in {200, 201, 202, 204, 302, 303, 401, 403}:
                            add_interesting(final_url or submission_url)
                        if marker in (body_text or ""):
                            add_reflected(reflected_markers, marker)
                        if filename and filename in (body_text or ""):
                            add_reflected(reflected_filenames, filename)
                        submission_results.append(
                            {
                                "form_index": form_index,
                                "method": request_method,
                                "url": submission_url,
                                "status": status,
                                "query_variant": query_variant,
                                "marker": marker,
                                "filename": filename or None,
                                "has_file_input": has_file_input,
                                "body_preview": (body_text or "")[:240],
                            }
                        )
                    if submission_budget <= 0:
                        break
                if submission_budget <= 0:
                    break
            if submission_budget <= 0:
                break

        severity = "high" if flag_candidates else ("medium" if submission_results else "info")
        if submission_results:
            records.append({
                "type": "finding",
                "finding_id": f"finding-{asset_id}-form-probe",
                "title": "HTML forms interacted with live target",
                "severity": severity,
                "description": f"Executed {len(submission_results)} baseline form submission(s) against {page_url}.",
                "asset_refs": [asset_id],
                "evidence_refs": interesting_paths[:8] or [page_url],
                "metadata": {
                    "source": "http_form_probe",
                    "submission_results": submission_results[:20],
                    "reflected_markers": reflected_markers[:10],
                    "reflected_filenames": reflected_filenames[:10],
                },
            })

        if flag_candidates:
            records.append({
                "type": "finding",
                "finding_id": f"finding-{asset_id}-form-probe-flags",
                "title": "Flag-like token recovered during form interaction",
                "severity": "high",
                "description": f"Recovered {len(flag_candidates)} flag candidate(s) while interacting with HTML forms.",
                "asset_refs": [asset_id],
                "evidence_refs": flag_candidates[:8],
                "metadata": {"source": "http_form_probe", "flag_candidates": flag_candidates[:10]},
            })

        records.append({
            "type": "summary",
            "text": (
                f"HTTP form probe completed for {page_url}: "
                f"{len(normalized_forms)} form(s), {len(submission_results)} submission(s), "
                f"{len(flag_candidates)} flag candidate(s)."
            ),
        })
        records.append({
            "type": "output_context",
            "page_url": page_url,
            "forms": normalized_forms[:6],
            "action_urls": action_urls[:10],
            "submission_results": submission_results[:20],
            "interesting_paths": interesting_paths[:20],
            "flag_candidates": flag_candidates[:10],
            "reflected_markers": reflected_markers[:10],
            "reflected_filenames": reflected_filenames[:10],
            "manual_checks": [
                "Review any reflected markers or filenames for unsafe server-side handling.",
                "Inspect multipart endpoints for filename, path, and content interpretation bugs.",
                "Validate any recovered flag-like token before submission.",
            ],
        })

for note in notes_list:
    records.append({"type": "note", "text": note})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "page_url": request.metadata.get("page_url"),
        "forms": request.metadata.get("forms", []),
        "text_payloads": request.metadata.get("text_payloads", []),
        "filename_variants": request.metadata.get("filename_variants", []),
        "query_variants": request.metadata.get("query_variants", []),
        "timeout_s": request.timeout_s,
    }
    if not payload["page_url"]:
        raise ToolExecutionError("http_form_probe requires metadata.page_url")
    return ["-c", SCRIPT, json.dumps(payload)]
