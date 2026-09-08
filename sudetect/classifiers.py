"""Bounded, deterministic content signals. Raw values never enter the report.

Heuristics raise candidates, never prove legal sensitivity or credential validity.
Only explicitly supplied synthetic test markers may be confirmed automatically.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit

MAX_ANALYSIS_BYTES = 262144
MAX_SIGNALS = 32
MAX_LINKS = 64
MAX_JSON_DEPTH = 128
SENSITIVE_FIELDS = frozenset({
    "email", "phone", "telephone", "mobile", "address", "birthdate", "dob",
    "ssn", "passport", "license_number", "account_number", "resident_number",
    "customer_name", "employee_name", "salary", "cost_price", "margin",
    "주민등록번호", "휴대폰", "전화번호", "계좌번호", "고객명", "원가", "급여",
})
SECRET_PATTERNS = (
    ("PRIVATE_KEY_CANDIDATE", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SERVER_SECRET_CANDIDATE", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{12,}\b")),
    ("GITHUB_SECRET_CANDIDATE", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
)
FETCH_LITERAL = re.compile(r'''\b(?:fetch|axios\.get)\s*\(\s*["']([^"'\s]{1,2048})["']''')
FETCH_DYNAMIC = re.compile(r'''\b(?:fetch|axios\.get)\s*\(\s*(?:`[^`\r\n]*\$\{[^}\r\n]+\}[^`\r\n]*`|[A-Za-z_$][\w$]*(?:\s*[+.]|\s*\[))''')
CLIENT_PASSWORD_ASSIGNMENT = re.compile(
    r'''\b(?:password|passwd|adminpassword|pw|pwd)\b\s*(?:={1,3}|:)\s*["'][^"'\r\n]{4,}["']''', re.I)
CLIENT_PASSWORD_COMPARISON = re.compile(
    r'''(?:\b(?:password|passwd|adminpassword|pw|pwd)\b\s*(?:={2,3}|!={1,2})\s*["'][^"'\r\n]{4,}["']|["'][^"'\r\n]{4,}["']\s*(?:={2,3}|!={1,2})\s*\b(?:password|passwd|adminpassword|pw|pwd)\b)''', re.I)


def is_filled(value):
    """Zero and false are real values, not missing data."""
    return value is not None and value != "" and value != [] and value != {}


def _bounded_json(text):
    """Use an explicit depth limit independent of interpreter recursion limits."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON depth limit exceeded")
        elif char in "]}":
            depth -= 1
    return json.loads(text)


def summarize_fields(value, *, node_limit=2048):
    counts = {"known_sensitive_fields": 0, "filled_sensitive_fields": 0,
              "nodes_examined": 0, "truncated": False}
    queue = [value]
    while queue and counts["nodes_examined"] < node_limit:
        item = queue.pop()
        counts["nodes_examined"] += 1
        if isinstance(item, dict):
            for key, val in item.items():
                if str(key).casefold() in SENSITIVE_FIELDS:
                    counts["known_sensitive_fields"] += 1
                    if is_filled(val):
                        counts["filled_sensitive_fields"] += 1
                if isinstance(val, (dict, list)):
                    queue.append(val)
        elif isinstance(item, list):
            queue.extend(item[:node_limit])
        if len(queue) > node_limit:
            del queue[node_limit:]
            counts["truncated"] = True
    counts["truncated"] |= bool(queue)
    return counts


class _HTMLSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.password_inputs = 0
        self.scripts = 0
        self.links = []
        self.json_depth = False
        self.json_chunks = []
        self.script_depth = False
        self.script_chunks = []
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "hidden" in a or re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", a.get("style") or "", re.I):
            self.hidden += 1
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_inputs += 1
        if tag == "script":
            self.scripts += 1
            self.script_depth = True
            self.json_depth = (a.get("type") or "").lower() in ("application/json", "application/ld+json")
        attr = "src" if tag in ("script", "iframe") else "href" if tag in ("a", "link") else None
        if attr and a.get(attr) and len(self.links) < MAX_LINKS:
            self.links.append((tag, a[attr]))

    def handle_endtag(self, tag):
        if tag == "script":
            self.script_depth = False
            self.json_depth = False

    def handle_data(self, data):
        if self.json_depth:
            if len(self.json_chunks) < 16:
                self.json_chunks.append(data)
            else:
                self.truncated = True
        elif self.script_depth:
            if len(self.script_chunks) < 16:
                self.script_chunks.append(data)
            else:
                self.truncated = True


@dataclass
class Analysis:
    report: dict
    # Transient locators for policy evaluation only; never JSON-dump this object.
    links: list[tuple[str, str]]


def analyze(body: bytes, content_type="", base_url="", *, synthetic_markers=()) -> Analysis:
    truncated = len(body) > MAX_ANALYSIS_BYTES
    text = body[:MAX_ANALYSIS_BYTES].decode("utf-8", errors="replace")
    signals = []
    links = []

    def signal(code, **details):
        if len(signals) < MAX_SIGNALS and not any(x["code"] == code for x in signals):
            signals.append({"code": code, **details})

    for name, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            signal(name, offset=match.start(), validity="not_tested")
    # Already delivered plaintext in tables/JS also matters, not just JSON.
    # Public contacts and demo data may match; these remain provisional signals.
    for code, pattern in (
        ("EMAIL_VALUE_CANDIDATE", r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"),
        ("KR_PHONE_VALUE_CANDIDATE", r"(?<!\d)01[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)"),
        ("KR_RESIDENT_VALUE_CANDIDATE", r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[ -]?[1-8]\d{6}(?!\d)"),
    ):
        if re.search(pattern, text):
            signal(code, confidence="heuristic")
    if "sb_publishable_" in text:
        signal("PUBLISHABLE_KEY_PRESENT", validity="public_identifier_not_secret")
    if re.search(r"(?:ignore (?:all |previous )?instructions|system prompt|send .*token|reveal .*secret)", text, re.I):
        signal("UNTRUSTED_INSTRUCTION_TEXT")
    if re.search(r"(?:staticrypt|crypto\.subtle\.decrypt|AES\.decrypt)", text, re.I):
        signal("CLIENT_ENCRYPTION_INDICATOR", confidence="heuristic")
    for marker in synthetic_markers:
        if marker and marker.startswith("SU_DETECT_SYNTHETIC_") and marker in text:
            signal("SYNTHETIC_CANARY_PRESENT", marker_digest=hashlib.sha256(marker.encode()).hexdigest())

    stats = {"hidden_elements": 0, "password_inputs": 0, "script_elements": 0}
    json_values = []
    script_texts = [text] if "javascript" in content_type.lower() else []
    stripped = text.lstrip()
    if "json" in content_type.lower() or stripped.startswith(("{", "[")):
        try:
            json_values.append(_bounded_json(text))
        except (ValueError, RecursionError):
            signal("JSON_PARSE_INCOMPLETE")
            truncated = True
    if "html" in content_type.lower() or re.search(r"<(?:html|input|script|div|section)\b", text, re.I):
        parser = _HTMLSignals()
        try:
            parser.feed(text)
            truncated |= parser.truncated
            if parser.truncated:
                signal("HTML_PARSE_INCOMPLETE")
            stats = {"hidden_elements": parser.hidden, "password_inputs": parser.password_inputs,
                     "script_elements": parser.scripts}
            links.extend(parser.links)
            script_texts.extend(parser.script_chunks)
            for chunk in parser.json_chunks:
                try:
                    json_values.append(_bounded_json(chunk))
                except (ValueError, RecursionError):
                    signal("JSON_PARSE_INCOMPLETE")
                    truncated = True
        except (ValueError, RecursionError):
            signal("HTML_PARSE_INCOMPLETE")
            truncated = True
    # A login form or request only describes an authentication flow.  A client-side
    # literal comparison is a separate, still-provisional structure signal.  Limit
    # it to JavaScript so page copy and CSS custom properties cannot imitate code.
    if any(CLIENT_PASSWORD_ASSIGNMENT.search(chunk) or CLIENT_PASSWORD_COMPARISON.search(chunk)
           for chunk in script_texts):
        signal("CLIENT_PASSWORD_CANDIDATE", validity="not_tested")
    for value in json_values:
        summary = summarize_fields(value)
        if summary["known_sensitive_fields"]:
            signal("SENSITIVE_FIELD_NAMES", count=summary["known_sensitive_fields"])
        if summary["filled_sensitive_fields"]:
            signal("SENSITIVE_VALUES_CANDIDATE", count=summary["filled_sensitive_fields"])
        if summary["truncated"]:
            truncated = True
    if stats["hidden_elements"]:
        signal("HIDDEN_DOM_PRESENT", count=stats["hidden_elements"])
    if stats["password_inputs"]:
        signal("LOGIN_FORM_INDICATOR", count=stats["password_inputs"], publication_intent="unknown")
    for match in FETCH_LITERAL.finditer(text):
        if len(links) < MAX_LINKS:
            links.append(("fetch_literal", match.group(1)))
    if any(kind == "fetch_literal" for kind, _ in links):
        signal("RUNTIME_ENDPOINT_CANDIDATE")
    if any(FETCH_DYNAMIC.search(chunk) for chunk in script_texts):
        # The source establishes that runtime routing exists, but interpolation
        # means no endpoint can be safely or accurately reconstructed here.
        signal("RUNTIME_ENDPOINT_UNRESOLVED")
    unique = []
    for kind, locator in links:
        try:
            full = urljoin(base_url, locator)
            if urlsplit(full).scheme in ("http", "https") and (kind, full) not in unique:
                unique.append((kind, full))
        except ValueError:
            signal("INVALID_LINK")
    codes = {s["code"] for s in signals}
    sensitive = any(code.endswith("_CANDIDATE") and code != "RUNTIME_ENDPOINT_CANDIDATE" for code in codes)
    content = "SENSITIVE_CANDIDATE" if sensitive else "NOT_INSPECTED"
    if "SYNTHETIC_CANARY_PRESENT" in codes:
        content = "SYNTHETIC_CONTENT_CONFIRMED"
    if re.search(r"(?:just a moment|verify you are human|security checkpoint|captcha)", text, re.I):
        signal("CHALLENGE_PAGE_INDICATOR")
    return Analysis({"classifier_version": "2.0.0", "content": content, "signals": signals,
                     "structure": stats, "analysis_complete": not truncated,
                     "linked_candidates": len(unique), "automated_sensitivity_is_provisional": True}, unique)


def main(argv=None):
    p = argparse.ArgumentParser(description="Analyze an authorized local file; emits signals only, never original values.")
    p.add_argument("path")
    p.add_argument("--content-type", default="")
    args = p.parse_args(argv)
    try:
        with Path(args.path).open("rb") as stream:
            body = stream.read(MAX_ANALYSIS_BYTES + 1)
        print(json.dumps(analyze(body, args.content_type).report, ensure_ascii=True))
        return 0
    except OSError:
        print(json.dumps({"error": "local_input_unavailable"}))
        return 2
