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
DEFAULT_STREAM_BYTES = 4 * 1024 * 1024
MAX_STRUCTURE_BYTES = 4 * 1024 * 1024
EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
PHONE = re.compile(r"(?<!\d)01[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)")
RESIDENT = re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[ -]?[1-8]\d{6}(?!\d)")
PLATE = re.compile(r"(?<![\w가-힣])(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)?\s?\d{2,3}[가-힣]\s?\d{4}(?!\d)")
BUSINESS_NUMBER = re.compile(r"(?<!\d)\d{3}[- ]?\d{2}[- ]?\d{5}(?!\d)")
CONFIDENTIAL = re.compile(r"(?:대외비|본사용|외부\s*공유\s*불가|confidential|internal\s+use\s+only)", re.I)
NEGATED_CONFIDENTIAL = re.compile(r"(?:대외비\s*(?:아님|해제|표시가?\s*없)|외부\s*공유\s*(?:가능|허용)|not\s+confidential)", re.I)
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
                    if is_filled(val) and not _is_example(val):
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
        self.style_depth = 0
        self.hidden_depth = 0
        self.visible_chunks = []
        self.hidden_chunks = []
        self.input_values = []
        self._stack = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        hidden = "hidden" in a or re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", a.get("style") or "", re.I) is not None
        if tag not in {"input", "img", "meta", "link", "br", "hr", "source", "area"}:
            self._stack.append((tag, hidden))
        if hidden:
            self.hidden += 1
            if tag not in {"input", "img", "meta", "link", "br", "hr", "source", "area"}:
                self.hidden_depth += 1
        if tag == "style": self.style_depth += 1
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_inputs += 1
        if tag == "input" and a.get("value") is not None and len(self.input_values) < 128:
            self.input_values.append(a["value"])
        if tag == "script":
            self.scripts += 1
            self.script_depth = True
            self.json_depth = (a.get("type") or "").lower() in ("application/json", "application/ld+json")
        attr = "src" if tag in ("script", "iframe") else "href" if tag in ("a", "link") else None
        if attr and a.get(attr) and len(self.links) < MAX_LINKS:
            self.links.append((tag, a[attr]))

    def handle_endtag(self, tag):
        if tag == "style" and self.style_depth: self.style_depth -= 1
        if tag == "script":
            self.script_depth = False
            self.json_depth = False
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                self.hidden_depth -= sum(hidden for _, hidden in self._stack[index:])
                del self._stack[index:]
                break

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
        elif not self.style_depth:
            target = self.hidden_chunks if self.hidden_depth else self.visible_chunks
            if len(target) < 4096: target.append(data)
            else: self.truncated = True


@dataclass
class Analysis:
    report: dict
    # Transient locators for policy evaluation only; never JSON-dump this object.
    links: list[tuple[str, str]]


def _valid_business_number(value: str) -> bool:
    digits = [int(x) for x in re.sub(r"\D", "", value)]
    if len(digits) != 10 or len(set(digits)) == 1: return False
    weights = (1, 3, 7, 1, 3, 7, 1, 3, 5)
    weighted = sum(a * b for a, b in zip(digits[:9], weights))
    return (10 - (weighted + digits[8] * 5 // 10) % 10) % 10 == digits[9]


def _is_example(value: object) -> bool:
    if not isinstance(value, str): return False
    return bool(re.fullmatch(r"\s*(?:example|sample|placeholder|dummy|test|예시|샘플|입력|미정|[-_]+|\{\{.*\}\}|\$\{.*\})\s*", value, re.I))


def analyze(body: bytes, content_type="", base_url="", *, synthetic_markers=(),
            max_bytes: int = MAX_ANALYSIS_BYTES, capture_complete: bool = True) -> Analysis:
    from .asset_profile import profile_content
    if max_bytes < 1 or max_bytes > 32 * 1024 * 1024: raise ValueError("invalid analysis byte limit")
    examined = body[:max_bytes]
    asset_profile = profile_content(examined, content_type, max_bytes=max_bytes)
    truncated = len(body) > max_bytes or not capture_complete
    text = examined.decode("utf-8", errors="replace")
    signals = []
    links = []

    def signal(code, **details):
        if len(signals) < MAX_SIGNALS and not any(x["code"] == code for x in signals):
            signals.append({"code": code, **details})

    if not asset_profile["static_json_literals"]["analysis_complete"]:
        signal("STRUCTURED_DATA_PARSE_INCOMPLETE")

    for name, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            signal(name, offset=match.start(), validity="not_tested")
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
    visible_text = text
    hidden_text = ""
    input_text = ""
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
            visible_text = " ".join(parser.visible_chunks)
            hidden_text = " ".join(parser.hidden_chunks)
            input_text = " ".join(parser.input_values)
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
    ctype = content_type.casefold()
    # CSS and URL attributes are excluded from value matching. JSON values are
    # handled separately; JS source only contributes explicit secret patterns.
    value_text = "" if "css" in ctype or "javascript" in ctype else (visible_text + " " + hidden_text + " " + input_text)
    if "json" in ctype or json_values:
        strings = []
        queue = list(json_values)
        visited = 0
        while queue and visited < 2048:
            item = queue.pop(); visited += 1
            if isinstance(item, dict): queue.extend(item.values())
            elif isinstance(item, list): queue.extend(item)
            elif isinstance(item, str) and not _is_example(item) and not re.match(r"^[a-z]+://", item, re.I):
                strings.append(item)
            if len(queue) > 2048: queue = queue[:2048]; truncated = True
        value_text = (" " if "json" in ctype else value_text + " ") + " ".join(strings)
    for code, pattern in (("EMAIL_VALUE_CANDIDATE", EMAIL), ("KR_PHONE_VALUE_CANDIDATE", PHONE),
                          ("KR_RESIDENT_VALUE_CANDIDATE", RESIDENT), ("KR_VEHICLE_PLATE_CANDIDATE", PLATE)):
        matches = list(pattern.finditer(value_text))
        if matches:
            signal(code, confidence="heuristic", occurrences=len(matches),
                   unique_values=len({m.group() for m in matches}), records=None, assets=None)
    business = [m for m in BUSINESS_NUMBER.finditer(value_text) if _valid_business_number(m.group())]
    if business:
        signal("KR_BUSINESS_NUMBER_CANDIDATE", confidence="format_validated", occurrences=len(business),
               unique_values=len({m.group() for m in business}), records=None, assets=None,
               personal_information="not_inferred")
    for region, content in (("visible_body", visible_text), ("hidden_body", hidden_text)):
        if CONFIDENTIAL.search(content):
            signal("CONFIDENTIAL_MARKER_CANDIDATE", location=region, target_region=region,
                   negated=bool(NEGATED_CONFIDENTIAL.search(content)), confidence="medium")
    for table in asset_profile.get("structured_tables", []):
        signal(table["reason_code"], category=table["category"], confidence=table["confidence"],
               value_state=table["value_state"], records=table["filled_records"], assets=None)
    filled_business = sum(
        category["filled_field_count"]
        for category in asset_profile["business_data_categories"]
        if category["category"] in {"pricing", "margin", "customer_contact", "contract_vehicle_record",
                                     "commission_settlement", "partner"}
        and set(category["evidence_bases"]) & {"structured_field_names", "static_js_json_literal"}
    )
    if filled_business:
        signal("BUSINESS_DATA_VALUE_CANDIDATE", count=filled_business, confidence="structural",
               records=None, assets=None)
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
        queue = [value]
        examined_nodes = 0
        contact_count = list_count = record_count = 0
        while queue and examined_nodes < 2048:
            node = queue.pop(); examined_nodes += 1
            if isinstance(node, dict):
                keys = {str(key).casefold() for key in node}
                if keys & {"customer_name", "customername", "client_name", "고객명", "employee_name"} and any(is_filled(v) and not _is_example(v) for v in node.values()):
                    record_count += 1
                for key, val in node.items():
                    key_name = str(key).casefold()
                    if key_name in {"email", "phone", "mobile", "telephone", "contact", "이메일", "전화번호"} and is_filled(val) and not _is_example(val): contact_count += 1
                    if key_name in {"customers", "clients", "employees", "고객명단", "고객목록"} and isinstance(val, list) and val: list_count += 1
                    if isinstance(val, (dict, list)): queue.append(val)
            elif isinstance(node, list): queue.extend(x for x in node if isinstance(x, (dict, list)))
            if len(queue) > 2048: queue = queue[:2048]; truncated = True
        if contact_count: signal("CONTACT_VALUE_CANDIDATE", occurrences=contact_count, records=None, assets=None, confidence="medium")
        if list_count: signal("PERSON_LIST_CANDIDATE", occurrences=list_count, records=record_count or None, assets=None, confidence="medium")
        if record_count: signal("CUSTOMER_RECORD_CANDIDATE", occurrences=record_count, records=record_count, assets=None, confidence="medium")
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
    complete = not truncated and asset_profile["analysis_complete"]
    gaps = []
    if not capture_complete: gaps.append("capture_incomplete")
    if len(body) > max_bytes: gaps.append("analysis_byte_limit")
    if not asset_profile["structure_analysis_complete"]: gaps.append("structure_parse_incomplete")
    image_pending = bool(re.search(r"(?:<img\b|data:image/|base64,)", text, re.I))
    if image_pending: gaps.append("image_or_base64_review")
    return Analysis({"classifier_version": "2.1.0", "content": content, "signals": signals,
                     "structure": stats, "analysis_complete": complete,
                     "capture_input_complete": bool(capture_complete), "text_analysis_complete": not truncated,
                     "structure_analysis_complete": asset_profile["structure_analysis_complete"] and not truncated,
                     "image_review_complete": "not_applicable" if not image_pending else False,
                     "pending_reviews": gaps,
                     "bytes_examined": len(examined), "bytes_supplied": len(body),
                     "linked_candidates": len(unique), "automated_sensitivity_is_provisional": True,
                     "asset_profile": asset_profile}, unique)


def analyze_stream(chunks, content_type="", base_url="", *, max_bytes: int = DEFAULT_STREAM_BYTES,
                   capture_complete: bool = True, synthetic_markers=()) -> Analysis:
    """Analyze a bounded byte stream with explicit partial coverage.

    The caller owns network and capture budgets. The stream is consumed once;
    one byte beyond the analysis budget establishes a partial result.
    """
    if max_bytes < 1 or max_bytes > 32 * 1024 * 1024: raise ValueError("invalid analysis byte limit")
    buffered = bytearray()
    over_limit = False
    for chunk in chunks:
        if not isinstance(chunk, bytes): raise TypeError("stream chunks must be bytes")
        remaining = max_bytes + 1 - len(buffered)
        if remaining > 0: buffered.extend(chunk[:remaining])
        if len(chunk) > remaining or len(buffered) > max_bytes:
            over_limit = True
            break
    result = analyze(bytes(buffered), content_type, base_url, synthetic_markers=synthetic_markers,
                     max_bytes=max_bytes, capture_complete=capture_complete and not over_limit)
    result.report["stream_limit_reached"] = over_limit
    if over_limit and "analysis_byte_limit" not in result.report["pending_reviews"]:
        result.report["pending_reviews"].append("analysis_byte_limit")
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Analyze an authorized local file; emits signals only, never original values.")
    p.add_argument("path")
    p.add_argument("--content-type", default="")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_STREAM_BYTES)
    args = p.parse_args(argv)
    try:
        with Path(args.path).open("rb") as stream:
            chunks = iter(lambda: stream.read(65536), b"")
            report = analyze_stream(chunks, args.content_type, max_bytes=args.max_bytes).report
        print(json.dumps(report, ensure_ascii=True))
        return 0
    except (OSError, ValueError):
        print(json.dumps({"error": "local_input_unavailable"}))
        return 2
