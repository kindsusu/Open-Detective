"""Bounded, value-free inspection of JSON literals in JavaScript assignments."""
from __future__ import annotations

from html.parser import HTMLParser
import json
import re
from typing import Any

MAX_LITERALS = 64
MAX_INPUT_CHARS = 4 * 1024 * 1024
MAX_LITERAL_CHARS = 2 * 1024 * 1024
MAX_NODES = 10_000
MAX_DEPTH = 128

_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_ASSIGN_HEAD = re.compile(r"\s+[A-Za-z_$][\w$]*\s*=\s*")
_PLACEHOLDER = re.compile(r"\s*(?:|[-—_]+|n/?a|null|undefined|example|sample|placeholder|dummy|test|예시|샘플|미정|입력|\{\{.*\}\}|\$\{.*\})\s*", re.I | re.S)
_CALCULATION = re.compile(r"^\s*(?:=|(?:calc\s*\())|\b(?:Math\.|function\s*\(|=>)\b", re.I)


def _category(key: str) -> str | None:
    words = re.sub(r"([a-z])([A-Z])", r"\1_\2", key).casefold().replace("-", "_")
    words = set(re.findall(r"[a-z]+|[가-힣]+", words))
    if words & {"margin", "cost", "cogs", "markup", "원가", "마진"}:
        return "margin"
    if words & {"price", "pricing", "rate", "rates", "rent", "rental", "lease", "discount", "fare", "fee", "요금", "가격", "렌트료", "할인", "리스료"}:
        return "pricing"
    if words & {"customer", "client", "email", "phone", "telephone", "mobile", "contact", "고객", "이메일", "전화번호", "휴대폰"}:
        return "customer_contact"
    if words & {"vehicle", "car", "vin", "plate", "차량", "차종", "차량번호"}:
        return "contract_vehicle_record"
    if words & {"commission", "settlement", "수수료", "정산"}:
        return "commission_settlement"
    if words & {"partner", "vendor", "affiliate", "파트너", "협력"}:
        return "partner"
    if words & {"revenue", "profit", "invoice", "balance", "expense", "budget", "매출", "수익", "예산"}:
        return "financial"
    return None


def _value_state(value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return "field_name_only"
    if isinstance(value, (dict, list)):
        return "field_name_only"
    if isinstance(value, str):
        if _PLACEHOLDER.fullmatch(value):
            return "template"
        if _CALCULATION.search(value):
            return "calculation"
    return "value"


def _skip_string(source: str, pos: int) -> tuple[int, bool]:
    quote = source[pos]
    pos += 1
    while pos < len(source):
        if source[pos] == "\\":
            pos += 2
        elif source[pos] == quote:
            return pos + 1, True
        else:
            pos += 1
    return len(source), False


def _literal_end(source: str, start: int) -> tuple[int, bool]:
    stack: list[str] = []
    pos = start
    while pos < len(source) and pos - start <= MAX_LITERAL_CHARS:
        char = source[pos]
        if char == '"':
            pos, closed = _skip_string(source, pos)
            if not closed or pos - start > MAX_LITERAL_CHARS:
                return pos, False
            continue
        if char in "[{":
            stack.append(char)
            if len(stack) > MAX_DEPTH:
                return pos, False
        elif char in "]}":
            if not stack or (stack.pop(), char) not in {("[", "]"), ("{", "}")}:
                return pos, False
            if not stack:
                return pos + 1, pos + 1 - start <= MAX_LITERAL_CHARS
        pos += 1
    return pos, False


def _summarize(value: Any) -> tuple[dict[str, dict[str, int]], int, bool]:
    counts: dict[str, dict[str, int]] = {}
    root_items = len(value) if isinstance(value, list) else 1
    # Exit frames let each container inherit the strongest state of its
    # descendants without repeatedly walking nested rate/record arrays.
    stack = [(value, 0, False)]
    states: dict[int, str] = {}
    visited = 0
    priority = {"field_name_only": 0, "template": 1, "calculation": 2, "value": 3}
    while stack:
        item, depth, exiting = stack.pop()
        if depth > MAX_DEPTH:
            return {}, root_items, False
        if not exiting:
            visited += 1
            if visited > MAX_NODES:
                return {}, root_items, False
            if isinstance(item, (dict, list)):
                stack.append((item, depth, True))
                children = item.values() if isinstance(item, dict) else item
                if len(stack) + len(children) > MAX_NODES * 2:
                    return {}, root_items, False
                stack.extend((child, depth + 1, False) for child in children)
            continue
        children = item.values() if isinstance(item, dict) else item
        state = "field_name_only"
        for child in children:
            child_state = states[id(child)] if isinstance(child, (dict, list)) else _value_state(child)
            if priority[child_state] > priority[state]:
                state = child_state
        states[id(item)] = state
        if isinstance(item, dict):
            for key, child in item.items():
                category = _category(str(key))
                if category is None:
                    continue
                row = counts.setdefault(category, {"candidate_count": 0, "filled_field_count": 0,
                                                   "template_count": 0, "calculation_count": 0})
                row["candidate_count"] += 1
                child_state = states[id(child)] if isinstance(child, (dict, list)) else _value_state(child)
                if child_state == "value": row["filled_field_count"] += 1
                elif child_state == "template": row["template_count"] += 1
                elif child_state == "calculation": row["calculation_count"] += 1
        if len(states) > MAX_NODES:
            return {}, root_items, False
    return counts, root_items, True


def _scan_js(source: str) -> tuple[list[Any], bool]:
    values: list[Any] = []
    complete = True
    pos = 0
    while pos < len(source):
        char = source[pos]
        if char in "\"'`":
            pos, closed = _skip_string(source, pos)
            complete &= closed
            continue
        if source.startswith("//", pos):
            end = source.find("\n", pos + 2)
            pos = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                return values, False
            pos = end + 2
            continue
        match = _IDENT.match(source, pos)
        if not match:
            pos += 1
            continue
        token = match.group()
        pos = match.end()
        if token not in {"const", "let", "var"}:
            continue
        head = _ASSIGN_HEAD.match(source, pos)
        if not head:
            continue
        start = head.end()
        if start >= len(source) or source[start] not in "[{":
            continue
        end, closed = _literal_end(source, start)
        if not closed:
            return values, False
        candidate = source[start:end]
        try:
            value = json.loads(candidate)
        except (ValueError, RecursionError):
            # A JavaScript object is not necessarily JSON; later literals remain eligible.
            if re.match(r'\{\s*"|\[\s*(?:\{|"|-?\d|true\b|false\b|null\b)', candidate):
                complete = False
            pos = end
            continue
        values.append(value)
        if len(values) >= MAX_LITERALS:
            complete = False
            break
        pos = end
    return values, complete


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.active = False
        self.js = False
        self.parts: list[str] = []
        self.scripts: list[str] = []
        self.complete = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.active = True
            kind = (dict(attrs).get("type") or "").casefold()
            self.js = kind in {"", "text/javascript", "application/javascript", "module"}
            self.parts = []

    def handle_data(self, data: str) -> None:
        if self.active and self.js:
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self.active:
            if self.js:
                if len(self.scripts) < MAX_LITERALS: self.scripts.append("".join(self.parts))
                else: self.complete = False
            self.active = False
            self.parts = []


def inspect_static_json(text: str, content_type: str) -> dict[str, Any]:
    """Inspect already captured HTML/JS; return bounded counts and no source values."""
    input_complete = len(text) <= MAX_INPUT_CHARS
    text = text[:MAX_INPUT_CHARS]
    ctype = content_type.casefold()
    if "html" in ctype or re.search(r"<script\b", text, re.I):
        parser = _Scripts()
        parser.feed(text)
        sources = parser.scripts
        complete = input_complete and parser.complete and not parser.active
    elif "javascript" in ctype or "typescript" in ctype:
        sources, complete = [text], input_complete
    else:
        sources, complete = [], input_complete
    totals: dict[str, dict[str, int]] = {}
    roots = literals = 0
    for source in sources:
        found, scanned = _scan_js(source)
        complete &= scanned
        for value in found:
            counted, items, bounded = _summarize(value)
            complete &= bounded
            if not bounded: continue
            literals += 1
            roots += items
            for category, row in counted.items():
                target = totals.setdefault(category, {key: 0 for key in row})
                for key, number in row.items(): target[key] += number
    return {"literal_count": literals, "root_item_count": roots, "categories": totals,
            "analysis_complete": complete}
