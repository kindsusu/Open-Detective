"""Bounded, value-free inspection of JSON literals in JavaScript assignments."""
from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any

from .js_literals import LiteralError, parse_static_literal
from .strict_json import loads as strict_json_loads

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


def _literal_end(source: str, start: int) -> tuple[int, bool, str | None]:
    stack: list[str] = []
    pos = start
    while pos < len(source) and pos - start <= MAX_LITERAL_CHARS:
        char = source[pos]
        if char in "\"'":
            pos, closed = _skip_string(source, pos)
            if not closed or pos - start > MAX_LITERAL_CHARS:
                return pos, False, "js_literal_limit" if pos - start > MAX_LITERAL_CHARS else "js_malformed_literal"
            continue
        if source.startswith("//", pos):
            end = source.find("\n", pos + 2)
            pos = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                return len(source), False, "js_malformed_literal"
            pos = end + 2
            continue
        if char in "[{":
            stack.append(char)
            if len(stack) > MAX_DEPTH:
                return pos, False, "js_literal_limit"
        elif char in "]}":
            if not stack or (stack.pop(), char) not in {("[", "]"), ("{", "}")}:
                return pos, False, "js_malformed_literal"
            if not stack:
                bounded = pos + 1 - start <= MAX_LITERAL_CHARS
                return pos + 1, bounded, None if bounded else "js_literal_limit"
        pos += 1
    return pos, False, "js_literal_limit" if pos - start > MAX_LITERAL_CHARS else "js_malformed_literal"


def _skip_regex(source: str, pos: int) -> tuple[int, bool]:
    """Skip one regex token in a position where a regex literal can start."""
    pos += 1
    character_class = False
    while pos < len(source):
        char = source[pos]
        if char in "\r\n":
            return pos, False
        if char == "\\":
            pos += 2
            continue
        if char == "[":
            character_class = True
        elif char == "]":
            character_class = False
        elif char == "/" and not character_class:
            pos += 1
            while pos < len(source) and (source[pos].isalpha() or source[pos] == "$" or source[pos] == "_"):
                pos += 1
            return pos, True
        pos += 1
    return pos, False


def _suffix_is_dynamic(source: str, end: int) -> bool:
    """A literal followed by an operator is an expression, not its final value."""
    pos = end
    saw_line_break = False
    while pos < len(source):
        if source[pos].isspace():
            saw_line_break |= source[pos] in "\r\n"
            pos += 1
        elif source.startswith("//", pos):
            line_end = source.find("\n", pos + 2)
            if line_end < 0:
                return False
            pos = line_end + 1
            saw_line_break = True
        elif source.startswith("/*", pos):
            comment_end = source.find("*/", pos + 2)
            if comment_end < 0:
                return True
            saw_line_break |= "\n" in source[pos:comment_end]
            pos = comment_end + 2
        else:
            break
    if pos >= len(source):
        return False
    if source[pos] in ".[(+-*/%?=|&^<>!,:`":
        return True
    match = _IDENT.match(source, pos)
    if match:
        return not saw_line_break or match.group() in {"as", "satisfies", "in", "instanceof"}
    return source[pos] not in ";}"


def _skip_space_comments(source: str, pos: int) -> int:
    while pos < len(source):
        if source[pos].isspace():
            pos += 1
        elif source.startswith("//", pos):
            end = source.find("\n", pos + 2)
            pos = len(source) if end < 0 else end + 1
        elif source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                return len(source)
            pos = end + 2
        else:
            break
    return pos


def _unsupported_assignment_literal(source: str, token_end: int) -> bool:
    """Recognize unparsed assignment targets without interpreting their value."""
    pos = token_end
    for _ in range(32):
        pos = _skip_space_comments(source, pos)
        if pos < len(source) and source[pos] == ".":
            pos = _skip_space_comments(source, pos + 1)
            segment = _IDENT.match(source, pos)
            if segment is None:
                return False
            pos = segment.end()
            continue
        if pos < len(source) and source[pos] == "[":
            pos = _skip_space_comments(source, pos + 1)
            if pos >= len(source) or source[pos] not in "\"'":
                return False
            pos, closed = _skip_string(source, pos)
            if not closed:
                return False
            pos = _skip_space_comments(source, pos)
            if pos >= len(source) or source[pos] != "]":
                return False
            pos += 1
            continue
        break
    pos = _skip_space_comments(source, pos)
    if pos >= len(source) or source[pos] != "=" or source[pos:pos + 2] in {"==", "=>"}:
        return False
    pos = _skip_space_comments(source, pos + 1)
    return pos < len(source) and source[pos] in "[{"


def _export_default_literal(source: str, token_end: int) -> bool:
    pos = _skip_space_comments(source, token_end)
    word = _IDENT.match(source, pos)
    if word is None or word.group() != "default":
        return False
    pos = _skip_space_comments(source, word.end())
    return pos < len(source) and source[pos] in "[{"


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


def _scan_js(source: str) -> tuple[list[Any], set[str]]:
    values: list[Any] = []
    reasons: set[str] = set()
    pos = 0
    while pos < len(source):
        char = source[pos]
        if char in "\"'`":
            pos, closed = _skip_string(source, pos)
            if not closed:
                reasons.add("js_malformed_literal")
            continue
        if source.startswith("//", pos):
            end = source.find("\n", pos + 2)
            pos = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                reasons.add("js_malformed_literal")
                return values, reasons
            pos = end + 2
            continue
        if char == "/":
            previous_pos = pos - 1
            while previous_pos >= 0 and source[previous_pos].isspace():
                previous_pos -= 1
            previous = source[previous_pos] if previous_pos >= 0 else ""
            word_start = previous_pos
            while word_start >= 0 and (source[word_start].isalnum() or source[word_start] in "_$"):
                word_start -= 1
            previous_word = source[word_start + 1:previous_pos + 1]
            if (previous in {"", "=", "(", "[", "{", ",", ":", ";", "!", "?"}
                    or previous_word in {"return", "throw", "case", "yield", "await"}):
                pos, closed = _skip_regex(source, pos)
                if not closed:
                    reasons.add("js_lexical_incomplete")
                continue
        match = _IDENT.match(source, pos)
        if not match:
            pos += 1
            continue
        token = match.group()
        pos = match.end()
        if token not in {"const", "let", "var"}:
            if ((token == "export" and _export_default_literal(source, pos))
                    or _unsupported_assignment_literal(source, pos)):
                reasons.add("js_unsupported_assignment")
            continue
        head = _ASSIGN_HEAD.match(source, pos)
        if not head:
            continue
        start = head.end()
        if start >= len(source) or source[start] not in "[{":
            continue
        end, closed, reason = _literal_end(source, start)
        if not closed:
            reasons.add(reason or "js_malformed_literal")
            return values, reasons
        candidate = source[start:end]
        try:
            value = strict_json_loads(candidate)
        except (ValueError, RecursionError):
            try:
                value = parse_static_literal(candidate, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)
            except LiteralError as exc:
                reasons.add(exc.reason)
                pos = end
                continue
        if _suffix_is_dynamic(source, end):
            reasons.add("js_unsupported_dynamic_expression")
            pos = end
            continue
        values.append(value)
        if len(values) >= MAX_LITERALS:
            reasons.add("js_literal_limit")
            break
        pos = end
    return values, reasons


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.active = False
        self.js = False
        self.json_script = False
        self.parts: list[str] = []
        self.scripts: list[str] = []
        self.json_scripts: list[str] = []
        self.complete = True
        self.limit_reached = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.active = True
            kind = (dict(attrs).get("type") or "").casefold()
            self.js = kind in {"", "text/javascript", "application/javascript", "module"}
            self.json_script = kind in {"application/json", "application/ld+json"}
            self.parts = []

    def handle_data(self, data: str) -> None:
        if self.active and (self.js or self.json_script):
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self.active:
            if self.js:
                if len(self.scripts) < MAX_LITERALS: self.scripts.append("".join(self.parts))
                else:
                    self.complete = False
                    self.limit_reached = True
            elif self.json_script:
                if len(self.json_scripts) < MAX_LITERALS: self.json_scripts.append("".join(self.parts))
                else:
                    self.complete = False
                    self.limit_reached = True
            self.active = False
            self.parts = []


def inspect_static_json(text: str, content_type: str) -> dict[str, Any]:
    """Inspect already captured HTML/JS; return bounded counts and no source values."""
    input_complete = len(text) <= MAX_INPUT_CHARS
    text = text[:MAX_INPUT_CHARS]
    ctype = content_type.casefold()
    reasons: set[str] = set()
    if not input_complete:
        reasons.add("analysis_input_limit")
    if "html" in ctype or re.search(r"<script\b", text, re.I):
        parser = _Scripts()
        parser.feed(text)
        sources = parser.scripts
        complete = input_complete and parser.complete and not parser.active
        if parser.limit_reached:
            reasons.add("html_script_limit")
        if parser.active:
            reasons.add("html_script_incomplete")
        for payload in parser.json_scripts:
            try:
                strict_json_loads(payload)
            except (ValueError, RecursionError):
                reasons.add("json_malformed")
    elif "javascript" in ctype or "typescript" in ctype:
        sources, complete = [text], input_complete
    elif "json" in ctype:
        sources, complete = [], input_complete
        try:
            strict_json_loads(text)
        except (ValueError, RecursionError):
            reasons.add("json_malformed")
            complete = False
    else:
        sources, complete = [], input_complete
    totals: dict[str, dict[str, int]] = {}
    roots = literals = 0
    for source in sources:
        found, scan_reasons = _scan_js(source)
        reasons.update(scan_reasons)
        complete &= not scan_reasons
        for value in found:
            counted, items, bounded = _summarize(value)
            complete &= bounded
            if not bounded:
                reasons.add("js_literal_limit")
                continue
            literals += 1
            roots += items
            for category, row in counted.items():
                target = totals.setdefault(category, {key: 0 for key in row})
                for key, number in row.items(): target[key] += number
    return {"literal_count": literals, "root_item_count": roots, "categories": totals,
            "analysis_complete": bool(complete and not reasons), "incomplete_reasons": sorted(reasons)}
