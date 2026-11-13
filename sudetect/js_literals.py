"""Small, bounded parser for data-only JavaScript object and array literals.

It never executes source. Expressions, calls, getters, spreads and template
strings are rejected, including when they appear inside an otherwise static
object. The caller still owns source size and source-location provenance.
"""
from __future__ import annotations

import re
import math


_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX = set("0123456789abcdefABCDEF")


class LiteralError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _Parser:
    def __init__(self, source: str, max_nodes: int, max_depth: int):
        self.source = source
        self.pos = 0
        self.nodes = 0
        self.max_nodes = max_nodes
        self.max_depth = max_depth

    def _skip(self) -> None:
        source = self.source
        while self.pos < len(source):
            if source[self.pos].isspace():
                self.pos += 1
            elif source.startswith("//", self.pos):
                end = source.find("\n", self.pos + 2)
                self.pos = len(source) if end < 0 else end + 1
            elif source.startswith("/*", self.pos):
                end = source.find("*/", self.pos + 2)
                if end < 0:
                    raise LiteralError("js_malformed_literal")
                self.pos = end + 2
            else:
                break

    def _take(self, expected: str) -> bool:
        self._skip()
        if self.source.startswith(expected, self.pos):
            self.pos += len(expected)
            return True
        return False

    def _string(self) -> str:
        source = self.source
        quote = source[self.pos]
        self.pos += 1
        out: list[str] = []
        escaped = {"0": "\0", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
        while self.pos < len(source):
            char = source[self.pos]
            self.pos += 1
            if char == quote:
                return "".join(out)
            if char in "\r\n":
                raise LiteralError("js_malformed_literal")
            if char != "\\":
                out.append(char)
                continue
            if self.pos >= len(source):
                raise LiteralError("js_malformed_literal")
            esc = source[self.pos]
            self.pos += 1
            if esc in "\"'\\/":
                out.append(esc)
            elif esc in escaped:
                out.append(escaped[esc])
            elif esc in "xu":
                count = 2 if esc == "x" else 4
                digits = source[self.pos:self.pos + count]
                if len(digits) != count or any(digit not in _HEX for digit in digits):
                    raise LiteralError("js_malformed_literal")
                self.pos += count
                out.append(chr(int(digits, 16)))
            elif esc == "\n":
                continue
            elif esc == "\r":
                if self.pos < len(source) and source[self.pos] == "\n":
                    self.pos += 1
            else:
                raise LiteralError("js_unsupported_syntax")
        raise LiteralError("js_malformed_literal")

    def _value(self, depth: int):
        if depth > self.max_depth:
            raise LiteralError("js_literal_limit")
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise LiteralError("js_literal_limit")
        self._skip()
        source = self.source
        if self.pos >= len(source):
            raise LiteralError("js_malformed_literal")
        char = source[self.pos]
        if char in "\"'":
            return self._string()
        if char == "`":
            raise LiteralError("js_unsupported_dynamic_expression")
        if char == "{":
            return self._object(depth)
        if char == "[":
            return self._array(depth)
        if char == "-" or char.isdigit():
            match = _NUMBER.match(source, self.pos)
            if match is None:
                raise LiteralError("js_malformed_literal")
            token = match.group()
            if len(token) > 128:
                raise LiteralError("js_literal_limit")
            self.pos = match.end()
            try:
                value = float(token) if any(char in token for char in ".eE") else int(token)
                if isinstance(value, float) and not math.isfinite(value):
                    raise LiteralError("js_nonfinite_number")
                return value
            except LiteralError:
                raise
            except (OverflowError, ValueError):
                raise LiteralError("js_literal_limit") from None
        match = _IDENT.match(source, self.pos)
        if match:
            self.pos = match.end()
            if match.group() in {"true", "false", "null"}:
                return {"true": True, "false": False, "null": None}[match.group()]
            raise LiteralError("js_unsupported_dynamic_expression")
        if source.startswith("...", self.pos) or char in "+!~(/":
            raise LiteralError("js_unsupported_dynamic_expression")
        raise LiteralError("js_malformed_literal")

    def _object(self, depth: int) -> dict:
        self.pos += 1
        result = {}
        if self._take("}"):
            return result
        while True:
            self._skip()
            if self.pos >= len(self.source):
                raise LiteralError("js_malformed_literal")
            if self.source.startswith("...", self.pos):
                raise LiteralError("js_unsupported_dynamic_expression")
            char = self.source[self.pos]
            if char in "\"'":
                key = self._string()
            else:
                match = _IDENT.match(self.source, self.pos)
                if not match:
                    raise LiteralError("js_unsupported_dynamic_expression" if char == "[" else "js_malformed_literal")
                key = match.group()
                self.pos = match.end()
            if not self._take(":"):
                raise LiteralError("js_unsupported_dynamic_expression")
            if key in result:
                raise LiteralError("js_duplicate_key")
            result[key] = self._value(depth + 1)
            if self._take("}"):
                return result
            if not self._take(","):
                self._skip()
                if self.pos < len(self.source) and self.source[self.pos] in "+-*/%?.([`":
                    raise LiteralError("js_unsupported_dynamic_expression")
                raise LiteralError("js_malformed_literal")
            if self._take("}"):
                return result

    def _array(self, depth: int) -> list:
        self.pos += 1
        result = []
        if self._take("]"):
            return result
        while True:
            result.append(self._value(depth + 1))
            if self._take("]"):
                return result
            if not self._take(","):
                self._skip()
                if self.pos < len(self.source) and self.source[self.pos] in "+-*/%?.([`":
                    raise LiteralError("js_unsupported_dynamic_expression")
                raise LiteralError("js_malformed_literal")
            if self._take("]"):
                return result


def parse_static_literal(source: str, *, max_nodes: int = 10_000,
                         max_depth: int = 128):
    """Return data-only value or raise LiteralError with a value-free reason."""
    if not isinstance(source, str) or len(source) > 2 * 1024 * 1024:
        raise LiteralError("js_literal_limit")
    if type(max_nodes) is not int or not 1 <= max_nodes <= 10_000:
        raise ValueError("invalid max_nodes")
    if type(max_depth) is not int or not 1 <= max_depth <= 128:
        raise ValueError("invalid max_depth")
    parser = _Parser(source, max_nodes, max_depth)
    value = parser._value(0)
    parser._skip()
    if parser.pos != len(source):
        raise LiteralError("js_unsupported_dynamic_expression")
    return value
