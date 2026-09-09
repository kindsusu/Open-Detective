"""Bounded anonymous GET tracing of static public script and fetch references."""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urljoin
import uuid

from .classifiers import analyze
from .evidence import clean_text, safe_url
from .locators import LocatorStore
from .policy import Budget, PolicyError, Scope
from .transport import fetch

MAX_DEPTH = 4
MAX_REQUESTS = 100
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_DURATION = 120.0
MAX_REFERENCES = 256
MAX_QUEUED_ASSETS = 1000

LIMITATIONS = [
    "static_script_src_and_literal_fetch_get_only",
    "no_dom_mutation_login_submission_clicking_or_credential_use",
    "no_dynamic_url_evaluation_or_url_guessing",
    "anonymous_get_is_not_authenticated_browser_equivalence",
    "unresolved_or_unobserved_content_never_establishes_absence",
]

_JS_TYPES = {
    "", "module", "text/javascript", "application/javascript",
    "text/ecmascript", "application/ecmascript",
}
_FETCH_SIMPLE = re.compile(
    r"fetch\s*\(\s*(['\"])([^'\"\\\r\n]{1,2048})\1\s*\)"
)
_FETCH_GET = re.compile(
    r"fetch\s*\(\s*(['\"])([^'\"\\\r\n]{1,2048})\1\s*,\s*"
    r"\{\s*method\s*:\s*(['\"])GET\3\s*\}\s*\)"
)


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.inline: list[str] = []
        self.unresolved: list[str] = []
        self.base_hrefs: list[str] = []
        self._capture = False
        self._chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() == "base":
            values = {str(k).casefold(): v for k, v in attrs}
            if values.get("href"):
                self.base_hrefs.append(values["href"])
            return
        if tag.casefold() != "script":
            return
        values = {str(k).casefold(): v for k, v in attrs}
        script_type = (values.get("type") or "").split(";", 1)[0].strip().casefold()
        executable = script_type in _JS_TYPES
        src = values.get("src")
        if executable and src and len(self.references) < MAX_REFERENCES:
            self.references.append(("script_src", src))
        elif executable and src:
            self.unresolved.append("reference_limit")
        self._capture = executable and not src
        self._chunks = []

    def handle_endtag(self, tag):
        if tag.casefold() == "script" and self._capture:
            self.inline.append("".join(self._chunks))
        if tag.casefold() == "script":
            self._capture = False
            self._chunks = []

    def handle_data(self, data):
        if self._capture:
            self._chunks.append(data)


def _fetch_positions(source: str):
    """Yield fetch call offsets only in executable code, outside strings/comments."""
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "line":
            if char in "\r\n":
                state = "code"
            i += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                state = "code"; i += 2
            else:
                i += 1
            continue
        if state == "string":
            if char == "\\":
                i += 2
            elif char == quote:
                state = "code"; i += 1
            else:
                i += 1
            continue
        if char == "/" and nxt == "/":
            state = "line"; i += 2; continue
        if char == "/" and nxt == "*":
            state = "block"; i += 2; continue
        if char == "/":
            # Distinguishing a regexp literal from division requires a JS parser.
            # Do not interpret either form as executable fetch text.
            yield -1
            return
        if char in "'\"`":
            state = "string"; quote = char; i += 1; continue
        if source.startswith("fetch", i):
            before = source[i - 1] if i else ""
            after = source[i + 5] if i + 5 < len(source) else ""
            if not (before and (before.isalnum() or before in "_$.")) and not (after and (after.isalnum() or after in "_$")):
                probe = i + 5
                while probe < len(source) and source[probe].isspace():
                    probe += 1
                if probe < len(source) and source[probe] == "(":
                    yield i
            i += 5
            continue
        i += 1


def _extract_fetches(source: str) -> tuple[list[tuple[str, str]], list[str]]:
    references: list[tuple[str, str]] = []
    unresolved: list[str] = []
    if re.search(r"\b(?:import|require|axios|XMLHttpRequest|Worker)\b", source):
        unresolved.append("unsupported_script_reference_form")
    for position in _fetch_positions(source):
        if position < 0:
            unresolved.append("javascript_lexical_ambiguity")
            break
        fragment = source[position:position + 4096]
        match = _FETCH_SIMPLE.match(fragment) or _FETCH_GET.match(fragment)
        if match:
            if len(references) < MAX_REFERENCES:
                references.append(("fetch_literal", match.group(2)))
            else:
                unresolved.append("reference_limit")
        else:
            unresolved.append("fetch_not_static_get")
    return references, unresolved


def extract_references(body: bytes, content_type: str) -> tuple[list[tuple[str, str]], list[str], str | None]:
    text = body.decode("utf-8", errors="replace")
    references: list[tuple[str, str]] = []
    unresolved: list[str] = []
    lowered = content_type.casefold()
    if "html" in lowered:
        parser = _Scripts()
        try:
            parser.feed(text)
        except (ValueError, RecursionError):
            return [], ["html_parse_incomplete"], None
        references.extend(parser.references)
        unresolved.extend(parser.unresolved)
        for script in parser.inline:
            found, gaps = _extract_fetches(script)
            references.extend(found)
            unresolved.extend(gaps)
        if len(parser.base_hrefs) > 1:
            unresolved.append("multiple_base_elements")
        base_href = parser.base_hrefs[0] if parser.base_hrefs else None
    elif "javascript" in lowered or "ecmascript" in lowered:
        references, unresolved = _extract_fetches(text)
        base_href = None
    else:
        base_href = None
    if len(references) > MAX_REFERENCES:
        unresolved.append("reference_limit")
    return references[:MAX_REFERENCES], sorted(set(unresolved)), base_href


def _validate_limit(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


def _validate_int_limit(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


def trace_assets(url: str, scope: Scope, *, max_depth: int = 2,
                 max_requests: int | None = None, max_total_bytes: int | None = None,
                 max_duration: float = 30.0, fetcher=None,
                 locator_store: LocatorStore | None = None, locator_scope: str | None = None) -> dict:
    max_depth = _validate_int_limit(max_depth, "max depth", 1, MAX_DEPTH)
    request_limit = min(scope.max_requests, 20) if max_requests is None else \
        _validate_int_limit(max_requests, "max requests", 1, min(scope.max_requests, MAX_REQUESTS))
    default_bytes = min(scope.max_bytes * request_limit, MAX_TOTAL_BYTES)
    byte_limit = default_bytes if max_total_bytes is None else \
        _validate_int_limit(max_total_bytes, "max total bytes", 1, MAX_TOTAL_BYTES)
    duration_limit = float(_validate_limit(max_duration, "max duration", 0.001, MAX_DURATION))
    canonical_root = scope.authorize(url)
    if bool(locator_store) != bool(locator_scope):
        raise ValueError("locator store and scope must be paired")
    if locator_scope is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", locator_scope):
        raise ValueError("invalid locator scope")

    started = time.monotonic()
    deadline = started + duration_limit
    budget = Budget(request_limit)
    do_fetch = fetcher or fetch
    trace_id = "trace:" + uuid.uuid4().hex
    result = {
        "schema_version": "1.0.0", "trace_id": trace_id,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy_id": clean_text(scope.policy_id, 128), "root_asset_id": None,
        "mode": "bounded_public_reference_trace",
        "limits": {"max_depth": max_depth, "max_requests": request_limit,
                   "max_total_bytes": byte_limit, "max_duration_seconds": duration_limit},
        "usage": {"requests": 0, "bytes_captured": 0, "elapsed_seconds": 0.0},
        "assets": [], "gaps": [],
        "coverage": {"state": "complete", "reason_codes": []},
        "limitations": list(LIMITATIONS),
    }
    if locator_scope:
        result["scope_id"] = locator_scope
    # document_base is retained when an external script is fetched: relative fetch()
    # URLs in that script resolve against the document, not the script response URL.
    queue = deque([(canonical_root, None, "root", 0, None)])
    seen: set[str] = set()
    reason_codes: set[str] = set()
    sensitive_stop = False

    def gap(parent, relation, reason):
        result["gaps"].append({"parent_asset_id": parent, "relation": relation, "reason": reason})
        reason_codes.add(reason)

    while queue and not sensitive_stop:
        if budget.used >= request_limit or time.monotonic() >= deadline or result["usage"]["bytes_captured"] >= byte_limit:
            reason_codes.add("aggregate_budget_exhausted")
            break
        target, parent_id, relation, depth, document_base = queue.popleft()
        if target in seen:
            continue
        seen.add(target)
        asset_id = "asset:" + uuid.uuid4().hex
        if result["root_asset_id"] is None:
            result["root_asset_id"] = asset_id
        redirects = []
        current = target
        response = None
        response_url = current
        classification = None
        while True:
            remaining_time = deadline - time.monotonic()
            remaining_bytes = byte_limit - result["usage"]["bytes_captured"]
            if remaining_time <= 0:
                gap(parent_id, relation, "duration_budget_exhausted")
                break
            if remaining_bytes <= 0:
                gap(parent_id, relation, "byte_budget_exhausted")
                break
            if budget.used >= request_limit:
                gap(parent_id, relation, "request_budget_exhausted")
                break
            try:
                response = do_fetch(current, scope, follow_redirects=False, budget=budget,
                                    max_bytes=remaining_bytes, timeout=remaining_time)
            except (PolicyError, ValueError):
                gap(parent_id, relation, "request_failed")
                response = None
                break
            result["usage"]["requests"] = budget.used
            result["usage"]["bytes_captured"] += len(response.body)
            response_url = current
            classification = None
            if response.headers.get("content-encoding", "identity").casefold() in ("", "identity"):
                classification = analyze(response.body, response.headers.get("content-type", ""), response_url)
                if classification.report["content"] in ("SENSITIVE_CANDIDATE", "SYNTHETIC_CONTENT_CONFIRMED"):
                    sensitive_stop = True
                    break
            else:
                break
            status = response.observation.get("http_status")
            if status not in (301, 302, 303, 307, 308):
                break
            location = response.headers.get("location")
            if not location:
                gap(parent_id, relation, "redirect_missing_location")
                break
            if len(redirects) >= scope.max_redirects:
                gap(parent_id, relation, "redirect_budget_exhausted")
                break
            try:
                next_url = scope.authorize(urljoin(current, location))
            except (PolicyError, ValueError):
                gap(parent_id, relation, "redirect_out_of_scope")
                break
            if next_url in seen:
                gap(parent_id, relation, "redirect_cycle_or_duplicate")
                break
            redirects.append({"http_status": status, "target_ref": safe_url(next_url)})
            seen.add(next_url)
            current = next_url

        if response is None:
            continue
        current = response_url
        observation = response.observation
        encoding = response.headers.get("content-encoding", "identity").casefold()
        content_type = response.headers.get("content-type", "")
        if encoding not in ("", "identity"):
            gap(asset_id, relation, "unsupported_content_encoding")
        else:
            if not observation.get("capture_complete", False):
                classification.report["analysis_complete"] = False
                gap(asset_id, relation, "capture_incomplete")
            if not classification.report["analysis_complete"]:
                reason_codes.add("analysis_incomplete")
        asset = {
            "asset_id": asset_id, "parent_asset_id": parent_id, "relation": relation,
            "depth": depth, "target_ref": safe_url(current),
            "observation_id": observation.get("observation_id"), "observed_at": observation.get("observed_at"),
            "access": observation.get("access", "INDETERMINATE"),
            "http_status": observation.get("http_status"),
            "content": classification.report["content"] if classification else "NOT_INSPECTED",
            "capture_complete": bool(observation.get("capture_complete", False)),
            "analysis_complete": bool(classification and classification.report["analysis_complete"]),
            "reason": clean_text(observation.get("reason", "unknown"), 128),
            "content_type": content_type.split(";", 1)[0].strip().casefold() if content_type.split(";", 1)[0].strip().casefold() in {"text/html", "application/xhtml+xml", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript", "application/json", "text/plain", "text/csv"} else "other",
            "bytes_captured": len(response.body),
            "sha256": observation.get("sha256"),
            "signals": classification.report["signals"] if classification else [],
            "structure": classification.report["structure"] if classification else {},
            "asset_profile": classification.report["asset_profile"] if classification else None,
            "analysis_scope": "supplied_bytes_only" if observation.get("capture_complete") else "captured_prefix",
            "redirects": redirects,
        }
        if locator_store is not None:
            asset["locator_ref"] = locator_store.put(locator_scope, current)
        result["assets"].append(asset)
        if sensitive_stop:
            reason_codes.add("sensitive_candidate_stop")
            gap(asset_id, "unresolved", "references_not_inspected_after_sensitive_stop")
            while queue:
                _, queued_parent, queued_relation, _, _ = queue.popleft()
                gap(queued_parent, queued_relation, "deferred_after_sensitive_stop")
            break
        if asset["access"] != "BODY_SERVED":
            reason_codes.add("body_not_served")
            continue
        if classification is None or not asset["capture_complete"] or not asset["analysis_complete"]:
            continue

        lowered_type = content_type.casefold()
        may_extract = relation == "root" or (
            relation == "script_src" and ("javascript" in lowered_type or "ecmascript" in lowered_type)
        )
        if not may_extract:
            if relation == "script_src":
                gap(asset_id, "unresolved", "unsupported_script_content_type")
            continue
        if not any(kind in lowered_type for kind in ("html", "javascript", "ecmascript", "json")):
            gap(asset_id, "unresolved", "unsupported_source_content_type")
            continue
        references, unresolved, base_href = extract_references(response.body, content_type)
        for reason in unresolved:
            gap(asset_id, "unresolved", reason)
        reference_base = current
        invalid_document_base = False
        if "html" in lowered_type:
            if base_href:
                try:
                    reference_base = scope.authorize(urljoin(current, base_href))
                except (PolicyError, ValueError):
                    gap(asset_id, "base_href", "base_out_of_scope_or_invalid")
                    invalid_document_base = True
            document_base = None if invalid_document_base else reference_base
        for child_relation, raw_reference in references:
            try:
                is_absolute = bool(re.match(r"^https://", raw_reference, re.I))
            except TypeError:
                is_absolute = False
            if invalid_document_base and not is_absolute:
                gap(asset_id, child_relation, "relative_reference_with_invalid_base")
                continue
            if child_relation == "fetch_literal" and document_base is None:
                if not is_absolute:
                    gap(asset_id, child_relation, "relative_fetch_without_document_context")
                    continue
            base = document_base if child_relation == "fetch_literal" and document_base else reference_base
            try:
                child = scope.authorize(urljoin(base, raw_reference))
            except (PolicyError, ValueError):
                gap(asset_id, child_relation, "reference_out_of_scope_or_invalid")
                continue
            if child in seen or any(item[0] == child for item in queue):
                continue
            if depth >= max_depth:
                gap(asset_id, child_relation, "depth_limit_reached")
            elif len(seen) + len(queue) >= MAX_QUEUED_ASSETS:
                gap(asset_id, child_relation, "asset_queue_limit")
            else:
                child_document_base = document_base if child_relation == "script_src" else None
                queue.append((child, asset_id, child_relation, depth + 1, child_document_base))

    if queue:
        for _, queued_parent, queued_relation, _, _ in queue:
            gap(queued_parent, queued_relation, "budget_deferred")
    result["usage"]["requests"] = budget.used
    result["usage"]["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["coverage"] = {
        "state": "stopped_sensitive" if sensitive_stop else "partial" if reason_codes else "complete",
        "reason_codes": sorted(reason_codes),
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Trace bounded static public asset references with anonymous GET requests.")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--locator-store")
    parser.add_argument("--scope-id")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-requests", type=int)
    parser.add_argument("--max-total-bytes", type=int)
    parser.add_argument("--max-duration", type=float, default=30.0)
    args = parser.parse_args(argv)
    store = None
    try:
        if bool(args.locator_store) != bool(args.scope_id):
            raise ValueError("locator options must be paired")
        output = Path(args.output).absolute()
        if output.exists():
            raise ValueError("output exists")
        for parent in output.parents:
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
                raise ValueError("linked output parent")
        scope = Scope.load(args.scope)
        if args.locator_store:
            store = LocatorStore(args.locator_store)
        report = trace_assets(args.url, scope, max_depth=args.max_depth,
                              max_requests=args.max_requests, max_total_bytes=args.max_total_bytes,
                              max_duration=args.max_duration, locator_store=store,
                              locator_scope=args.scope_id)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
            stream.write(json.dumps(report, ensure_ascii=True, indent=2) + "\n")
        print(json.dumps({"trace_id": report["trace_id"], "assets": len(report["assets"]),
                          "coverage": report["coverage"]["state"]}))
        return 0
    except (OSError, ValueError, PolicyError):
        print(json.dumps({"error": "asset_trace_failed"}))
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
