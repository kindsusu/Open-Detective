"""Bounded, offline semantic review of already captured source bytes.

The original JavaScript is never executed. Results contain only controlled
categories, counts and coverage states; no source text or field values leave
the isolated worker.
"""
from __future__ import annotations

import math
import multiprocessing as mp
import re
import time

from .asset_profile import _substantive, _terms, profile_content
from .classifiers import SENSITIVE_FIELDS
from .media_projection import project_inline_images
from .structured_data import inspect_static_json
from . import strict_json

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_NODES = 500_000
MAX_DEPTH = 128
_DECL = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,100})\s*=\s*[\[{]")
_SINK = re.compile(r"\b(?:innerHTML|textContent|appendChild|replaceChildren|insertAdjacentHTML|"
                   r"setAttribute|style\.display|classList\.(?:add|remove|toggle))\b")
_EVENT = re.compile(r"\b(?:addEventListener|on(?:click|change|input|submit)\s*=)\b", re.I)
_RENDER = re.compile(r"\b(?:render|filter|calculate|compute|update|display|show)[A-Za-z0-9_$]*\s*\(", re.I)


def _depth_within_limit(text: str, max_depth: int) -> bool:
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
            if depth > max_depth:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _dom_flow(source: str) -> dict:
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", source, re.I | re.S)
    code = "\n".join(scripts) if scripts else source
    declarations = [match.group(1) for match in _DECL.finditer(code)]
    sink_positions = [match.start() for match in _SINK.finditer(code)]
    # Regex proximity can match comments and strings. It is only a lexical
    # candidate, never proof of dataflow, execution or a successful render.
    linked = 0
    for name in set(declarations[:4096]):
        token = re.compile(r"\b" + re.escape(name) + r"\b")
        if any(token.search(code[max(0, pos - 512):pos + 512])
               for pos in sink_positions[:4096]):
            linked += 1
    limits_reached = len(declarations) > 4096 or len(sink_positions) > 4096
    return {"static_data_declarations": len(declarations),
            "dom_write_sites": len(sink_positions),
            "event_binding_sites": len(_EVENT.findall(code)),
            "render_or_filter_call_sites": len(_RENDER.findall(code)),
            "declaration_dom_proximity_links": linked,
            "link_strength": "lexical_candidate_only" if linked else "not_observed",
            "lexical_scan_complete": not limits_reached,
            "runtime_flow_verified": False,
            "original_script_executed": False,
            "network_request_attempts": 0}


def _review_worker(body: bytes, content_type: str, max_nodes: int,
                   max_depth: int, deadline: float) -> dict:

    kind = "json" if "json" in content_type.casefold() else (
        "html" if "html" in content_type.casefold() else "javascript"
        if "javascript" in content_type.casefold() else "other")
    result = {"document_type": kind, "body_bytes": len(body),
              "source_text_complete": True, "source_structure_complete": False,
              "syntax_valid": None, "nodes_examined": 0,
              "filled_field_count_by_category": {},
              "sensitive_field_count": 0, "sensitive_filled_field_count": 0,
              "pending_reviews": [], "dom_flow": None,
              "inline_images_projected": 0}
    if kind == "other":
        try:
            body.decode("utf-8", "strict")
        except UnicodeError:
            result["source_text_complete"] = False
            result["pending_reviews"].append("semantic_utf8_invalid")
        result["pending_reviews"].append("semantic_unsupported_content_type")
        return result
    if kind == "json":
        try:
            text = body.decode("utf-8", "strict")
        except UnicodeError:
            result["source_text_complete"] = False
            result["pending_reviews"].append("semantic_utf8_invalid")
            return result
        if not _depth_within_limit(text, max_depth):
            result["pending_reviews"].append("semantic_depth_limit")
            return result
        try:
            root = strict_json.loads(text)
        except (ValueError, RecursionError) as exc:
            duplicate = str(exc) == "duplicate_json_key"
            result["syntax_valid"] = None if duplicate else False
            result["pending_reviews"].append("semantic_json_duplicate_keys" if duplicate
                                             else "semantic_json_syntax_invalid")
            return result
        result["syntax_valid"] = True
        stack = [(root, 0)]
        categories: dict[str, int] = {}
        while stack:
            if result["nodes_examined"] >= max_nodes:
                result["pending_reviews"].append("semantic_node_limit")
                break
            if time.monotonic() >= deadline:
                result["pending_reviews"].append("semantic_time_limit")
                break
            value, depth = stack.pop()
            result["nodes_examined"] += 1
            if depth > max_depth:
                result["pending_reviews"].append("semantic_depth_limit")
                break
            if isinstance(value, dict):
                for key, child in value.items():
                    key_text = str(key)
                    for category in _terms(key_text):
                        if not isinstance(child, (dict, list)) and _substantive(child):
                            categories[category] = categories.get(category, 0) + 1
                    if key_text.casefold() in SENSITIVE_FIELDS:
                        result["sensitive_field_count"] += 1
                        if _substantive(child):
                            result["sensitive_filled_field_count"] += 1
                    stack.append((child, depth + 1))
            elif isinstance(value, list):
                stack.extend((child, depth + 1) for child in value)
        result["filled_field_count_by_category"] = dict(sorted(categories.items()))
        result["source_structure_complete"] = not result["pending_reviews"]
        return result

    source = body
    if re.search(br"data:image/", body, re.I):
        projection = project_inline_images(
            (body[index:index + 65_536] for index in range(0, len(body), 65_536)),
            max_wire_bytes=len(body), max_projected_bytes=min(MAX_SOURCE_BYTES, len(body) + 1_048_576))
        source = projection.projected
        result["inline_images_projected"] = projection.skipped_images
        if projection.wire_truncated or projection.projected_truncated:
            result["pending_reviews"].append("semantic_media_projection_incomplete")
    if time.monotonic() >= deadline:
        result["pending_reviews"].append("semantic_time_limit")
        return result
    try:
        decoded = source.decode("utf-8", "strict")
    except UnicodeError:
        result["source_text_complete"] = False
        result["pending_reviews"].append("semantic_utf8_invalid")
        return result
    profile = profile_content(source, content_type, max_bytes=max(1, len(source)))
    static = inspect_static_json(decoded, content_type)
    # This bounded parser recognises a safe literal subset; it is not a full
    # HTML/JavaScript syntax validator.
    result["syntax_valid"] = None
    result["filled_field_count_by_category"] = {
        row["category"]: row["filled_field_count"]
        for row in profile["business_data_categories"] if row["filled_field_count"]}
    result["source_structure_complete"] = (bool(profile["structure_analysis_complete"])
                                           and "semantic_media_projection_incomplete" not in result["pending_reviews"])
    if not result["source_structure_complete"]:
        structure_reasons = (set(profile.get("structure_incomplete_reasons", [])) |
                             set(static["incomplete_reasons"]))
        result["pending_reviews"].extend(
            "semantic_" + reason for reason in sorted(structure_reasons))
        if not structure_reasons:
            result["pending_reviews"].append("semantic_static_parser_incomplete")
    result["dom_flow"] = _dom_flow(decoded)
    if not result["dom_flow"]["lexical_scan_complete"]:
        result["pending_reviews"].append("semantic_dom_flow_limit")
    if "semantic_media_projection_incomplete" in result["pending_reviews"]:
        result["source_text_complete"] = False
    if result["inline_images_projected"]:
        result["pending_reviews"].append("semantic_image_visual_review_separate")
    return result


def _process_entry(connection, body, content_type, max_nodes, max_depth, deadline):
    try:
        connection.send(_review_worker(body, content_type, max_nodes, max_depth, deadline))
    except Exception:
        connection.send({"document_type": "unknown", "body_bytes": len(body),
                         "source_text_complete": False, "source_structure_complete": False,
                         "syntax_valid": None, "nodes_examined": 0,
                         "filled_field_count_by_category": {},
                         "sensitive_field_count": 0, "sensitive_filled_field_count": 0,
                         "pending_reviews": ["semantic_worker_failed"],
                         "dom_flow": None, "inline_images_projected": 0})
    finally:
        connection.close()


def review_semantic_source(body: bytes, content_type: str, *,
                           max_bytes: int = MAX_SOURCE_BYTES,
                           max_nodes: int = MAX_NODES,
                           max_depth: int = MAX_DEPTH,
                           max_seconds: float = 60.0) -> dict:
    """Review public captured bytes in a time-limited isolated process."""
    if not isinstance(body, bytes) or not isinstance(content_type, str):
        raise TypeError("source bytes and content type required")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
        raise ValueError("invalid semantic byte limit")
    if type(max_nodes) is not int or not 1 <= max_nodes <= MAX_NODES:
        raise ValueError("invalid semantic node limit")
    if type(max_depth) is not int or not 1 <= max_depth <= MAX_DEPTH:
        raise ValueError("invalid semantic depth limit")
    if not isinstance(max_seconds, (int, float)) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 60:
        raise ValueError("invalid semantic time limit")
    if len(body) > max_bytes:
        return {"document_type": "unknown", "body_bytes": len(body),
                "source_text_complete": False, "source_structure_complete": False,
                "syntax_valid": None, "nodes_examined": 0,
                "filled_field_count_by_category": {},
                "sensitive_field_count": 0, "sensitive_filled_field_count": 0,
                "pending_reviews": ["semantic_byte_limit"], "dom_flow": None,
                "inline_images_projected": 0}
    context = mp.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    deadline = time.monotonic() + max_seconds
    process = context.Process(target=_process_entry,
        args=(writer, body, content_type, max_nodes, max_depth, deadline))
    process.start()
    writer.close()
    try:
        remaining = max(0.0, deadline - time.monotonic())
        if not reader.poll(remaining):
            process.terminate()
            return {"document_type": "unknown", "body_bytes": len(body),
                    "source_text_complete": False, "source_structure_complete": False,
                    "syntax_valid": None, "nodes_examined": 0,
                    "filled_field_count_by_category": {},
                    "sensitive_field_count": 0, "sensitive_filled_field_count": 0,
                    "pending_reviews": ["semantic_time_limit"], "dom_flow": None,
                    "inline_images_projected": 0}
        return reader.recv()
    except EOFError:
        return {"document_type": "unknown", "body_bytes": len(body),
                "source_text_complete": False, "source_structure_complete": False,
                "syntax_valid": None, "nodes_examined": 0,
                "filled_field_count_by_category": {},
                "sensitive_field_count": 0, "sensitive_filled_field_count": 0,
                "pending_reviews": ["semantic_worker_failed"], "dom_flow": None,
                "inline_images_projected": 0}
    finally:
        reader.close()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
