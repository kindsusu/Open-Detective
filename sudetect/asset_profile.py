"""Offline, value-free profiling of already captured asset content.

This module never fetches a locator.  Its conclusions describe only the supplied
bytes and therefore never establish anonymous/public reachability.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping

MAX_MANIFEST_BYTES = 1_048_576
MAX_ASSETS = 100
MAX_CONTENT_BYTES = 262_144
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_LOCATOR_REF = re.compile(r"^(?:opaque:[0-9a-f]{32}|hmac-sha256:[0-9a-f]{64})$")
_CATEGORIES = {
    "pricing": ("price", "pricing", "currency", "discount", "rate", "요금", "가격", "할인"),
    "margin": ("margin", "cost_price", "cogs", "markup", "원가", "마진"),
    "customer_contact": ("customer", "client", "email", "phone", "telephone", "contact", "고객", "이메일", "전화"),
    "partner": ("partner", "vendor", "reseller", "affiliate", "협력", "파트너"),
    "financial": ("revenue", "profit", "invoice", "balance", "expense", "budget", "매출", "수익", "예산"),
}
_SAFE_EXTENSIONS = frozenset({"json", "csv", "tsv", "xml", "yaml", "yml", "toml", "ini", "env", "sql", "txt", "md", "pdf", "docx", "xlsx", "js", "ts", "jsx", "tsx", "py", "java", "go", "rb", "php", "c", "cc", "cpp", "h", "cs", "sh", "html", "css", "vue", "svelte", "conf", "config"})


def _has_symlink_ancestor(path: Path) -> bool:
    return any(part.is_symlink() for part in (path, *path.parents))


def _terms(value: str) -> set[str]:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", value).casefold().replace("_", " ").replace("-", " ")
    padded = " " + re.sub(r"\s+", " ", normalized).strip() + " "
    return {category for category, words in _CATEGORIES.items()
            if any(" " + word.replace("_", " ") + " " in padded for word in words)}


class _MarkupStructure(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: dict[str, int] = {}
        self.attribute_terms: set[str] = set()
        self.text_terms: set[str] = set()
        self.in_script = False
        self.json_script = False
        self.json_chunks: list[str] = []
        self.script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.in_script = True
            self.json_script = (dict(attrs).get("type") or "").casefold() in {"application/json", "application/ld+json"}
        self.tags[tag] = self.tags.get(tag, 0) + 1
        # Attribute names can reveal a data shape; values are intentionally ignored.
        self.attribute_terms.update(_terms(" ".join(name for name, _ in attrs)))

    def handle_data(self, data: str) -> None:
        if not self.in_script: self.text_terms.update(_terms(data))
        elif self.json_script and len(self.json_chunks) < 16: self.json_chunks.append(data)
        elif not self.json_script and len(self.script_chunks) < 16: self.script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script": self.in_script = self.json_script = False


def _walk_json(value: Any, *, limit: int = 2048) -> tuple[dict[str, list[int]], bool]:
    found: dict[str, list[int]] = {}; queue = [value]; examined = 0; truncated = False
    while queue and examined < limit:
        item = queue.pop(); examined += 1
        if isinstance(item, dict):
            for key, val in item.items():
                for category in _terms(str(key)):
                    stats = found.setdefault(category, [0, 0]); stats[0] += 1
                    if val is not None and val != "" and val != [] and val != {}: stats[1] += 1
                if isinstance(val, (dict, list)): queue.append(val)
        elif isinstance(item, list):
            queue.extend(v for v in item if isinstance(v, (dict, list)))
        if len(queue) > limit:
            del queue[limit:]
            truncated = True
    return found, truncated or bool(queue)


def _kind_hint(text: str, content_type: str, markup: _MarkupStructure | None, parsed_json: Any | None) -> str:
    ct = content_type.casefold(); lower = text.casefold()
    if "json" in ct or parsed_json is not None: return "data_file"
    if markup:
        if markup.tags.get("table", 0) or re.search(r"\b(?:dashboard|chart|analytics|metric)\b", lower): return "dashboard"
        if markup.tags.get("form", 0) and re.search(r"\b(?:calculate|calculator|estimate|quote)\b", lower): return "calculator"
        return "webpage"
    if "javascript" in ct or "typescript" in ct or re.search(r"\b(?:function|const|let|import|export)\b", text): return "source_code"
    return "unknown"


def profile_content(body: bytes, content_type: str = "") -> dict[str, Any]:
    """Return safe structural hints from bounded local bytes, never values or keys."""
    truncated = len(body) > MAX_CONTENT_BYTES
    text = body[:MAX_CONTENT_BYTES].decode("utf-8", errors="replace")
    parsed_json = None; json_terms: dict[str, list[int]] = {}; json_truncated = False
    markup = None
    stripped = text.lstrip()
    if "json" in content_type.casefold() or stripped.startswith(("{", "[")):
        try:
            parsed_json = json.loads(text)
            json_terms, json_truncated = _walk_json(parsed_json)
        except (ValueError, RecursionError):
            truncated = True
    if "html" in content_type.casefold() or re.search(r"<(?:html|body|script|form|table|div)\b", text, re.I):
        markup = _MarkupStructure()
        try:
            markup.feed(text)
            for chunk in markup.json_chunks:
                try:
                    nested, nested_truncated = _walk_json(json.loads(chunk))
                    for category, values in nested.items():
                        totals = json_terms.setdefault(category, [0, 0]); totals[0] += values[0]; totals[1] += values[1]
                    json_truncated |= nested_truncated
                except (ValueError, RecursionError): truncated = True
        except (ValueError, RecursionError): truncated = True
    source_text = text if ("javascript" in content_type.casefold() or _kind_hint(text, content_type, markup, parsed_json) == "source_code") else " ".join(markup.script_chunks if markup else [])
    source_terms = _terms(source_text)
    bases: dict[str, set[str]] = {}; counts: dict[str, list[int]] = {key: value[:] for key, value in json_terms.items()}
    for terms, basis in ((set(json_terms), "structured_field_names"),
                         (markup.attribute_terms if markup else set(), "markup_attribute_names"),
                         (markup.text_terms if markup else set(), "markup_text_labels"),
                         (source_terms, "source_text_terms")):
        for category in terms: bases.setdefault(category, set()).add(basis)
    categories = [{"category": category, "candidate_count": counts.get(category, [1, 0])[0],
                   "filled_field_count": counts.get(category, [0, 0])[1],
                   "candidate_confidence": "low" if len(bases[category]) == 1 else "medium",
                   "evidence_bases": sorted(bases[category])}
                  for category in sorted(bases)]
    return {"asset_kind_hint": _kind_hint(text, content_type, markup, parsed_json),
            "business_data_categories": categories, "analysis_complete": not (truncated or json_truncated),
            "analysis_scope": "supplied_bytes_only",
            "bytes_examined": min(len(body), MAX_CONTENT_BYTES),
            "truncated": bool(truncated or json_truncated),
            "automated_sensitivity_is_provisional": True}


def _read_manifest(path: Path) -> tuple[list[dict[str, Any]], int, str | None, dict[str, Any] | None]:
    if path.is_symlink() or not path.is_file(): raise ValueError("unsafe input")
    with path.open("rb") as stream: data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES: raise ValueError("manifest too large")
    value = json.loads(data)
    if not isinstance(value, Mapping) or not isinstance(value.get("assets"), list): raise ValueError("invalid manifest")
    # Native offline inventory reports can be profiled directly.  Their URL and
    # object metadata remain private input; only opaque references are retained.
    if "inventory_id" in value:
        edges = value.get("edges", [])
        if not isinstance(edges, list): raise ValueError("invalid inventory edges")
        parents: dict[str, str] = {}
        for edge in edges:
            if isinstance(edge, Mapping) and edge.get("relationship") == "contains" and isinstance(edge.get("source_asset_id"), str) and isinstance(edge.get("target_asset_id"), str):
                if edge["target_asset_id"] in parents: raise ValueError("multiple inventory parents")
                parents[edge["target_asset_id"]] = edge["source_asset_id"]
        rows = []
        for asset in value["assets"]:
            if not isinstance(asset, Mapping) or not isinstance(asset.get("asset_id"), str): raise ValueError("invalid inventory asset")
            row: dict[str, Any] = {"asset_id": asset["asset_id"]}
            if asset["asset_id"] in parents: row["parent_asset_id"] = parents[asset["asset_id"]]
            if isinstance(asset.get("locator_ref"), str): row["locator_ref"] = asset["locator_ref"]
            if isinstance(asset.get("candidate_kind"), str): row["kind"] = asset["candidate_kind"]
            elif isinstance(asset.get("kind"), str): row["kind"] = asset["kind"]
            metadata = {key: asset[key] for key in ("extension", "byte_size", "git_object_sha", "visibility", "public_exposure", "locator_mutability") if key in asset}
            if metadata: row["asset_metadata"] = metadata
            rows.append(row)
        scope_id = value.get("scope_id") if isinstance(value.get("scope_id"), str) and _ID.fullmatch(value["scope_id"]) else None
        status = value.get("status")
        coverage_value = value.get("coverage")
        coverage_state = status.casefold() if isinstance(status, str) and status.casefold() in {"complete", "partial", "failed"} else (coverage_value if coverage_value in {"complete", "partial", "failed", "PARTIAL", "COMPLETE", "FAILED"} else "unknown")
        coverage = {"state": coverage_state,
                    "error_count": len(value.get("errors", [])) if isinstance(value.get("errors"), list) else 0}
        if len(rows) <= MAX_ASSETS: return rows, 0, scope_id, coverage
        # The profile is deliberately bounded.  Keep parent repositories with
        # selected children so displayed relationships remain valid.
        selected = {row["asset_id"] for row in rows[:MAX_ASSETS]}
        for row in rows[:MAX_ASSETS]:
            if row.get("parent_asset_id"): selected.add(row["parent_asset_id"])
        ordered = [row for row in rows if row["asset_id"] in selected]
        while len(ordered) > MAX_ASSETS:
            removable = next((row for row in reversed(ordered) if row["asset_id"] not in {x.get("parent_asset_id") for x in ordered}), None)
            if removable is None: break
            ordered.remove(removable)
        return ordered, len(rows) - len(ordered), scope_id, coverage
    if set(value) != {"assets"}: raise ValueError("invalid manifest")
    if len(value["assets"]) > MAX_ASSETS: raise ValueError("too many assets")
    return value["assets"], 0, None, None


def _validate_rows(rows: list[dict[str, Any]]) -> None:
    ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not set(row).issubset({"asset_id", "parent_asset_id", "kind", "locator_ref", "content_type", "local_file", "asset_metadata"}) or "asset_id" not in row: raise ValueError("invalid asset row")
        if not isinstance(row["asset_id"], str) or not _ID.fullmatch(row["asset_id"]) or row["asset_id"] in ids: raise ValueError("invalid or duplicate asset_id")
        ids.add(row["asset_id"])
        for key in ("parent_asset_id", "kind", "content_type", "local_file"):
            if key in row and (not isinstance(row[key], str) or len(row[key]) > 255): raise ValueError("invalid asset field")
        if row.get("kind", "unknown") not in {"unknown", "website", "webpage", "dashboard", "calculator", "data_file", "source_code", "document", "config", "other", "repository", "repository_file", "project", "deployment", "alias", "custom_domain", "certificate_name", "public_search_result", "document_result"}: raise ValueError("invalid declared kind")
        if "locator_ref" in row and (not isinstance(row["locator_ref"], str) or not _LOCATOR_REF.fullmatch(row["locator_ref"])): raise ValueError("invalid locator reference")
        metadata = row.get("asset_metadata")
        if metadata is not None:
            if not isinstance(metadata, dict) or set(metadata) - {"extension", "byte_size", "git_object_sha", "visibility", "public_exposure", "locator_mutability"}: raise ValueError("invalid asset metadata")
            if "extension" in metadata and metadata["extension"] is not None and metadata["extension"] not in _SAFE_EXTENSIONS: raise ValueError("invalid extension")
            if "byte_size" in metadata and (not isinstance(metadata["byte_size"], int) or isinstance(metadata["byte_size"], bool) or metadata["byte_size"] < 0): raise ValueError("invalid byte size")
            if "git_object_sha" in metadata and (not isinstance(metadata["git_object_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", metadata["git_object_sha"])): raise ValueError("invalid git object")
            if "visibility" in metadata and metadata["visibility"] not in {"public", "private", "internal", "unknown"}: raise ValueError("invalid visibility")
            if "public_exposure" in metadata and metadata["public_exposure"] != "not_measured": raise ValueError("invalid public exposure")
            if "locator_mutability" in metadata and metadata["locator_mutability"] not in {"branch_ref_mutable", "immutable", "unknown"}: raise ValueError("invalid locator mutability")
    parents = {r["asset_id"]: r.get("parent_asset_id") for r in rows}
    if any(parent is not None and parent not in parents for parent in parents.values()): raise ValueError("unknown parent")
    for asset_id in parents:
        seen = set(); current = asset_id
        while parents.get(current) is not None:
            if current in seen: raise ValueError("asset relationship cycle")
            seen.add(current); current = parents[current]


def _safe_content(root: Path, reference: str) -> bytes:
    ref_path = Path(reference)
    if ref_path.is_absolute() or ".." in ref_path.parts: raise ValueError("unsafe local_file")
    candidate = root / reference
    if _has_symlink_ancestor(candidate): raise ValueError("unsafe local_file")
    try: resolved = candidate.resolve(strict=True)
    except OSError as exc: raise ValueError("unsafe local_file") from exc
    try: resolved.relative_to(root.resolve(strict=True))
    except ValueError: raise ValueError("unsafe local_file") from None
    if candidate.is_symlink() or not resolved.is_file(): raise ValueError("unsafe local_file")
    with resolved.open("rb") as stream: return stream.read(MAX_CONTENT_BYTES + 1)


def build_asset_profile(manifest: str | Path) -> dict[str, Any]:
    original = Path(manifest)
    if _has_symlink_ancestor(original.absolute()): raise ValueError("unsafe input")
    path = original.absolute(); rows, omitted, scope_id, source_coverage = _read_manifest(path); _validate_rows(rows)
    assets = []
    for row in rows:
        result = {"asset_id": row["asset_id"], "parent_asset_id": row.get("parent_asset_id"),
                  "declared_kind": row.get("kind", "unknown"), "locator_ref": row.get("locator_ref"),
                  "exposure": "NOT_ESTABLISHED_BY_LOCAL_ANALYSIS"}
        if "asset_metadata" in row: result["asset_metadata"] = row["asset_metadata"]
        if "local_file" not in row:
            result.update({"inspection_state": "NOT_INSPECTED", "next_action": "capture_authorized_content_or_measure_reachability"})
        else:
            result.update({"inspection_state": "LOCAL_CONTENT_ANALYZED", "content_profile": profile_content(_safe_content(path.parent, row["local_file"]), row.get("content_type", "")),
                           "next_action": "measure_authorized_reachability_separately"})
        assets.append(result)
    result = {"version": 1, "assets": assets, "profile_input_omitted_asset_count": omitted,
            "profile_coverage": "partial" if omitted else "complete",
            "limitations": ["local_content_analysis_never_establishes_anonymous_reachability", "business_data_categories_are_candidates_not_sensitive_confirmations"]}
    if scope_id is not None: result["scope_id"] = scope_id
    if source_coverage is not None: result["source_coverage"] = source_coverage
    return result


def _exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or _has_symlink_ancestor(path) or not path.parent.is_dir(): raise ValueError("unsafe output")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream: json.dump(value, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally: temporary.unlink(missing_ok=True)


def _exclusive_text(path: Path, value: str) -> None:
    if path.exists() or _has_symlink_ancestor(path) or not path.parent.is_dir(): raise ValueError("unsafe output")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream: stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally: temporary.unlink(missing_ok=True)


def _markdown(report: Mapping[str, Any]) -> str:
    lines = ["# Asset profile", "", "Local analysis does not establish anonymous reachability.", "", "| Asset | Parent | Locator reference | Inspection | Exposure | Declared / inferred kind | Next action |", "| --- | --- | --- | --- | --- | --- |"]
    for asset in report["assets"]:
        profile = asset.get("content_profile", {})
        lines.append(f"| {asset['asset_id']} | {asset.get('parent_asset_id') or ''} | {asset.get('locator_ref') or ''} | {asset['inspection_state']} | {asset['exposure']} | {asset['declared_kind']} / {profile.get('asset_kind_hint', 'unknown')} | {asset['next_action']} |")
        for category in profile.get("business_data_categories", []):
            lines.append("|  |  |  | candidate data: " + category["category"] + " | fields=" + str(category["candidate_count"]) + ", filled=" + str(category["filled_field_count"]) + ", confidence=" + category["candidate_confidence"] + " | basis=" + ", ".join(category["evidence_bases"]) + " | review authorized capture |")
        if asset.get("asset_metadata"):
            metadata = asset["asset_metadata"]
            lines.append("|  |  |  | file metadata | " + ", ".join(f"{key}={value}" for key, value in sorted(metadata.items())) + " | metadata does not establish exposure |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile bounded, already captured local asset content")
    parser.add_argument("--input", required=True); parser.add_argument("--output", required=True); parser.add_argument("--markdown")
    args = parser.parse_args(argv)
    try:
        source = Path(args.input).absolute(); output = Path(args.output).absolute()
        markdown = Path(args.markdown).absolute() if args.markdown else None
        if output == source or markdown in {source, output}: raise ValueError("input and output collide")
        result = build_asset_profile(source); _exclusive_json(output, result)
        if markdown: _exclusive_text(markdown, _markdown(result))
        print(json.dumps({"assets": len(result["assets"]), "local_content_analyzed": sum(x["inspection_state"] == "LOCAL_CONTENT_ANALYZED" for x in result["assets"])})); return 0
    except (ValueError, OSError, json.JSONDecodeError): print(json.dumps({"error": "asset_profile_failed"})); return 2
