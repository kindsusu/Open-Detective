"""Versioned offline joins for owner inventory and discovery references."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RELATIONSHIPS = {"deployment", "alias", "custom_domain", "repository", "certificate_name", "public_search_result", "document_result"}

def _exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir(): raise ValueError("unsafe output")
    temporary=path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x",encoding="utf-8",newline="\n") as stream:
            json.dump(value,stream,indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally: temporary.unlink(missing_ok=True)


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_time(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() is not None
    except (ValueError, OverflowError):
        return False


def _read(source: str | Path | Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(source, (str, Path)):
        with Path(source).open("rb") as handle:
            data = handle.read(8_388_609)
        if len(data) > 8_388_608:
            raise ValueError("asset graph input too large")
        value = json.loads(data)
    else:
        value = list(source)
    if not isinstance(value, list):
        raise ValueError("asset graph records must be a list")
    return json.loads(json.dumps(value))


def build_asset_graph(records: str | Path | Iterable[Mapping[str, Any]], *, previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate normalized records and build a reference-only graph snapshot."""
    rows = _read(records)
    normalized: list[dict[str, Any]] = []
    validated: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    conflicted_keys: set[tuple[str, str, str]] = set()
    conflicts: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for raw in rows:
        fields = {"scope_id", "source_kind", "source_id", "source_record_id", "retrieved_at", "locator_ref",
                  "asset_id", "alias_id", "relationship", "ownership_evidence", "coverage_state"}
        if not isinstance(raw, dict) or set(raw) != fields:
            raise ValueError("invalid asset graph record")
        for key in ("scope_id", "source_id", "source_record_id", "asset_id"):
            if not isinstance(raw[key], str) or not _ID.fullmatch(raw[key]):
                raise ValueError("invalid opaque record identifier")
        if raw["source_kind"] not in {"owner_inventory", "public_discovery"} or raw["relationship"] not in _RELATIONSHIPS:
            raise ValueError("invalid graph classification")
        if raw["coverage_state"] not in {"complete", "partial", "failed"} or not _valid_time(raw["retrieved_at"]):
            raise ValueError("invalid graph provenance")
        if not isinstance(raw["locator_ref"], str) or not re.fullmatch(r"opaque:[0-9a-f]{32}", raw["locator_ref"]):
            raise ValueError("invalid locator reference")
        if raw["alias_id"] is not None and (not isinstance(raw["alias_id"], str) or not _ID.fullmatch(raw["alias_id"])):
            raise ValueError("invalid alias identifier")
        if raw["ownership_evidence"] is not None and (not isinstance(raw["ownership_evidence"], str) or not _ID.fullmatch(raw["ownership_evidence"])):
            raise ValueError("invalid ownership evidence reference")
        key = (raw["scope_id"], raw["source_id"], raw["source_record_id"])
        validated.append(raw)
        if key in seen:
            if seen[key] != raw:
                conflicted_keys.add(key)
                conflicts.append({"conflict_id": "conflict:" + hashlib.sha256("\x1f".join(key).encode()).hexdigest(), "reason": "source_record_changed"})
            continue
        seen[key] = raw
        normalized.append(raw)
        if raw["coverage_state"] != "complete":
            gaps.append({"source_id": raw["source_id"], "source_record_id": raw["source_record_id"], "coverage_state": raw["coverage_state"]})
    by_locator: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in normalized:
        by_locator.setdefault((row["scope_id"], row["locator_ref"]), []).append(row)
    nodes, links = [], []
    for (scope_id, locator_ref), group in sorted(by_locator.items()):
        disputed = any((x["scope_id"], x["source_id"], x["source_record_id"]) in conflicted_keys for x in group)
        owner = [x for x in group if x["source_kind"] == "owner_inventory" and x["ownership_evidence"]]
        discovered = [x for x in group if x["source_kind"] == "public_discovery"]
        ownership = "disputed" if disputed else ("evidence_linked" if owner else "ownership_pending")
        nodes.append({"scope_id": scope_id, "locator_ref": locator_ref, "ownership_state": ownership,
                      "asset_ids": sorted({x["asset_id"] for x in group}),
                      "alias_ids": sorted({x["alias_id"] for x in group if x["alias_id"] is not None}),
                      "source_record_count": len(group)})
        for row in group:
            key=(row["scope_id"],row["source_id"],row["source_record_id"])
            links.append({"scope_id": scope_id, "source_kind": row["source_kind"], "source_id": row["source_id"], "source_record_id": row["source_record_id"],
                          "locator_ref": locator_ref, "relationship": row["relationship"],
                          "retrieved_at": row["retrieved_at"], "coverage_state": row["coverage_state"],
                          "ownership_evidence": row["ownership_evidence"],
                          "ownership_state": ("disputed" if key in conflicted_keys else (ownership if row in owner else "candidate_signal"))})
        if discovered and not owner:
            gaps.append({"locator_ref": locator_ref, "coverage_state": "ownership_evidence_missing"})
    canonical = json.dumps(sorted(validated, key=lambda x: json.dumps(x, sort_keys=True)), sort_keys=True, separators=(",", ":")).encode()
    snapshot_id = "graph:" + hashlib.sha256(canonical).hexdigest()
    prior_refs = set()
    prior_id = None
    if previous is not None:
        if not isinstance(previous, Mapping) or not isinstance(previous.get("nodes"), list):
            raise ValueError("invalid previous graph")
        prior_id = previous.get("snapshot_id")
        if any(not isinstance(x, Mapping) or not isinstance(x.get("scope_id"),str) or not re.fullmatch(r"opaque:[0-9a-f]{32}",str(x.get("locator_ref",""))) for x in previous["nodes"]):
            raise ValueError("invalid previous graph nodes")
        prior_refs = {(x["scope_id"],x["locator_ref"]) for x in previous["nodes"]}
    refs = set(by_locator)
    return {"version": 1, "snapshot_id": snapshot_id, "created_at": _stamp(), "previous_snapshot_id": prior_id,
            "nodes": nodes, "links": links, "conflicts": conflicts, "coverage_gaps": gaps,
            "diff": {"added_scope_locator_refs": [{"scope_id":x[0],"locator_ref":x[1]} for x in sorted(refs-prior_refs)],
                     "removed_scope_locator_refs": [{"scope_id":x[0],"locator_ref":x[1]} for x in sorted(prior_refs-refs)]},
            "limitations": ["similarity_does_not_promote_ownership", "public_discovery_remains_candidate_until_evidence_linked",
                            "removed_source_records_do_not_establish_exposure_closure"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a versioned offline asset reference graph")
    parser.add_argument("--input", required=True); parser.add_argument("--output", required=True); parser.add_argument("--previous")
    args = parser.parse_args(argv)
    try:
        previous = json.loads(Path(args.previous).read_text(encoding="utf-8")) if args.previous else None
        result = build_asset_graph(args.input, previous=previous)
        inputs=[Path(args.input).resolve()]+([Path(args.previous).resolve()] if args.previous else [])
        if Path(args.output).resolve() in inputs: raise ValueError("input and output collide")
        _exclusive_json(Path(args.output),result)
        print(json.dumps({"snapshot_id": result["snapshot_id"], "nodes": len(result["nodes"]), "conflicts": len(result["conflicts"]), "coverage_gaps": len(result["coverage_gaps"])}))
        return 0
    except (ValueError, OSError, json.JSONDecodeError):
        print(json.dumps({"error": "asset_graph_failed"})); return 2
