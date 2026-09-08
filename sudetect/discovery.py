"""Offline import and prioritization of passive public discovery results."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from .channel_health import extract_health_provenance, validate_health


_NAMESPACE = uuid.UUID("d95936fb-8251-482a-ab3a-9071191814f2")
CHANNEL_STATES = {"PLANNED", "EXECUTED", "NOT_APPLICABLE", "BLOCKED", "FAILED"}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?::[A-Za-z0-9][A-Za-z0-9._/-]{0,191})?$")
_KINDS = {"public_candidate", "repository_result", "deployment_result", "certificate_result", "custom_share_candidate"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _id(prefix: str, *parts: object) -> str:
    return f"{prefix}_{uuid.uuid5(_NAMESPACE, chr(31).join(map(str, parts))).hex}"


def _sanitize_url(value: str) -> tuple[str | None, str, str]:
    identity = hashlib.sha256(value.encode()).hexdigest()
    key = os.environ.get("SUDETECT_LOCATOR_HMAC_KEY")
    locator_ref = f"hmac-sha256:{hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()}" if key else f"opaque:{uuid.uuid4().hex}"
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None, locator_ref, identity
        port = parsed.port
        default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
        origin = urlunsplit((parsed.scheme, parsed.hostname.lower() + ("" if port is None or default else f":{port}"), "", "", ""))
        return origin, locator_ref, identity
    except ValueError:
        return None, locator_ref, identity


def _timestamp(value: Any, fallback: str) -> str:
    if value is None: return fallback
    if not isinstance(value, str) or len(value) > 40: return fallback
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        if parsed.tzinfo is None: return fallback
        parsed = parsed.astimezone(timezone.utc)
        if parsed > datetime.now(timezone.utc): return fallback
        return parsed.isoformat().replace("+00:00", "Z")
    except ValueError:
        return fallback


def _safe_ref(value: Any, fallback: str = "offline_import") -> str:
    if isinstance(value, str) and _REF_RE.fullmatch(value):
        return value
    return fallback


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _health_provenance(report: Any, channel_id: str) -> dict[str, Any]:
    try:
        controls=extract_health_provenance(report, [channel_id])
    except Exception:
        controls=[]
    return {"kind":"channel_health", "channel_id":channel_id, "controls":controls}


def _unit(value: Any, default: float) -> float:
    try: return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError): return default


def priority_score(
    ownership_confidence: float,
    expected_impact: float,
    novelty: float,
    information_gain: float,
    request_cost: float,
    time_cost: float,
    privacy_cost: float,
) -> float:
    """Documented heuristic, not a probability or proof of ownership.

    score = ownership × impact × novelty × information gain /
            (1 + request cost + time cost + privacy cost)
    All inputs are clamped to [0, 1].
    """
    values = [ownership_confidence, expected_impact, novelty, information_gain, request_cost, time_cost, privacy_cost]
    ownership, impact, new, gain, req, duration, privacy = [min(1.0, max(0.0, float(v))) for v in values]
    return round((ownership * impact * new * gain) / (1.0 + req + duration + privacy), 6)


def import_candidates(source: str | Path | Mapping[str, Any], *, scope_id: str,
                      locator_store: Any | None = None) -> dict[str, Any]:
    """Normalize an offline public-search export without crawling any candidate."""
    if not isinstance(scope_id, str) or not _ID_RE.fullmatch(scope_id): raise ValueError("invalid scope")
    if isinstance(source, Mapping):
        payload = dict(source)
    else:
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("invalid discovery import")
    channels = payload.get("channels")
    candidates = payload.get("candidates")
    if not isinstance(channels, list) or not isinstance(candidates, list):
        raise ValueError("invalid discovery import")
    imported_at = _now()
    observed_at = imported_at
    normalized_channels: list[dict[str, Any]] = []
    known_channels: set[str] = set()
    errors: list[str] = []
    seen_channels: set[str] = set()
    health_report = payload.get("channel_health")
    for item in channels:
        if not isinstance(item, Mapping) or not isinstance(item.get("channel_id"), str):
            errors.append("CHANNEL_INVALID")
            continue
        channel_id = item["channel_id"]
        if not _ID_RE.fullmatch(channel_id) or channel_id in seen_channels:
            errors.append("CHANNEL_INVALID")
            continue
        seen_channels.add(channel_id)
        state = str(item.get("state", "FAILED")).upper()
        if state not in CHANNEL_STATES:
            state = "FAILED"
            errors.append("CHANNEL_STATE_INVALID")
        known_channels.add(channel_id)
        supplied_time = item.get("observed_at") is not None
        channel_time = _timestamp(item.get("observed_at"), "") if supplied_time else imported_at
        if not channel_time:
            channel_time = imported_at; errors.append("TIMESTAMP_INVALID")
        if not supplied_time: errors.append("OBSERVED_AT_MISSING")
        supplied_source = _safe_ref(item.get("source_ref"), "")
        if not supplied_source: errors.append("SOURCE_REF_MISSING" if item.get("source_ref") is None else "SOURCE_REF_INVALID")
        if item.get("error_code") is not None and (not isinstance(item.get("error_code"), str) or not _CODE_RE.fullmatch(item["error_code"])): errors.append("ERROR_CODE_INVALID")
        error_code = str(item.get("error_code")) if isinstance(item.get("error_code"), str) and _CODE_RE.fullmatch(item["error_code"]) else None
        work_id = item.get("work_id") if isinstance(item.get("work_id"), str) and _ID_RE.fullmatch(item["work_id"]) else None
        end_condition = item.get("end_condition") if item.get("end_condition") in {"cursor_exhausted", "page_exhausted", "provider_empty", "import_verified"} else None
        if state == "EXECUTED" and work_id is None: errors.append("WORK_ID_MISSING")
        if state == "EXECUTED" and end_condition is None: errors.append("END_CONDITION_MISSING")
        provenance_complete = bool(supplied_time and supplied_source and work_id and end_condition and not error_code)
        health_errors: list[str] = []
        if state == "EXECUTED" and item.get("complete") is True and provenance_complete:
            parsed_channel_time = datetime.fromisoformat(channel_time.replace("Z", "+00:00"))
            health_errors = validate_health(health_report, [channel_id], now=parsed_channel_time)
            if health_errors:
                errors.extend("CHANNEL_HEALTH_" + code.upper() for code in health_errors)
        provenance_complete = provenance_complete and not health_errors
        normalized_channels.append({
            "channel_id": channel_id,
            "state": state,
            "observed_at": channel_time,
            "source_ref": supplied_source or None,
            "pages": _count(item.get("pages", 0)),
            "items": _count(item.get("items", 0)),
            "complete": item.get("complete") is True and provenance_complete and not health_errors if state == "EXECUTED" else False,
            "error_code": error_code, "work_id": work_id, "end_condition": end_condition,
            "provenance_complete": provenance_complete,
            "health_errors": ["CHANNEL_HEALTH_" + code.upper() for code in health_errors],
            "health_provenance": _health_provenance(health_report, channel_id),
        })
        if error_code: errors.append(error_code)
    normalized: list[dict[str, Any]] = []
    seen_candidates: set[str] = set()
    for item in candidates:
        if not isinstance(item, Mapping):
            errors.append("CANDIDATE_INVALID")
            continue
        locator = item.get("url")
        channel_id = item.get("channel_id")
        if not isinstance(locator, str) or not isinstance(channel_id, str) or channel_id not in known_channels:
            errors.append("CANDIDATE_INVALID")
            continue
        origin, locator_ref, locator_identity = _sanitize_url(locator)
        if origin is None:
            errors.append("CANDIDATE_INVALID")
            continue
        parent = item.get("parent_candidate_id")
        candidate_id = _id("can", scope_id, channel_id, locator_identity)
        if candidate_id in seen_candidates:
            errors.append("CANDIDATE_DUPLICATE")
            continue
        seen_candidates.add(candidate_id)
        score_inputs = item.get("score_inputs") if isinstance(item.get("score_inputs"), Mapping) else {}
        score = priority_score(
            _unit(score_inputs.get("ownership_confidence"), 0.1), _unit(score_inputs.get("expected_impact"), 0.5),
            _unit(score_inputs.get("novelty"), 0.5), _unit(score_inputs.get("information_gain"), 0.5),
            _unit(score_inputs.get("request_cost"), 0.5), _unit(score_inputs.get("time_cost"), 0.5),
            _unit(score_inputs.get("privacy_cost"), 0.5),
        )
        candidate_time = _timestamp(item.get("observed_at"), "") if item.get("observed_at") is not None else observed_at
        if not candidate_time:
            candidate_time = observed_at; errors.append("TIMESTAMP_INVALID")
        if item.get("source_ref") is not None and _safe_ref(item.get("source_ref"), "") == "": errors.append("SOURCE_REF_INVALID")
        if item.get("kind") is not None and item.get("kind") not in _KINDS: errors.append("KIND_INVALID")
        if parent is not None and (not isinstance(parent, str) or not _ID_RE.fullmatch(parent)): errors.append("PARENT_ID_INVALID")
        if locator_store is not None:
            locator_ref = locator_store.put(scope_id, locator)
            handoff_state = "ready"
        else:
            handoff_state = "blocked"
            errors.append("HANDOFF_BLOCKED")
        normalized.append({
            "candidate_id": candidate_id,
            "scope_id": scope_id,
            "url": origin,
            "locator_ref": locator_ref,
            "handoff_state": handoff_state,
            "kind": str(item.get("kind")) if item.get("kind") in _KINDS else "public_candidate",
            "workflow": "ownership_pending",
            "scope_decision": "pending",
            "channel_id": channel_id,
            "source_ref": _safe_ref(item.get("source_ref")),
            "observed_at": candidate_time,
            "parent_candidate_id": str(parent) if isinstance(parent, str) and _ID_RE.fullmatch(parent) else None,
            "pivot": {
                "state": "ownership_pending",
                "allowed_action": "ownership_verification_only",
                "network_request_authorized": False,
            },
            "priority": {"score": score, "heuristic_version": "ownership-impact-novelty-gain-cost-v1"},
        })
    required_channels = payload.get("required_channels", [])
    if not isinstance(required_channels, list) or any(not isinstance(x, str) or not _ID_RE.fullmatch(x) for x in required_channels):
        errors.append("REQUIRED_CHANNELS_INVALID"); required_channels = []
    missing_required = sorted(set(required_channels) - known_channels)
    if missing_required: errors.append("REQUIRED_CHANNEL_MISSING")
    states = {x["state"] for x in normalized_channels}
    fully_executed = (not missing_required and all(x["state"] == "NOT_APPLICABLE" or
                      (x["state"] == "EXECUTED" and x["complete"] and x["error_code"] is None)
                      for x in normalized_channels))
    status = "FAILED" if not normalized_channels or states == {"FAILED"} else ("COMPLETE" if fully_executed and not errors else "PARTIAL")
    return {
        "schema_version": "1.0", "discovery_id": _id("dsc", scope_id, observed_at),
        "scope_id": scope_id, "status": status, "observed_at": observed_at, "imported_at": imported_at,
        "required_channels": sorted(set(required_channels)), "missing_required_channels": missing_required,
        "channels": sorted(normalized_channels, key=lambda x: x["channel_id"]),
        "candidates": sorted(normalized, key=lambda x: x["candidate_id"]),
        "errors": sorted(set(errors)),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import passive discovery results without crawling.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--locator-store")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.locator_store:
            from .locators import LocatorStore
            with LocatorStore(args.locator_store) as store:
                report = import_candidates(args.input, scope_id=args.scope_id, locator_store=store)
        else:
            report = import_candidates(args.input, scope_id=args.scope_id)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        report = {"schema_version": "1.0", "scope_id": args.scope_id, "status": "FAILED", "channels": [], "candidates": [], "errors": ["IMPORT_INVALID"]}
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["status"] != "FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
