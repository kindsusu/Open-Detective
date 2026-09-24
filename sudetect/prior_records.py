"""Offline reconciliation of an explicitly supplied prior-review manifest.

Prior-review data is historical context only.  This module never reads a vault,
opens a locator, or inherits authorization from an earlier review.  Exact URLs,
captured bodies, credentials, and other raw secrets are deliberately outside the
small manifest shape accepted here.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


_REF = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,159}\Z")
_LOOKUP = {"verified", "none", "unavailable"}
_MAX_BYTES = 1_000_000
_MAX_RECORDS = 2_000
_REPARSE_POINT = 0x0400


class PriorRecordsError(ValueError):
    """Raised when an offline prior-review manifest is not safe to reconcile."""


def _reference(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value) or "://" in value:
        raise PriorRecordsError(f"INVALID_{field.upper()}")
    return value


def _timestamp(value: Any, field: str) -> str:
    # Normalize a valid ISO timestamp to UTC.  It remains provenance only, never a
    # freshness or authorization signal.  A date-only due value means midnight UTC.
    if not isinstance(value, str) or len(value) > 40 or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)?", value):
        raise PriorRecordsError(f"INVALID_{field.upper()}")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PriorRecordsError(f"INVALID_{field.upper()}") from exc
    if parsed.tzinfo is None:
        if "T" in value:
            raise PriorRecordsError(f"INVALID_{field.upper()}")
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    parsed = parsed.astimezone(dt.timezone.utc)
    return parsed.isoformat(timespec="microseconds" if parsed.microsecond else "seconds").replace("+00:00", "Z")


def _load_json(path: str | Path) -> Mapping[str, Any]:
    candidate = Path(path)
    try:
        if _has_reparse_ancestor(candidate) or not candidate.is_file():
            raise OSError("unsafe input")
        with candidate.open("rb") as stream:
            data = stream.read(_MAX_BYTES + 1)
    except OSError as exc:
        raise PriorRecordsError("MANIFEST_UNAVAILABLE") from exc
    if len(data) > _MAX_BYTES:
        raise PriorRecordsError("MANIFEST_TOO_LARGE")
    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PriorRecordsError("MANIFEST_INVALID_JSON") from exc
    if not isinstance(decoded, dict):
        raise PriorRecordsError("MANIFEST_NOT_OBJECT")
    return decoded


def _record_list(value: Any, field: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) > 500:
        raise PriorRecordsError(f"INVALID_{field.upper()}")
    if not all(isinstance(item, dict) for item in value):
        raise PriorRecordsError(f"INVALID_{field.upper()}")
    return value


def _is_reparse_path(path: Path) -> bool:
    """Detect symlinks and Windows junction/reparse points without resolving them."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _has_reparse_ancestor(path: Path) -> bool:
    absolute = path.absolute()
    return any(_is_reparse_path(part) for part in (absolute, *absolute.parents))


def reconcile(manifest: Mapping[str, Any], intake: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate and summarize historical records without granting current scope.

    ``intake`` is optional, explicit local operator input.  Its ``scope_id`` is
    recorded only as an association for the next ownership review; it neither
    authorizes a request nor changes unresolved historical assets into targets.
    """
    if manifest.get("schema_version") != "1.0":
        raise PriorRecordsError("UNSUPPORTED_SCHEMA_VERSION")
    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("kind") != "trusted_operator_export":
        raise PriorRecordsError("UNTRUSTED_SOURCE")
    export_ref = _reference(source.get("export_ref"), "export_ref")
    exported_at = _timestamp(source.get("exported_at"), "exported_at")
    reviews = _record_list(manifest.get("reviews"), "reviews")
    scope_id = None
    if intake is not None:
        if not isinstance(intake, Mapping):
            raise PriorRecordsError("INVALID_INTAKE")
        raw_scope = intake.get("scope_id")
        if raw_scope is not None:
            scope_id = _reference(raw_scope, "scope_id")

    known_assets: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    due: list[dict[str, str]] = []
    summaries: list[dict[str, Any]] = []
    known_assets_by_ref: dict[str, dict[str, Any]] = {}
    review_times: dict[str, str] = {}
    record_total = 0
    for review in reviews:
        review_ref = _reference(review.get("review_ref"), "review_ref")
        reviewed_at = _timestamp(review.get("reviewed_at"), "reviewed_at")
        if review_ref in review_times:
            if review_times[review_ref] != reviewed_at:
                raise PriorRecordsError("AMBIGUOUS_REVIEW_REF")
            raise PriorRecordsError("DUPLICATE_REVIEW_REF")
        review_times[review_ref] = reviewed_at
        lookup_status = review.get("lookup_status")
        if lookup_status not in _LOOKUP:
            raise PriorRecordsError("INVALID_LOOKUP_STATUS")
        assets = _record_list(review.get("known_assets", []), "known_assets")
        pending = _record_list(review.get("unresolved", []), "unresolved")
        scheduled = _record_list(review.get("due", []), "due")
        if lookup_status == "none" and assets:
            raise PriorRecordsError("LOOKUP_NONE_WITH_ASSETS")
        record_total += len(assets) + len(pending) + len(scheduled)
        if record_total > _MAX_RECORDS:
            raise PriorRecordsError("RECORD_LIMIT_EXCEEDED")
        for item in assets:
            asset_ref = _reference(item.get("record_ref"), "asset_record_ref")
            if asset_ref not in known_assets_by_ref:
                entry = {"record_ref": asset_ref, "review_refs": [review_ref],
                         "history_state": "recorded_history",
                         "current_scope_required": True}
                known_assets_by_ref[asset_ref] = entry
                known_assets.append(entry)
            elif review_ref not in known_assets_by_ref[asset_ref]["review_refs"]:
                known_assets_by_ref[asset_ref]["review_refs"].append(review_ref)
        for item in pending:
            unresolved.append({"record_ref": _reference(item.get("record_ref"), "unresolved_record_ref"),
                               "review_ref": review_ref,
                               "reason": _reference(item.get("reason_ref"), "reason_ref")})
        for item in scheduled:
            due.append({"record_ref": _reference(item.get("record_ref"), "due_record_ref"),
                        "review_ref": review_ref,
                        "due_at": _timestamp(item.get("due_at"), "due_at")})
        summaries.append({"review_ref": review_ref, "reviewed_at": reviewed_at,
                          "lookup_status": lookup_status,
                          # An unavailable lookup preserves recorded context, while
                          # making the missing coverage explicit; it never marks an
                          # asset open, unresolved, or in current scope.
                          "coverage_gaps": ["lookup_unavailable"] if lookup_status == "unavailable" else [],
                          "known_asset_count": len(assets), "unresolved_count": len(pending),
                          "due_count": len(scheduled)})
    return {
        "schema_version": "1.0",
        "source": {"kind": "trusted_operator_export", "trust": "declared_not_verified",
                   "export_ref": export_ref, "exported_at": exported_at},
        "authority": {"inherited": False, "network": "current_scope_required",
                      "current_scope_id": scope_id},
        "reviews": summaries,
        "known_assets": known_assets,
        "unresolved": unresolved,
        "due": due,
        "summary": {"review_count": len(summaries), "known_asset_count": len(known_assets),
                    "unresolved_count": len(unresolved), "due_count": len(due)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile an explicit trusted operator prior-review export offline")
    parser.add_argument("--manifest", required=True, help="explicit trusted-operator export JSON")
    parser.add_argument("--intake", help="optional explicit local intake JSON; no scope is inherited")
    parser.add_argument("--output", required=True, help="new local JSON summary path")
    args = parser.parse_args(argv)
    try:
        manifest = _load_json(args.manifest)
        intake = _load_json(args.intake) if args.intake else None
        result = reconcile(manifest, intake)
        output = Path(args.output)
        if output.exists() or _has_reparse_ancestor(output):
            raise PriorRecordsError("OUTPUT_ALREADY_EXISTS")
        if not output.parent.is_dir():
            raise PriorRecordsError("OUTPUT_PARENT_UNAVAILABLE")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except PriorRecordsError as exc:
        print(str(exc))
        return 2
    except OSError:
        print("LOCAL_FILE_ERROR")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
