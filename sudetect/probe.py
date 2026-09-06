"""JSONL command-line interface for the scope-bound HTTPS transport."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, TextIO

from .classifiers import analyze
from .evidence import clean_text, safe_url, stable_ref
from .policy import PolicyError, Scope
from .transport import FetchResult, fetch


def _load_scope(value: str) -> Scope:
    if len(value) > 1_048_576:
        raise PolicyError("scope input is too large")
    candidate = value.lstrip()
    if candidate.startswith("{"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            raise PolicyError("scope JSON could not be loaded") from None
        return Scope.from_dict(parsed)
    return Scope.load(value)


def _error_observation(scope: Scope, url: str, reason: str) -> dict[str, object]:
    return {
        "observation_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy_id": clean_text(scope.policy_id, 128),
        "target_ref": safe_url(url),
        "access": "INDETERMINATE",
        "content": "NOT_INSPECTED",
        "http_status": None,
        "sha256": None,
        "capture_complete": False,
        "reason": clean_text(reason, 128),
        "redirects": [],
    }


def _clean_label(label: str) -> str:
    if "://" in label:
        return safe_url(label)
    cleaned = clean_text(label, 128)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", cleaned):
        return cleaned
    return "<label-omitted>"


def _rows(stream: TextIO) -> Iterable[tuple[str, str]]:
    # split preserves empty and trailing TSV fields. Universal newline handling
    # accepts LF/CRLF and the final unterminated row.
    for raw in stream:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        fields = line.split("\t")
        url = fields[0]
        if not url or url.lstrip().startswith("#"):
            continue
        yield url, fields[1] if len(fields) > 1 else ""


def _run_one(scope: Scope, url: str, label: str = "", *, target_id: str | None = None) -> dict[str, object]:
    try:
        result: FetchResult = fetch(url, scope)
        observation = result.observation
        canonical = scope.authorize(url)
        # Without a configured correlation key, do not publish a dictionary-
        # attackable hash of a path that may contain a low-entropy secret.
        key = os.environ.get("SUDETECT_LOCATOR_HMAC_KEY")
        observation["target_id"] = target_id or (stable_ref(canonical, key) if key else "opaque:" + uuid.uuid4().hex)
        if isinstance(observation.get("http_status"), int):
            content_type = result.headers.get("content-type", "")
            if result.headers.get("content-encoding", "identity").casefold() in ("", "identity"):
                classification = analyze(result.body, content_type, canonical)
                if not observation.get("capture_complete"):
                    # The transport retained a bounded identity-encoded prefix.  Its
                    # signals are useful leads, but cannot establish that the whole
                    # response was reviewed or that no later content changes them.
                    classification.report["analysis_complete"] = False
                    classification.report["content_review_complete"] = False
                    classification.report["analysis_scope"] = "captured_prefix"
                observation.update(classification.report)
    except PolicyError as exc:
        observation = _error_observation(scope, url, str(exc))
    if label:
        observation["label"] = _clean_label(label)
    return observation


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "invalid_arguments\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(
        prog="su-detect-probe",
        description="Observe an explicitly owned HTTPS target and emit JSONL.",
    )
    parser.add_argument("--scope", help="scope JSON file or inline JSON (or set SU_SCOPE)")
    parser.add_argument("--batch", metavar="TSV", help="TSV containing URL and optional label")
    parser.add_argument("--locator-store")
    parser.add_argument("--locator-scope")
    parser.add_argument("--locator-ref")
    parser.add_argument("url", nargs="?", help="authorized HTTPS URL")
    parser.add_argument("label", nargs="?", help="optional display label")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    scope_value = args.scope or os.environ.get("SU_SCOPE")
    if not scope_value:
        print("scope_required", file=sys.stderr)
        return 2
    try:
        scope = _load_scope(scope_value)
    except PolicyError as exc:
        print(clean_text(exc, 128), file=sys.stderr)
        return 2
    if bool(args.batch) == bool(args.url or args.locator_ref):
        print("provide_one_url_or_batch", file=sys.stderr)
        return 2
    if args.batch:
        if any((args.locator_store, args.locator_scope, args.locator_ref)):
            print("batch_locator_combination_rejected", file=sys.stderr)
            return 2
        try:
            with Path(args.batch).open("r", encoding="utf-8", newline=None) as stream:
                for url, label in _rows(stream):
                    print(json.dumps(_run_one(scope, url, label), ensure_ascii=False, sort_keys=True))
        except (OSError, UnicodeError):
            print("batch_file_unreadable", file=sys.stderr)
            return 2
    else:
        from .locators import resolve_target
        try:
            url, target_id = resolve_target(args.url, args.locator_store, args.locator_scope, args.locator_ref)
        except (ValueError, OSError):
            print("invalid_locator_handoff", file=sys.stderr)
            return 2
        print(json.dumps(_run_one(scope, url, args.label or "", target_id=target_id), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
