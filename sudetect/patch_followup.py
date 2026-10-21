"""Explicit, resumable review of exact previously observed public commit patches.

Authenticated GitHub access is confined to commit metadata. Every patch and raw
file is measured through the ordinary anonymous, scope-bound transport. No raw
response body or credential is persisted in the case.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
from io import BytesIO
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .audit import Case
from .github_history import _patch_url_parts, analyze_repository_patch
from .followup_media import review_inline_media
from .media_review import _image_header, analyze_image, analyze_svg
from .policy import Scope
from .repository_commit import (_detail_parts, _next_detail_url, _raw_url,
                                analyze_commit_detail, commit_detail_url)
from .repository_workflow import _load as load_bindings, repository_job_authorized
from .transport import fetch

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".avif", ".tif", ".tiff"}
_BINARY_SUFFIX = {".zip", ".pdf", ".db", ".sqlite", ".sqlite3", ".parquet", ".gz",
                  ".7z", ".rar", ".docx", ".xlsx", ".pptx", ".wasm", ".exe",
                  ".dll", ".bin", ".ico", ".woff", ".woff2", ".ttf", ".otf"}
_BINARY_MAGIC = (b"%PDF-", b"PK\x03\x04", b"PK\x05\x06", b"SQLite format 3\x00",
                 b"PAR1", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
                 b"\x00asm", b"\x7fELF", b"MZ")
_BUDGET_KEYS = {"max_requests", "max_total_bytes", "max_patch_bytes", "max_file_bytes",
                "max_seconds", "max_attempts", "max_files", "max_ocr_seconds"}
ANALYSIS_VERSION = "patch-followup-20261021-2"


def _now():
    return datetime.now(timezone.utc)


def _expiry(value):
    if not isinstance(value, str):
        raise ValueError("followup_expiry_required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("followup_expiry_invalid") from None
    if result.tzinfo is None or result <= _now():
        raise ValueError("followup_expired")
    return result


def _manifest(case, source, scope):
    if not isinstance(source, dict) or set(source) != {"schema_version", "case_id", "authorization_ref",
                                                       "expires_at", "continue_sensitive_review", "asset_refs", "budgets"}:
        raise ValueError("followup_manifest_invalid")
    if source["schema_version"] != "1.0" or source["case_id"] != case.meta["case_id"]:
        raise ValueError("followup_case_mismatch")
    if not isinstance(source["authorization_ref"], str) or not _REF.fullmatch(source["authorization_ref"]):
        raise ValueError("followup_authorization_ref_invalid")
    if source["continue_sensitive_review"] is not True:
        raise ValueError("followup_sensitive_review_not_authorized")
    until = _expiry(source["expires_at"])
    if scope.expires_at <= _now():
        raise ValueError("scope_expired")
    refs = source["asset_refs"]
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 100
            or any(not isinstance(ref, str) for ref in refs) or len(refs) != len(set(refs))):
        raise ValueError("followup_asset_refs_invalid")
    budgets = source["budgets"]
    if not isinstance(budgets, dict) or set(budgets) - (_BUDGET_KEYS | {"max_pixels"}) or not _BUDGET_KEYS <= set(budgets) or any(
            type(budgets[key]) is not int or budgets[key] < 1 for key in _BUDGET_KEYS):
        raise ValueError("followup_budgets_invalid")
    if budgets["max_requests"] > 500 or budgets["max_files"] > 3000 or budgets["max_attempts"] > 10:
        raise ValueError("followup_budget_too_large")
    if (budgets["max_patch_bytes"] > 128 * 1024 * 1024 or
            budgets["max_file_bytes"] > 128 * 1024 * 1024 or
            budgets["max_total_bytes"] > 4 * 1024 * 1024 * 1024 or
            budgets["max_ocr_seconds"] > 300 or
            type(budgets.get("max_pixels", 25_000_000)) is not int or
            not 1 <= budgets.get("max_pixels", 25_000_000) <= 40_000_000):
        raise ValueError("followup_byte_or_time_budget_too_large")
    bindings = load_bindings(case)
    if bindings is None or _expiry(bindings["expires_at"]) <= _now():
        raise ValueError("repository_binding_expired")
    selected = {row["repository"]: row for row in bindings["repositories"]
                if row["ownership_status"] == "confirmed"}
    items = []
    for ref in refs:
        if not isinstance(ref, str) or not ref.startswith("opaque:"):
            raise ValueError("followup_asset_ref_invalid")
        url = case.locators.get(case.scope_id, ref)
        parts = _patch_url_parts(url)
        if parts is None or parts[0] not in selected or repository_job_authorized(case, url, scope) is not True:
            raise ValueError("followup_patch_not_bound_or_scoped")
        scope.authorize(url)
        items.append((ref, url, parts[0], parts[1]))
    return items, budgets, until


def _setup(case):
    case.ledger.db.executescript("""
        CREATE TABLE IF NOT EXISTS patch_followup_results(
          result_ref TEXT PRIMARY KEY, asset_ref TEXT NOT NULL, authorization_ref TEXT NOT NULL,
          attempt INTEGER NOT NULL, report_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS patch_followup_by_asset ON patch_followup_results(asset_ref,attempt);
        CREATE TRIGGER IF NOT EXISTS patch_followup_no_update BEFORE UPDATE ON patch_followup_results
          BEGIN SELECT RAISE(ABORT,'patch followup is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS patch_followup_no_delete BEFORE DELETE ON patch_followup_results
          BEGIN SELECT RAISE(ABORT,'patch followup is append-only'); END;
    """)


def _prior(case, ref, authorization_ref):
    row = case.ledger.db.execute("""SELECT attempt,report_json FROM patch_followup_results
        WHERE asset_ref=? AND authorization_ref=? ORDER BY attempt DESC LIMIT 1""",
        (ref, authorization_ref)).fetchone()
    return (int(row[0]), json.loads(row[1])) if row else (0, None)


def _version_attempts(case, ref, authorization_ref):
    count = 0
    for row in case.ledger.db.execute("""SELECT report_json FROM patch_followup_results
            WHERE asset_ref=? AND authorization_ref=?""", (ref, authorization_ref)):
        try:
            count += json.loads(row[0]).get("analyzer_version") == ANALYSIS_VERSION
        except (TypeError, ValueError):
            continue
    return count


def _append(case, ref, auth_ref, attempt, report):
    report_ref = "patch-followup:" + hashlib.sha256(
        f"{case.meta['case_id']}:{auth_ref}:{ref}:{attempt}".encode()).hexdigest()[:32]
    with case.ledger.db:
        case.ledger.db.execute("INSERT INTO patch_followup_results VALUES(?,?,?,?,?)",
                               (report_ref, ref, auth_ref, attempt, json.dumps(report, ensure_ascii=False)))
        case.ledger._event("PATCH_FOLLOWUP_RESULT", ref,
                           {"result_ref": report_ref, "authorization_ref": auth_ref,
                            "attempt": attempt, "processing_complete": report["processing_complete"]})
    return report_ref


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _authenticated_metadata(url, token, max_bytes, timeout):
    # Exact API endpoint is validated before this function. Token is never passed
    # into anonymous transport, reports, exceptions, or command arguments.
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "open-detective-owner-inventory/1"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            return int(response.status), body, response.headers.get("Link", ""), {
                "retry_after": response.headers.get("Retry-After", ""),
                "rate_remaining": response.headers.get("X-RateLimit-Remaining", ""),
                "rate_reset": response.headers.get("X-RateLimit-Reset", "")}
    except urllib.error.HTTPError as exc:
        return int(exc.code), b"", "", {
            "retry_after": exc.headers.get("Retry-After", ""),
            "rate_remaining": exc.headers.get("X-RateLimit-Remaining", ""),
            "rate_reset": exc.headers.get("X-RateLimit-Reset", "")}
    except (OSError, ValueError):
        return 0, b"", "", {}


def _safe_signals(profile):
    result = []
    for item in profile.get("signals", []):
        if isinstance(item, dict) and isinstance(item.get("code"), str):
            result.append(item["code"])
    return sorted(set(result))


def _material_codes(codes):
    return any(isinstance(code, str) and code.endswith("_CANDIDATE")
               and code != "RUNTIME_ENDPOINT_CANDIDATE" for code in codes)


def _file_review(body, path, content_type, *, max_seconds, max_pixels):
    # Only category and counts are persisted; full filenames, body and OCR text
    # stay transient. A full before/after file is never labeled a hunk diff.
    suffix = Path(path).suffix.casefold()
    deadline = time.monotonic() + max_seconds
    if suffix in _IMAGE or _image_header(body) is not None:
        profile = analyze_image(body, content_type, max_seconds=min(max_seconds, 300),
                                max_bytes=min(len(body) or 1, 32 * 1024 * 1024),
                                max_pixels=max_pixels)
        metadata_present = None
        try:
            from PIL import Image
            with Image.open(BytesIO(body)) as picture:
                metadata_present = bool(picture.getexif())
        except (ImportError, OSError, ValueError):
            pass
        return {"kind": "image", "ocr_state": profile.get("ocr_state"),
                "signal_codes": _safe_signals(profile), "content": profile.get("content"),
                "embedded_metadata_present": metadata_present,
                "visual_review_remaining": not bool(profile.get("image_review_complete")),
                "pending_reviews": sorted(set(profile.get("pending_reviews", [])))}
    if suffix in _BINARY_SUFFIX or body.startswith(_BINARY_MAGIC) or b"\x00" in body[:4096]:
        return {"kind": "unsupported_binary", "text_analysis_complete": False,
                "signal_codes": [], "findings": [], "content": "NOT_INSPECTED",
                "visual_review_remaining": False,
                "pending_reviews": ["unsupported_binary_format"]}
    if suffix == ".svg" or body.lstrip()[:200].startswith((b"<svg", b"<?xml")) and b"<svg" in body[:4096]:
        vector = analyze_svg(body, max_bytes=min(len(body) or 1, 8_388_608))
        return {"kind": "svg", "text_analysis_complete": bool(vector["text_analysis_complete"]),
                "signal_codes": _safe_signals(vector), "findings": [],
                "content": vector["content"], "visual_review_remaining": True,
                "pending_reviews": sorted(set(vector["pending_reviews"]))}
    from .candidate_review import review_candidate_bytes
    inferred = {".json": "application/json", ".html": "text/html", ".htm": "text/html",
                ".js": "application/javascript", ".mjs": "application/javascript",
                ".css": "text/css", ".csv": "text/csv", ".xml": "application/xml"}.get(suffix)
    profile = review_candidate_bytes(body, content_type=inferred or content_type or "application/octet-stream",
                                     max_bytes=min(len(body) or 1, 128 * 1024 * 1024),
                                     max_seconds=min(max_seconds, 300))
    pending = set(profile["pending_reviews"])
    inline_summary = None
    if b"data:image/" in body and deadline - time.monotonic() > 0.001:
        inline = review_inline_media(body,
                                     max_seconds=max(0.001, min(deadline - time.monotonic(), 300)),
                                     max_pixels=max_pixels)
        inline_summary = {key: inline[key] for key in
                          ("inline_images_found", "inline_images_examined", "inline_images_remaining",
                           "ocr_completed", "decoded_bytes_examined", "ocr_coverage_complete", "signal_counts")}
        pending.update(inline["pending_reviews"])
        if inline["ocr_coverage_complete"]:
            pending.discard("inline_image_ocr_unexamined")
    return {"kind": "text_or_binary", "text_analysis_complete": profile["text_analysis_complete"],
            "signal_codes": sorted(set(profile["candidate_signal_codes"]) |
                                   set((inline_summary or {}).get("signal_counts", {}))),
            "findings": profile["findings"],
            "content": "SENSITIVE_CANDIDATE" if profile["findings"] or
                _material_codes(profile["candidate_signal_codes"]) or
                _material_codes((inline_summary or {}).get("signal_counts", {})) else "NOT_INSPECTED",
            "inline_image_review": inline_summary, "pending_reviews": sorted(pending)}


def _retry_due(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    if value.isdecimal():
        try:
            return time.time() + int(value)
        except OverflowError:
            return None
    try:
        due = parsedate_to_datetime(value)
        return due.timestamp() if due.tzinfo else None
    except (TypeError, ValueError, OverflowError):
        return None


def _project_exact_diff(body, sha):
    """Wrap observed .diff bytes for the mail-patch parser without claiming .patch capture."""
    if not isinstance(body, bytes) or not body.startswith(b"diff --git a/") or b"\x00" in body:
        return None
    try:
        body.decode("utf-8", "strict")
    except UnicodeError:
        return None
    header = (f"From {sha} Mon Sep 17 00:00:00 2001\n"
              "From: Open-Detective <local-projection@invalid.test>\n"
              "Date: Thu, 1 Jan 1970 00:00:00 +0000\n"
              "Subject: [PATCH] Exact GitHub diff projection\n\n").encode()
    return header + body


def _metadata_pages(detail_url, scope, token, budgets, request, remaining_bytes, charge_bytes,
                    remaining_seconds, *, metadata_fetcher=None):
    if not token:
        return None, "authenticated_metadata_unavailable", [], None
    slug, sha, _ = _detail_parts(detail_url)
    page_url = detail_url
    rows, evidence = [], []
    parent = None
    for page in range(1, 31):
        if not request():
            return None, "request_budget_reached", evidence, None
        scope.authorize(page_url)
        limit = min(budgets["max_file_bytes"], remaining_bytes())
        if limit < 1:
            return None, "metadata_byte_budget_reached", evidence, None
        fetched = (metadata_fetcher(page_url, token, limit, min(scope.timeout, max(0.1, remaining_seconds())))
                   if metadata_fetcher else _authenticated_metadata(
                       page_url, token, limit, min(scope.timeout, max(0.1, remaining_seconds()))))
        status, body, link = fetched[:3]
        headers = fetched[3] if len(fetched) == 4 and isinstance(fetched[3], dict) else {}
        charge_bytes(len(body))
        rate_due = None
        if (status in {403, 429} and headers.get("rate_remaining") == "0"
                and isinstance(headers.get("rate_reset"), str)
                and headers["rate_reset"].isdecimal()):
            rate_due = float(headers["rate_reset"])
        retry_due = _retry_due(headers.get("retry_after", ""))
        if status != 200 or len(body) > limit:
            evidence.append({"page": page, "status": status, "access_mode": "authenticated_metadata"})
            return None, "metadata_response_incomplete", evidence, (
                max(rate_due or 0, retry_due or 0) or (time.time() + 60 if status in {429, 503} else None))
        report, _ = analyze_commit_detail(body, page_url, link_header=link,
                                          max_bytes=min(budgets["max_file_bytes"], 32 * 1024 * 1024))
        if not report["file_list_page_complete"]:
            return None, "metadata_provenance_incomplete", evidence, None
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return None, "metadata_parse_failed", evidence, None
        if payload["sha"].casefold() != sha or len(payload["files"]) != report["files_observed"]:
            return None, "metadata_sha_or_files_mismatch", evidence, None
        actual_parent = [p["sha"].casefold() for p in payload["parents"]]
        if any(not _SHA.fullmatch(p) for p in actual_parent) or (parent is not None and actual_parent != parent):
            return None, "metadata_parent_mismatch", evidence, None
        parent = actual_parent
        rows.extend(payload["files"])
        evidence.append({"page": page, "status": status, "sha256": hashlib.sha256(body).hexdigest(),
                         "files_observed": len(payload["files"]), "access_mode": "authenticated_metadata"})
        next_url, invalid = _next_detail_url(link, slug, sha, page)
        if invalid or (not next_url and len(payload["files"]) == 100):
            return None, "metadata_pagination_incomplete", evidence, None
        if not next_url:
            return (rows, parent), None, evidence, None
        page_url = next_url
    return None, "metadata_page_limit", evidence, None


def review(case_path, scope_path, manifest_path, *, output=None, token_env=None,
           anonymous_fetcher=None, metadata_fetcher=None):
    """Process an exact local manifest; return a value-free summary.

    ``anonymous_fetcher`` has the same signature as transport.fetch and is only
    for deterministic tests. ``metadata_fetcher`` has the private API signature.
    """
    scope = Scope.load(scope_path)
    source_path = Path(manifest_path)
    if source_path.stat().st_size > 1_048_576 or source_path.is_symlink():
        raise ValueError("followup_manifest_invalid")
    source = json.loads(source_path.read_text(encoding="utf-8"))
    output_path = Path(output) if output is not None else None
    if output_path is not None and (output_path.is_symlink() or output_path.exists()):
        raise ValueError("followup_output_must_be_new")
    if token_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", token_env):
        raise ValueError("metadata_token_env_unavailable")
    # Remove the explicit owner-inventory token from the process environment
    # before image OCR subprocesses can inherit it.
    token = os.environ.pop(token_env, "") if token_env else ""
    if token_env and not token:
        raise ValueError("metadata_token_env_unavailable")
    fetcher = anonymous_fetcher or fetch
    with Case(case_path) as case:
        items, budgets, until = _manifest(case, source, scope)
        _setup(case)
        started = time.monotonic()
        requests = total_bytes = 0
        deadline = started + budgets["max_seconds"]
        origin_cooldowns = {}
        for row in case.ledger.db.execute("SELECT report_json FROM patch_followup_results"):
            try:
                previous = json.loads(row[0])
                for origin, due in previous.get("provider_cooldowns", {}).items():
                    if origin in {"https://github.com", "https://api.github.com",
                                  "https://raw.githubusercontent.com"} and type(due) in {int, float} and due > time.time():
                        origin_cooldowns[origin] = max(origin_cooldowns.get(origin, 0), due)
            except (TypeError, ValueError):
                continue
        def remaining_seconds():
            return max(0.0, deadline - time.monotonic())
        aggregate = {"case_id": case.meta["case_id"], "authorization_ref": source["authorization_ref"],
                     "selected": len(items), "already_complete": 0, "attempted": 0,
                     "processing_complete": 0, "overall_verified": 0, "remaining": 0,
                     "requests": 0, "bytes_captured": 0, "results": []}

        def reserve():
            nonlocal requests
            if _now() >= until or scope.expires_at <= _now() or remaining_seconds() <= 0:
                return False
            if requests >= min(budgets["max_requests"], scope.max_requests):
                return False
            requests += 1
            return True

        def anonymous(url, limit):
            nonlocal total_bytes
            parsed = urlsplit(url)
            if origin_cooldowns.get(f"{parsed.scheme}://{parsed.netloc}", 0) > time.time():
                return None
            if not reserve() or total_bytes >= budgets["max_total_bytes"]:
                return None
            if repository_job_authorized(case, url, scope) is not True:
                raise ValueError("raw_file_not_bound_or_scoped")
            scope.authorize(url)
            result = fetcher(url, scope, follow_redirects=False,
                             max_bytes=min(limit, budgets["max_total_bytes"] - total_bytes),
                             timeout=min(scope.timeout, max(0.1, remaining_seconds())))
            total_bytes += len(result.body)
            return result

        def _charge_metadata(amount):
            nonlocal total_bytes
            total_bytes += amount

        def hold(record, origin, due):
            if type(due) not in {int, float} or due <= time.time():
                return
            origin_cooldowns[origin] = max(origin_cooldowns.get(origin, 0), due)
            record.setdefault("provider_cooldowns", {})[origin] = origin_cooldowns[origin]
            record["retry_after_epoch"] = max(record.get("retry_after_epoch", 0), due)

        for ref, url, repository, sha in items:
            attempt, prior = _prior(case, ref, source["authorization_ref"])
            same_version = prior is not None and prior.get("analyzer_version") == ANALYSIS_VERSION
            version_attempts = _version_attempts(case, ref, source["authorization_ref"])
            if same_version and prior.get("processing_complete"):
                aggregate["already_complete"] += 1
                aggregate["processing_complete"] += 1
                aggregate["overall_verified"] += bool(prior.get("overall_verified"))
                continue
            if (version_attempts >= budgets["max_attempts"] or remaining_seconds() <= 0
                    or requests >= min(budgets["max_requests"], scope.max_requests)
                    or total_bytes >= budgets["max_total_bytes"]):
                aggregate["remaining"] += 1
                continue
            if same_version and prior.get("retry_after_epoch", 0) > time.time():
                aggregate["remaining"] += 1
                continue
            aggregate["attempted"] += 1
            record = {"asset_ref": ref, "repository_ref": hashlib.sha256(repository.encode()).hexdigest()[:24],
                      "commit_sha": sha, "observed_at": _now().isoformat(),
                      "analyzer_version": ANALYSIS_VERSION,
                      "metadata_access": "not_requested", "anonymous_measurement": [],
                      "text_review": "not_inspected", "file_comparison": "not_inspected",
                      "candidate_review": "not_inspected", "visual_review_remaining": False,
                      "processing_complete": False, "overall_verified": False, "pending_reviews": []}
            patch = anonymous(url, budgets["max_patch_bytes"])
            if patch is None:
                record["pending_reviews"].append("request_or_byte_budget_reached")
            else:
                obs = patch.observation
                record["anonymous_measurement"].append({"kind": "patch", "http_status": obs.get("http_status"),
                    "capture_complete": bool(obs.get("capture_complete")), "sha256": obs.get("sha256"),
                    "bytes_captured": len(patch.body), "access_mode": "anonymous"})
                if obs.get("http_status") in {429, 503}:
                    due = _retry_due(patch.headers.get("retry-after", ""))
                    if due:
                        hold(record, "https://github.com", due)
                review_body = None
                if obs.get("http_status") == 200 and obs.get("capture_complete"):
                    record["patch_anonymous_captured"] = True
                    review_body = patch.body
                elif obs.get("http_status") == 503 and not record.get("retry_after_epoch"):
                    diff_url = url[:-6] + ".diff"
                    diff_result = anonymous(diff_url, budgets["max_patch_bytes"])
                    if diff_result is not None:
                        diff_obs = diff_result.observation
                        record["anonymous_measurement"].append({"kind": "exact_commit_diff_fallback",
                            "http_status": diff_obs.get("http_status"),
                            "capture_complete": bool(diff_obs.get("capture_complete")),
                            "sha256": diff_obs.get("sha256"), "bytes_captured": len(diff_result.body),
                            "access_mode": "anonymous"})
                        if diff_obs.get("http_status") == 200 and diff_obs.get("capture_complete"):
                            review_body = _project_exact_diff(diff_result.body, sha)
                            if review_body is not None and len(review_body) <= budgets["max_patch_bytes"]:
                                record["diff_anonymous_captured"] = True
                                record["diff_fallback_projection"] = "local_mail_envelope_for_parser"
                            else:
                                review_body = None
                                record["pending_reviews"].append("diff_fallback_invalid_or_oversize")
                        elif diff_obs.get("http_status") in {429, 503}:
                            due = _retry_due(diff_result.headers.get("retry-after", ""))
                            if due:
                                hold(record, "https://github.com", due)
                    if not record.get("diff_anonymous_captured"):
                        hold(record, "https://github.com", time.time() + 60)
                elif obs.get("http_status") == 429 and not record.get("retry_after_epoch"):
                    hold(record, "https://github.com", time.time() + 60)
                if review_body is not None:
                    profile = analyze_repository_patch(review_body, url, case.locators, case.scope_id,
                        max_bytes=budgets["max_patch_bytes"], continue_sensitive_review=True)
                    record["patch_analysis_complete"] = bool(profile.get("analysis_complete"))
                    record["patch_text_analysis_complete"] = bool(profile.get("text_analysis_complete"))
                    record["patch_parse_valid"] = isinstance(profile.get("changed_files"), list)
                    record["text_review"] = profile.get("content_review", "not_inspected")
                    record["pending_reviews"].extend(profile.get("pending_reviews", []))
                    record["candidate_review"] = ("candidate_detected" if profile.get("sensitivity_candidate")
                                                  else "no_candidate_signal_detected")
                    record["signal_codes"] = sorted(set(profile.get("signal_codes", [])))
                    from .candidate_review import review_candidate_bytes
                    candidate = review_candidate_bytes(review_body, content_type="text/plain",
                        max_bytes=min(len(review_body) or 1, budgets["max_patch_bytes"]),
                        max_seconds=max(0.001, min(300, budgets["max_ocr_seconds"], remaining_seconds())))
                    record["candidate_findings"] = candidate["findings"]
                    record["candidate_review"] = ("candidate_detected" if candidate["findings"] or
                        profile.get("sensitivity_candidate") or _material_codes(candidate["candidate_signal_codes"])
                        else "no_candidate_signal_detected")
                    record["patch_candidate_text_complete"] = candidate["text_analysis_complete"]
                    record["pending_reviews"].extend(candidate["pending_reviews"])
                    if b"data:image/" in review_body:
                        inline = review_inline_media(review_body,
                            max_seconds=max(0.001, min(300, budgets["max_ocr_seconds"], remaining_seconds())),
                            max_pixels=budgets.get("max_pixels", 25_000_000))
                        record["inline_image_review"] = {key: inline[key] for key in
                            ("inline_images_found", "inline_images_examined", "inline_images_remaining",
                             "ocr_completed", "decoded_bytes_examined", "ocr_coverage_complete", "signal_counts")}
                        record["signal_codes"] = sorted(set(record["signal_codes"]) | set(inline["signal_counts"]))
                        if _material_codes(inline["signal_counts"]):
                            record["candidate_review"] = "candidate_detected"
                        record["visual_review_remaining"] = inline["inline_images_found"] > 0
                        record["pending_reviews"].extend(inline["pending_reviews"])
                        if inline["ocr_coverage_complete"]:
                            record["pending_reviews"] = [reason for reason in record["pending_reviews"]
                                                         if reason != "inline_image_ocr_unexamined"]
                else:
                    record["pending_reviews"].append("patch_anonymous_capture_incomplete")
                    record["patch_analysis_complete"] = False
                if not record.get("patch_anonymous_captured"):
                    record["pending_reviews"].append("patch_anonymous_capture_incomplete")

            # Commit metadata may close binary/missing-hunk/file-list gaps. The
            # private token remains exclusively inside this call.
            detail_url = commit_detail_url(url)
            if detail_url is None or repository_job_authorized(case, detail_url, scope) is not True:
                record["pending_reviews"].append("commit_metadata_not_scoped")
            elif origin_cooldowns.get("https://api.github.com", 0) > time.time():
                record["pending_reviews"].append("metadata_provider_cooldown")
                record["retry_after_epoch"] = max(record.get("retry_after_epoch", 0),
                                                   origin_cooldowns["https://api.github.com"])
            else:
                pages, error, evidence, retry_due = _metadata_pages(detail_url, scope, token, budgets, reserve,
                                                                     lambda: budgets["max_total_bytes"] - total_bytes,
                                                                     lambda amount: _charge_metadata(amount),
                                                                     remaining_seconds,
                                                                     metadata_fetcher=metadata_fetcher)
                record["metadata_access"] = "authenticated_metadata" if token else "not_available"
                record["metadata_evidence"] = evidence
                if retry_due:
                    hold(record, "https://api.github.com", retry_due)
                if error:
                    record["pending_reviews"].append(error)
                elif pages:
                    files, parents = pages
                    if len(files) > budgets["max_files"]:
                        record["pending_reviews"].append("file_count_budget_reached")
                    elif len(parents) > 1:
                        record["pending_reviews"].append("merge_parent_comparison_incomplete")
                    else:
                        comparisons = []
                        raw_complete = True
                        prior_files = {item["file_key"]: item for item in prior.get("file_review_summary", [])
                                       if isinstance(item, dict) and isinstance(item.get("file_key"), str)} \
                            if same_version and prior.get("metadata_evidence") == evidence else {}
                        for row in files:
                            status, path, previous = row.get("status"), row.get("filename"), row.get("previous_filename")
                            if status not in {"added", "removed", "modified", "changed", "renamed", "copied"}:
                                record["pending_reviews"].append("file_status_invalid")
                                break
                            file_key = hashlib.sha256(
                                f"{status}\0{path}\0{previous or ''}".encode("utf-8")).hexdigest()
                            saved = prior_files.get(file_key)
                            expected_revisions = 1 if status in {"added", "removed"} else 2
                            if (saved and saved.get("status") == status
                                    and isinstance(saved.get("revision_reviews"), list)
                                    and len(saved["revision_reviews"]) == expected_revisions
                                    and all(not any(reason in rev.get("pending_reviews", []) for reason in
                                            ("capture_incomplete", "image_byte_limit", "image_pixel_limit",
                                             "candidate_review_byte_or_time_limit", "candidate_review_time_limit",
                                             "candidate_projection_incomplete", "inline_image_ocr_unexamined",
                                             "unsupported_binary_format", "svg_capture_or_byte_limit",
                                             "svg_parse_or_entity_review"))
                                            and (rev.get("kind") != "image" or rev.get("ocr_state") == "completed")
                                            and (rev.get("kind") not in {"text_or_binary", "svg"}
                                                 or rev.get("text_analysis_complete") is True)
                                            for rev in saved["revision_reviews"])):
                                comparisons.append({"file_key": file_key, "status": status,
                                                    "revisions": saved["revision_reviews"]})
                                record["reused_file_count"] = record.get("reused_file_count", 0) + 1
                                continue
                            paths = []
                            if status != "removed":
                                paths.append(("after", sha, path))
                            if status != "added":
                                if not parents:
                                    record["pending_reviews"].append("first_parent_missing")
                                    break
                                paths.append(("before", parents[0], previous if status in {"renamed", "copied"} else path))
                            file_row = {"file_key": file_key, "status": status, "revisions": []}
                            for revision, revision_sha, name in paths:
                                raw_url = _raw_url(repository, revision_sha, name)
                                if raw_url is None:
                                    record["pending_reviews"].append("raw_path_invalid")
                                    raw_complete = False
                                    break
                                if remaining_seconds() <= 0:
                                    record["pending_reviews"].append("followup_time_budget_reached")
                                    raw_complete = False
                                    break
                                captured = anonymous(raw_url, budgets["max_file_bytes"])
                                if captured is None:
                                    record["pending_reviews"].append("raw_budget_reached")
                                    raw_complete = False
                                    break
                                raw_obs = captured.observation
                                safe = {"kind": "raw_file", "revision": revision, "status": raw_obs.get("http_status"),
                                        "capture_complete": bool(raw_obs.get("capture_complete")),
                                        "sha256": raw_obs.get("sha256"), "bytes_captured": len(captured.body),
                                        "access_mode": "anonymous"}
                                record["anonymous_measurement"].append(safe)
                                if raw_obs.get("http_status") != 200 or not raw_obs.get("capture_complete"):
                                    record["pending_reviews"].append("raw_file_capture_incomplete")
                                    if raw_obs.get("http_status") in {429, 503}:
                                        due = _retry_due(captured.headers.get("retry-after", ""))
                                        hold(record, "https://raw.githubusercontent.com", due or time.time() + 60)
                                    raw_complete = False
                                    break
                                file_row["revisions"].append({"revision": revision,
                                    "sha256": raw_obs.get("sha256"),
                                    **_file_review(captured.body, name, captured.headers.get("content-type", ""),
                                                   max_seconds=max(0.001, min(budgets["max_ocr_seconds"], remaining_seconds())),
                                                   max_pixels=budgets.get("max_pixels", 25_000_000))})
                                file_row["revisions"][-1]["file_locator_ref"] = case.locators.put(case.scope_id, raw_url)
                            comparisons.append(file_row)
                            if record["pending_reviews"] and record["pending_reviews"][-1] in {
                                    "raw_path_invalid", "raw_budget_reached", "raw_file_capture_incomplete",
                                    "followup_time_budget_reached"}:
                                break
                        record["file_comparison"] = ("full_before_after_files" if raw_complete and len(comparisons) == len(files)
                                                     and all(len(item["revisions"]) == (1 if item["status"] in {"added", "removed"} else 2)
                                                             for item in comparisons) else "partial")
                        record["files_compared"] = len(comparisons)
                        record["files_reported"] = len(files)
                        record["file_review_summary"] = [{"file_key": item["file_key"], "status": item["status"],
                            "revision_count": len(item["revisions"]),
                            "revision_reviews": item["revisions"],
                            "byte_comparison": ("changed" if item["revisions"][0]["sha256"] != item["revisions"][1]["sha256"]
                                                else "identical") if len(item["revisions"]) == 2 else "single_revision",
                            "signal_codes": sorted({code for rev in item["revisions"] for code in rev.get("signal_codes", [])}),
                            "candidate_findings": [finding for rev in item["revisions"]
                                                   for finding in rev.get("findings", [])],
                            "pending_reviews": sorted({reason for rev in item["revisions"]
                                                       for reason in rev.get("pending_reviews", [])}),
                            "ocr_states": [rev.get("ocr_state") for rev in item["revisions"] if rev.get("kind") == "image"],
                            "embedded_metadata_present": [rev.get("embedded_metadata_present") for rev in item["revisions"]
                                                          if rev.get("kind") == "image"],
                            "inline_image_reviews": [rev.get("inline_image_review") for rev in item["revisions"]
                                                     if rev.get("inline_image_review") is not None]}
                            for item in comparisons]
                        record["visual_review_remaining"] |= any(
                            rev.get("visual_review_remaining", False) for item in comparisons for rev in item["revisions"])
                        if any(rev.get("content") == "SENSITIVE_CANDIDATE" for item in comparisons for rev in item["revisions"]):
                            record["candidate_review"] = "candidate_detected"
                        record["pending_reviews"].extend(
                            reason for item in comparisons for rev in item["revisions"]
                            for reason in rev.get("pending_reviews", []))
            record["pending_reviews"] = sorted(set(record["pending_reviews"]))
            unresolved_processing = {"raw_file_capture_incomplete", "raw_budget_reached", "file_count_budget_reached",
                "metadata_response_incomplete", "metadata_provenance_incomplete", "candidate_review_byte_or_time_limit",
                "candidate_review_time_limit", "candidate_classifier_text_incomplete",
                "candidate_projection_incomplete", "image_byte_limit",
                "unsupported_binary_format", "svg_capture_or_byte_limit", "svg_parse_or_entity_review",
                "image_pixel_limit", "ocr_unavailable", "ocr_failed", "ocr_timeout",
                "inline_image_byte_limit", "inline_image_time_limit", "inline_image_count_or_budget_limit",
                "inline_image_ocr_unexamined", "inline_image_ocr_incomplete", "followup_inline_body_byte_limit",
                "request_or_byte_budget_reached", "followup_time_budget_reached"}
            patch_content_supported = (record.get("patch_text_analysis_complete") is True or
                "binary_patch_not_inspected" in record["pending_reviews"] or
                "patch_has_no_text_hunks" in record["pending_reviews"])
            if "binary_patch_not_inspected" in record["pending_reviews"]:
                record["binary_hunks_not_decoded"] = True
            record["processing_complete"] = ((record.get("patch_anonymous_captured") is True or
                                              record.get("diff_anonymous_captured") is True)
                and record.get("patch_parse_valid") is True
                and record.get("patch_candidate_text_complete") is True
                and patch_content_supported
                and record["file_comparison"] == "full_before_after_files"
                and not any(reason in record["pending_reviews"] for reason in unresolved_processing)
                and all(state == "completed" for item in record.get("file_review_summary", [])
                        for state in item.get("ocr_states", []))
                and all(rev.get("text_analysis_complete") is True for item in record.get("file_review_summary", [])
                        for rev in item.get("revision_reviews", []) if rev.get("kind") in {"text_or_binary", "svg"})
                and record.get("inline_image_review", {}).get("ocr_coverage_complete", True) is True
                and all(rev.get("inline_image_review") is None or
                        rev["inline_image_review"].get("ocr_coverage_complete") is True
                        for item in record.get("file_review_summary", []) for rev in item.get("revision_reviews", [])))
            if not record["processing_complete"] and version_attempts + 1 >= budgets["max_attempts"]:
                record["terminal_disposition"] = "attempt_limit_with_remaining_gaps"
            record["overall_verified"] = (record["processing_complete"] and not record["pending_reviews"]
                                          and not record["visual_review_remaining"]
                                          and record["candidate_review"] == "no_candidate_signal_detected")
            result_ref = _append(case, ref, source["authorization_ref"], attempt + 1, record)
            aggregate["results"].append({"asset_ref": ref, "result_ref": result_ref,
                "processing_complete": record["processing_complete"],
                "overall_verified": record["overall_verified"],
                "pending_reviews": record["pending_reviews"]})
            aggregate["processing_complete"] += bool(record["processing_complete"])
            aggregate["overall_verified"] += bool(record["overall_verified"])
            aggregate["remaining"] += not record["processing_complete"]
        aggregate["requests"] = requests
        aggregate["bytes_captured"] = total_bytes
    if output_path is not None:
        with output_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(aggregate, ensure_ascii=False, indent=2) + "\n")
    return aggregate


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Review exact authorized commit patches in an existing case")
    parser.add_argument("--case", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--token-env", help="Name of environment variable containing owner inventory token")
    args = parser.parse_args(argv)
    try:
        summary = review(args.case, args.scope, args.manifest, output=args.output, token_env=args.token_env)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Print a controlled code, never provider errors, source, file paths or credentials.
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z_]+", str(exc)) else "followup_failed"
        parser.exit(2, code + "\n")
    print(json.dumps({key: summary[key] for key in ("selected", "attempted", "already_complete",
                     "processing_complete", "overall_verified", "remaining", "requests", "bytes_captured")}))
    return 0 if summary["remaining"] == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
