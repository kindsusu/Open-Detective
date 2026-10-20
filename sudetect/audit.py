"""Agent-independent, resumable orchestration over the existing ledger and locators.

Raw captures live only for the bounded run interval. The case directory is private
operational state: search seeds and exact locators must never be published.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
from urllib.parse import urljoin, urlsplit
import uuid

from .ledger import Ledger
from .locators import LocatorStore
from .policy import PolicyError, Scope, _normalize_url
from .scheduler import Scheduler

_RETRY_REASONS = {"request budget exhausted", "timeout", "dns_failure", "connection_reset",
                  "connection_refused", "request timed out", "transport_error"}
_RETRY_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
_COOLDOWN_HTTP_STATUSES = frozenset({429, 503})
_INSPECTION_JOB_TYPES = frozenset({
    "capture", "repository_tree", "repository_history", "repository_patch",
    "repository_commit_detail", "content_review"})
_MEDIA_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp",
                   ".tif", ".tiff", ".svg", ".woff", ".woff2", ".ttf", ".ico"}


class _RetryCapture(Exception):
    def __init__(self, reference=None, due_at=None):
        self.reference = reference
        self.due_at = due_at


def _origin(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _retry_due(header, attempts, *, now=None):
    """Return bounded local backoff without shortening a valid provider delay."""
    now = now or datetime.now(timezone.utc)
    seconds = min(15 * 60, 30 * (2 ** min(max(attempts - 1, 0), 5)))
    due = now + timedelta(seconds=seconds)
    if isinstance(header, str) and len(header) <= 128:
        value = header.strip()
        if re.fullmatch(r"\d{1,8}", value):
            due = max(due, now + timedelta(seconds=int(value)))
        else:
            try:
                date = parsedate_to_datetime(value)
                if date.tzinfo is not None:
                    due = max(due, date.astimezone(timezone.utc))
            except (TypeError, ValueError, OverflowError):
                pass
    return due.isoformat()


def _github_rate_limit_due(url, status, headers, attempts, *, now=None):
    """Recognize only a confirmed, timed GitHub API rate-limit response."""
    if status != 403 or urlsplit(url).hostname != "api.github.com":
        return None
    if headers.get("x-ratelimit-remaining") != "0":
        return None
    reset = headers.get("x-ratelimit-reset")
    if not isinstance(reset, str) or not reset.isascii() or not re.fullmatch(r"\d{1,12}", reset):
        return None
    now = now or datetime.now(timezone.utc)
    try:
        provider_due = datetime.fromtimestamp(int(reset), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    if provider_due <= now:
        return None
    local_due = datetime.fromisoformat(_retry_due(headers.get("retry-after"), attempts, now=now))
    return max(local_due, provider_due).isoformat()


def _origin_cooldown(case, url):
    row = case.ledger.db.execute("SELECT due_at FROM audit_origin_cooldown WHERE origin=?", (_origin(url),)).fetchone()
    if row and datetime.fromisoformat(row[0]) > datetime.now(timezone.utc):
        return row[0]
    return None


def _defer_ready_origin(case, origin, due_at):
    """Persist a provider pause without claiming jobs or spending attempts."""
    with case.queue._transaction():
        rows = case.ledger.db.execute("""SELECT job_id,asset_ref,state,next_eligible_at
            FROM audit_jobs WHERE state IN ('ready','retry_wait')""").fetchall()
        for row in rows:
            try:
                target = case.locators.get(case.scope_id, row["asset_ref"])
            except (KeyError, ValueError):
                continue  # Discovery and channel jobs have no URL locator.
            if _origin(target) != origin:
                continue
            current_due = row["next_eligible_at"]
            if current_due and datetime.fromisoformat(current_due.replace("Z", "+00:00")) >= datetime.fromisoformat(due_at):
                continue
            case.ledger.db.execute("""UPDATE audit_jobs SET state='retry_wait',next_eligible_at=?,
                last_error_code='ORIGIN_COOLDOWN',updated_at=? WHERE job_id=?""",
                (due_at, datetime.now(timezone.utc).isoformat(), row["job_id"]))
            case.ledger._event("AUDIT_JOB_DEFERRED", row["job_id"],
                               {"reason_code": "ORIGIN_COOLDOWN", "next_eligible_at": due_at})


def _set_origin_cooldown(case, url, due_at, status):
    origin = _origin(url)
    with case.ledger.db:
        case.ledger.db.execute("""INSERT INTO audit_origin_cooldown(origin,due_at,status)
            VALUES(?,?,?) ON CONFLICT(origin) DO UPDATE SET
            due_at=MAX(audit_origin_cooldown.due_at,excluded.due_at),status=excluded.status""",
            (origin, due_at, status))
        case.ledger._event("AUDIT_ORIGIN_COOLDOWN", hashlib.sha256(origin.encode()).hexdigest(),
                           {"http_status": status, "due_at": due_at})
    effective_due = _origin_cooldown(case, url) or due_at
    _defer_ready_origin(case, origin, effective_due)
    return effective_due


def _apply_active_cooldowns(case):
    now = datetime.now(timezone.utc)
    for origin, due_at in case.ledger.db.execute("SELECT origin,due_at FROM audit_origin_cooldown"):
        if datetime.fromisoformat(due_at) > now:
            _defer_ready_origin(case, origin, due_at)


def _review_context(scope, capability, budget):
    from .media_review import _windows_ocr_available
    values = {"engine_review_version": 3, "policy": scope.policy_id if scope else None, "max_bytes": scope.max_bytes if scope else None,
              "capability": capability, "pdf": importlib.util.find_spec("pypdf") is not None,
              "browser": importlib.util.find_spec("playwright") is not None,
              "browser_path": os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
              "ocr_rapidocr": importlib.util.find_spec("rapidocr_onnxruntime") is not None,
              "ocr_windows": _windows_ocr_available(),
              "ocr_tesseract": shutil.which("tesseract"),
              "analysis_budget": budget.get("max_analysis_bytes"), "download_budget": budget.get("max_download_bytes"),
              "repository_files": budget.get("max_repository_files", 1000),
              "patch_bytes": budget.get("max_patch_bytes", 524288)}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def read_json(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 8_388_608:
        raise ValueError("invalid_input")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("unsafe_output")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class Case:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise ValueError("unsafe_case")
        self.meta = read_json(self.root / "case.json")
        self.scope_id = self.meta["scope_id"]
        for name in ("ledger.sqlite", "locators.sqlite", "search-plan.json"):
            if (self.root / name).is_symlink():
                raise ValueError("unsafe_case")
        self.ledger = Ledger(self.root / "ledger.sqlite")
        self.queue = Scheduler(self.ledger)
        self.locators = LocatorStore(self.root / "locators.sqlite")
        self.transient_responses = {}
        self.ledger.db.execute("""CREATE TABLE IF NOT EXISTS audit_results(
            result_ref TEXT PRIMARY KEY, job_id TEXT NOT NULL, report_json TEXT NOT NULL)""")
        self.ledger.db.executescript("""
            CREATE INDEX IF NOT EXISTS audit_results_by_job ON audit_results(job_id);
            CREATE TRIGGER IF NOT EXISTS audit_results_no_update BEFORE UPDATE ON audit_results
            BEGIN SELECT RAISE(ABORT,'audit results are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_results_no_delete BEFORE DELETE ON audit_results
            BEGIN SELECT RAISE(ABORT,'audit results are append-only'); END;
            CREATE TABLE IF NOT EXISTS audit_gate_attempts(
                job_id TEXT PRIMARY KEY, reserved_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit_origin_cooldown(
                origin TEXT PRIMARY KEY, due_at TEXT NOT NULL, status INTEGER NOT NULL);
        """)
        self.ledger.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.transient_responses.clear()
        self.locators.close()
        self.ledger.close()

    def save_result(self, job, report):
        reference = "audit:" + uuid.uuid4().hex
        # Reports here are generated by trusted classifiers, never raw source.
        self.ledger.db.execute("BEGIN IMMEDIATE")
        try:
            active = self.ledger.db.execute("SELECT lease_owner,lease_expires_at,state FROM audit_jobs WHERE job_id=?",
                                            (job["job_id"],)).fetchone()
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if not active or active["state"] != "running" or active["lease_owner"] != job["lease_owner"] or active["lease_expires_at"] <= now:
                raise ValueError("lease_lost")
            self.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                                   (reference, job["job_id"], json.dumps(report, ensure_ascii=False)))
            self.ledger._event("AUDIT_RESULT", job["job_id"], {"result_ref": reference})
            self.ledger.db.commit()
        except BaseException:
            self.ledger.db.rollback()
            raise
        return reference

    def prior_result(self, job):
        row = self.ledger.db.execute("SELECT result_ref,report_json FROM audit_results WHERE job_id=? ORDER BY rowid DESC LIMIT 1",
                                     (job["job_id"],)).fetchone()
        return (row[0], json.loads(row[1])) if row and not json.loads(row[1]).get("retry_required") else None

    def reusable_child_review(self, job, scope, context_digest, run_started_at):
        """Find a committed review of this run's same capture, never a new observation."""
        if job["job_type"] != "capture" or self.ledger.db.execute(
                "SELECT 1 FROM audit_results WHERE job_id=? LIMIT 1", (job["job_id"],)).fetchone():
            return None
        checkpoint = job.get("checkpoint") or {}
        rows = self.ledger.db.execute("""SELECT job_id,state,checkpoint,result_refs FROM audit_jobs
            WHERE parent_job_id=? AND job_type='content_review' AND asset_ref=?
            AND scope_id=? AND policy_id=? AND state IN ('succeeded','blocked_input')""",
            (job["job_id"], job["asset_ref"], self.scope_id, scope.policy_id)).fetchall()
        start = datetime.fromisoformat(run_started_at.replace("Z", "+00:00"))
        for child in rows:
            child_checkpoint = json.loads(child["checkpoint"] or "{}")
            if (child_checkpoint.get("analysis_kind") != checkpoint.get("analysis_kind", "capture")
                    or child_checkpoint.get("document_base_ref") != checkpoint.get("document_base_ref")
                    or child_checkpoint.get("depth", 0) != checkpoint.get("depth", 0)
                    or child_checkpoint.get("context_digest") != context_digest):
                continue
            committed = set(json.loads(child["result_refs"]))
            if not committed:
                continue
            for row in self.ledger.db.execute("""SELECT result_ref,report_json FROM audit_results
                    WHERE job_id=? ORDER BY rowid DESC LIMIT 1""", (child["job_id"],)):
                if row["result_ref"] not in committed:
                    continue
                report = json.loads(row["report_json"])
                try:
                    observed = datetime.fromisoformat(report["observed_at"].replace("Z", "+00:00"))
                except (KeyError, AttributeError, TypeError, ValueError):
                    continue
                if (observed.tzinfo is not None and observed >= start
                        and report.get("target_id") == job["asset_ref"]
                        and report.get("policy_id") == scope.policy_id
                        and report.get("engine_review_version") == 3
                        and report.get("capture_complete") is True
                        and report.get("retry_required") is False
                        and isinstance(report.get("observation_id"), str)):
                    return row["result_ref"], report
        return None

    def enqueue_url(self, url, *, parent=None, evidence=None, depth=0, redirect_count=0, scope=None, job_type="capture", document_base_ref=None, review_reason=None):
        try:
            url, _ = _normalize_url(url)
        except PolicyError:
            return None
        ref = self.locators.put(self.scope_id, url)
        excluded = next((item for item in self.meta["intake"].get("excluded_urls", [])
                         if isinstance(item, dict) and item.get("url") == url), None)
        if excluded is not None:
            exclusion_ref = excluded.get("evidence_ref")
            valid = isinstance(exclusion_ref, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", exclusion_ref)
            return self.queue.enqueue("exclusion", ref, scope_id=self.scope_id,
                state="succeeded" if valid else "blocked_input", dedupe_key="exclusion:" + ref,
                origin_evidence_ref=exclusion_ref if valid else None,
                checkpoint={"reason_codes": ["OPERATOR_EXCLUDED" if valid else "EXCLUSION_EVIDENCE_REQUIRED"]})
        state, policy_id = "blocked_scope", None
        if scope is not None:
            try:
                scope.authorize(url)
                from .repository_workflow import repository_job_authorized
                if repository_job_authorized(self, url, scope) is not False:
                    state, policy_id = "ready", scope.policy_id
            except PolicyError:
                pass
        suffix = Path(urlsplit(url).path).suffix.lower()
        priority = 30 if suffix in {".pdf", ".json", ".csv", ".js", ".mjs", ".html", ".htm"} else 20
        if suffix in _MEDIA_SUFFIXES:
            priority = 1
        if job_type == "repository_history":
            priority = 5
        if job_type == "repository_patch":
            priority = 4
        if job_type == "repository_commit_detail":
            priority = 3
        if job_type == "repository_tree" and depth > 0:
            priority = 2
        if review_reason and state == "ready":
            state = "blocked_input"
        queued = self.queue.enqueue(job_type, ref, scope_id=self.scope_id,
            policy_id=policy_id, parent_job_id=parent, origin_evidence_ref=evidence,
            state=state, priority=priority, checkpoint={"depth": depth, "redirect_count": redirect_count,
                "document_base_ref": document_base_ref, "reason_codes": [review_reason] if review_reason else []},
            dedupe_key=job_type + ":" + ref + ((":" + document_base_ref) if document_base_ref else ""))
        if state == "ready":
            cooldown = _origin_cooldown(self, url)
            if cooldown:
                # New work queued after a 503/429 pause must not burn an attempt
                # merely to learn that the origin is still cooling down.
                with self.queue._transaction():
                    row = self.ledger.db.execute(
                        "SELECT state FROM audit_jobs WHERE job_id=?", (queued,)).fetchone()
                    if row and row["state"] == "ready":
                        self.ledger.db.execute("""UPDATE audit_jobs SET state='retry_wait',next_eligible_at=?,
                            last_error_code='ORIGIN_COOLDOWN',updated_at=? WHERE job_id=?""",
                            (cooldown, datetime.now(timezone.utc).isoformat(), queued))
                        self.ledger._event("AUDIT_JOB_DEFERRED", queued,
                                           {"reason_code": "ORIGIN_COOLDOWN", "next_eligible_at": cooldown})
        return queued


def init_case(directory, intake, mode="discovery"):
    from .search_plan import create_plan
    if mode not in {"discovery", "recheck"}:
        raise ValueError("invalid_mode")
    identity = intake["identity"]
    accepted = {key: identity.get(key, [] if key not in {"company_ko", "company_en"} else "")
                for key in ("company_ko", "company_en", "aliases", "industry", "functions", "known_urls", "domains")}
    plan = create_plan(scope_id=intake["scope_id"], **accepted)
    root = Path(directory).absolute()
    if root.exists() and any(root.iterdir()):
        raise ValueError("case_not_empty")
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("unsafe_case")
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "search-plan.json", plan)
    write_json(root / "case.json", {"schema_version": "1.0", "case_id": "case_" + uuid.uuid4().hex,
        "scope_id": intake["scope_id"], "mode": mode, "created_at": datetime.now(timezone.utc).isoformat(),
        "intake": intake})
    with Case(root) as case:
        case.queue.enqueue("discovery", "search-plan", scope_id=case.scope_id,
                           dedupe_key="discovery", estimated_cost=1)
        for url in identity.get("known_urls", []):
            case.enqueue_url(url)
        for domain in identity.get("domains", []):
            case.enqueue_url("https://" + domain + "/")
        return {"case_id": case.meta["case_id"], "mode": mode, "status": "initialized"}


class _RequestBudget:
    """Charge pessimistic capture reservations before each real transport request.

Reservations survive crashes and are never refunded: a killed process cannot
prove an in-flight request did not happen. Actual sizes are separate evidence.
"""
    def __init__(self, queue, run_id, original, capture_limit):
        self.queue, self.run_id, self.original = queue, run_id, original
        self.capture_limit = capture_limit

    @property
    def used(self):
        return self.original.used

    def consume(self):
        if self.original.used >= self.original.maximum:
            raise PolicyError("request budget exhausted")
        if not self.queue.reserve(self.run_id, requests=1, download_bytes=self.capture_limit):
            raise PolicyError("request budget exhausted")
        self.original.consume()


class _Documents(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        if tag in {"a", "iframe", "embed", "object"}:
            values = dict(attrs)
            url = values.get("href") or values.get("src") or values.get("data")
            if url and not url.startswith("#"):
                if len(self.links) >= 64:
                    self.truncated = True
                    return
                # Follow observed navigation and document references, never
                # synthesized record IDs. Scope still authorizes every request.
                self.links.append(("navigation" if tag == "a" else "document", url))


def _capture(case, job, scope, run_id, capability, fetcher=None):
    from .classifiers import analyze
    from .asset_trace import extract_references
    from .transport import fetch
    from .gate_review import review_gate, _capability
    from .repository_workflow import repository_job_authorized
    url = case.locators.get(case.scope_id, job["asset_ref"])
    scope.authorize(url)
    if repository_job_authorized(case, url, scope) is False:
        raise PolicyError("repository binding authorization required")
    if any(isinstance(item, dict) and item.get("url") == url for item in case.meta["intake"].get("excluded_urls", [])):
        raise PolicyError("operator excluded target")
    cached = case.prior_result(job)
    if cached and not (job["job_type"] == "content_review" and cached[1].get("gaps")):
        _project_observation(case, job, cached[1])
        return cached[0]
    if job["job_type"] == "capture":
        current_run = case.queue.get_run(run_id)
        reusable = case.reusable_child_review(job, scope,
            _review_context(scope, capability, current_run["budget"]), current_run["started_at"])
        if reusable:
            source_ref, source_report = reusable
            reused = {**source_report, "reused_result_ref": source_ref}
            # Preserve the original observation ID/time and every partial gap.
            # The child already projected that observation; this is an audit
            # result for the pending job, not a second network observation.
            return case.save_result(job, reused)
    original_url = url
    document_base_ref = (job.get("checkpoint") or {}).get("document_base_ref")
    document_base = case.locators.get(case.scope_id, document_base_ref) if document_base_ref else None
    invalid_document_base = False
    # Keep each redirect target as its own scoped locator. Following transparently
    # would lose the exact final base URL and resolve relative dependencies wrong.
    def collect(target, active_scope, **kwargs):
        active_scope.authorize(target)
        if repository_job_authorized(case, target, active_scope) is False:
            raise PolicyError("repository binding authorization required")
        if any(isinstance(item, dict) and item.get("url") == target for item in case.meta["intake"].get("excluded_urls", [])):
            raise PolicyError("operator excluded target")
        if target in case.transient_responses:
            return case.transient_responses[target]
        cooldown = _origin_cooldown(case, target)
        if cooldown:
            raise _RetryCapture(due_at=cooldown)
        response = fetcher(target, active_scope) if fetcher else fetch(target, active_scope, **kwargs)
        if response.observation.get("capture_complete") and response.observation.get("http_status") == 200:
            # A long image/file pass must not retain its entire download in RAM.
            cache_limit = 64 * 1024 * 1024
            if len(response.body) <= cache_limit:
                cache_bytes = sum(len(item.body) for item in case.transient_responses.values())
                while case.transient_responses and cache_bytes + len(response.body) > cache_limit:
                    oldest = next(iter(case.transient_responses))
                    cache_bytes -= len(case.transient_responses.pop(oldest).body)
                case.transient_responses[target] = response
        return response
    analysis_kind = (job.get("checkpoint") or {}).get("analysis_kind", job["job_type"])
    review_limits = case.queue.get_run(run_id)["budget"]
    capture_options = {"follow_redirects": False}
    if analysis_kind == "repository_patch":
        from .github_history import MAX_PATCH_BYTES
        capture_options["max_bytes"] = min(scope.max_bytes, review_limits.get("max_patch_bytes", MAX_PATCH_BYTES))
    elif analysis_kind == "repository_commit_detail":
        from .repository_commit import MAX_COMMIT_DETAIL_BYTES
        capture_options["max_bytes"] = min(scope.max_bytes, MAX_COMMIT_DETAIL_BYTES)
    elif analysis_kind in {"repository_tree", "repository_history"}:
        capture_options["max_bytes"] = min(scope.max_bytes,
            8_388_608 if analysis_kind == "repository_tree" else 2_097_152)
    result = collect(url, scope, **capture_options)
    body, observation = result.body, dict(result.observation)
    capture_complete = bool(observation.get("capture_complete"))
    http_status = observation.get("http_status")
    github_rate_due = _github_rate_limit_due(original_url, http_status, result.headers, job["attempts"])
    if http_status in _RETRY_HTTP_STATUSES or github_rate_due:
        due = github_rate_due or _retry_due(result.headers.get("retry-after"), job["attempts"])
        if http_status in _COOLDOWN_HTTP_STATUSES or github_rate_due:
            due = _set_origin_cooldown(case, original_url, due, http_status)
        if github_rate_due:
            observation["access"] = "INDETERMINATE"
            observation["reason"] = "provider_rate_limited"
        observation.update(target_id=job["asset_ref"], content="NOT_INSPECTED", analysis_complete=False,
            review_complete=False, retry_required=True, retry_after_at=due,
            gaps=(["provider_rate_limited"] if github_rate_due else
                  ["upstream_transient_status", "patch_source_unavailable"]
                  if analysis_kind == "repository_patch" and http_status == 503
                  else ["upstream_transient_status"]), engine_review_version=3,
            policy_id=scope.policy_id)
        if analysis_kind == "repository_patch" and http_status == 503:
            from .repository_commit import commit_detail_url
            detail = commit_detail_url(original_url)
            if detail:
                fallback = case.enqueue_url(detail, parent=job["job_id"],
                    evidence="observation:" + observation["observation_id"],
                    depth=(job.get("checkpoint") or {}).get("depth", 0),
                    job_type="repository_commit_detail", scope=scope)
                observation["commit_detail_fallback_queued"] = fallback is not None
        reference = case.save_result(job, observation)
        _project_observation(case, job, observation)
        raise _RetryCapture(reference, due)
    observation["target_id"] = job["asset_ref"]
    ctype = result.headers.get("content-type", "")
    if ctype.split(";", 1)[0].lower() in {"", "text/plain", "application/octet-stream"}:
        suffix = Path(urlsplit(url).path).suffix.lower()
        hint = {".html": "text/html", ".htm": "text/html", ".js": "application/javascript",
                ".mjs": "application/javascript", ".json": "application/json", ".pdf": "application/pdf",
                ".css": "text/css", ".csv": "text/csv"}.get(suffix)
        if hint:
            ctype = hint
            observation["media_type_basis"] = "path_hint_for_offline_analysis"
    observation["policy_id"] = scope.policy_id
    observation["engine_review_version"] = 3
    gaps, refs = [], []
    redirect_ref = result.headers.get("location") if observation.get("http_status") in {301, 302, 303, 307, 308} else None
    if result.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
        gaps.append("unsupported_encoding")
        profile = {"content": "NOT_INSPECTED", "analysis_complete": False}
    elif not case.queue.reserve(run_id, analysis_bytes=len(body)):
        gaps.append("analysis_budget_exhausted")
        profile = {"content": "NOT_INSPECTED", "analysis_complete": False}
    else:
        if analysis_kind == "repository_history":
            from .repository_history import analyze_history
            profile, refs = analyze_history(body, url)
        elif analysis_kind == "repository_patch":
            from .repository_history import analyze_repository_patch
            profile = analyze_repository_patch(body, url, case.locators, case.scope_id,
                max_bytes=min(scope.max_bytes, review_limits.get("max_patch_bytes", 524288)))
        elif analysis_kind == "repository_commit_detail":
            from .repository_commit import analyze_commit_detail
            profile, refs = analyze_commit_detail(body, url, link_header=result.headers.get("link"),
                max_bytes=min(scope.max_bytes, capture_options["max_bytes"]))
        elif analysis_kind == "repository_tree":
            from .repository_assets import analyze_tree
            profile, locations = analyze_tree(body, url, max_files=review_limits.get("max_repository_files", 1000))
            profile.update(content="NOT_INSPECTED", analysis_complete=profile["status"] == "COMPLETE")
            refs = [("repository_file", location) for location in locations]
            if profile["status"] != "COMPLETE":
                gaps.append("repository_tree_incomplete")
        elif "pdf" in ctype.lower() or body.startswith(b"%PDF-"):
            from .documents import analyze_document, extract_document_references
            profile = analyze_document(body, ctype, capture_complete=capture_complete,
                                       max_bytes=min(scope.max_bytes, 32 * 1024 * 1024))
            if case.queue.reserve(run_id, analysis_bytes=len(body)):
                refs, reference_gaps = extract_document_references(body, ctype,
                    max_bytes=min(scope.max_bytes, 32 * 1024 * 1024))
                gaps.extend(reference_gaps)
            else:
                gaps.append("document_reference_analysis_budget_exhausted")
        elif "image/svg+xml" in ctype.lower() or Path(urlsplit(url).path).suffix.lower() == ".svg":
            from .media_review import analyze_svg
            profile = analyze_svg(body, capture_complete=capture_complete,
                max_bytes=min(scope.max_bytes, 8_388_608))
        elif ctype.lower().startswith("image/") or Path(urlsplit(url).path).suffix.lower() in {
                ".png", ".jpg", ".jpeg", ".webp", ".avif", ".gif", ".bmp", ".tif", ".tiff", ".ico"}:
            from .media_review import analyze_image
            profile = analyze_image(body, ctype, capture_complete=capture_complete,
                max_bytes=min(scope.max_bytes, 32 * 1024 * 1024))
        elif (ctype.lower().startswith("text/") or any(kind in ctype.lower() for kind in (
                "json", "javascript", "xml", "ecmascript"))):
            analysis_body, analysis_capture_complete = body, capture_complete
            projection_metadata = None
            if re.search(br"data:image/", body, re.I):
                from .media_projection import project_inline_images
                projection = project_inline_images((body[i:i + 65_536] for i in range(0, len(body), 65_536)),
                    max_wire_bytes=scope.max_bytes, max_projected_bytes=min(scope.max_bytes, 4_194_304))
                if projection.skipped_images:
                    analysis_body = projection.projected
                    analysis_capture_complete = capture_complete and not projection.projected_truncated and not projection.wire_truncated
                    projection_metadata = {key: value for key, value in vars(projection).items() if key != "projected"}
                    projection_metadata.update(original_capture_complete=capture_complete, analysis_only=True,
                                               original_dom_replayed=False)
                    gaps.append("inline_image_ocr_unexamined")
            analysis = analyze(analysis_body, ctype, url, max_bytes=min(scope.max_bytes, 32 * 1024 * 1024), capture_complete=analysis_capture_complete)
            profile = analysis.report
            if projection_metadata:
                profile["media_projection"] = projection_metadata
                from .media_review import analyze_inline_images
                inline_review = analyze_inline_images(body, max_seconds=120.0)
                profile["inline_image_review"] = inline_review
                gaps.extend(inline_review.get("pending_reviews", []))
                if (inline_review.get("inline_images_found") == inline_review.get("ocr_completed")
                        and not set(inline_review.get("pending_reviews", [])) & {
                            "ocr_requested_language_not_covered", "ocr_text_byte_limit"}):
                    gaps = [gap for gap in gaps if gap != "inline_image_ocr_unexamined"]
                if inline_review.get("content") == "SENSITIVE_CANDIDATE":
                    profile["content"] = "SENSITIVE_CANDIDATE"
                profile.setdefault("signals", []).extend(inline_review.get("signals", []))
            refs, unresolved, base = extract_references(analysis_body, ctype)
            gaps.extend(unresolved)
            if base:
                try:
                    url = scope.authorize(urljoin(url, base))
                except PolicyError:
                    invalid_document_base = True
                    gaps.append("base_out_of_scope_or_invalid")
            if "html" in ctype.lower():
                document_base = None if invalid_document_base else url
                document_base_ref = case.locators.put(case.scope_id, document_base) if document_base else None
                parser = _Documents()
                parser.feed(analysis_body.decode("utf-8", errors="replace"))
                refs.extend(parser.links)
                if parser.truncated:
                    gaps.append("navigation_reference_limit")
        else:
            profile = {"content": "NOT_INSPECTED", "analysis_complete": False,
                       "pending_reviews": ["unsupported_document_format"]}
        if "html" in ctype.lower():
            replay = False
            if capability is not None and _capability(capability, scope, original_url,
                    hashlib.sha256(body).hexdigest(), datetime.now(timezone.utc)) == "authorized":
                # Reserve before entering the browser. A crash must not silently
                # repeat a gate input. Changing workers does not reset this row.
                with case.ledger.db:
                    replay = case.ledger.db.execute("INSERT OR IGNORE INTO audit_gate_attempts VALUES(?,?)",
                        (job["job_id"], datetime.now(timezone.utc).isoformat())).rowcount == 1
            gate = review_gate(body, ctype, original_url, scope=scope, capability=capability,
                               replay_browser=replay, max_bytes=min(scope.max_bytes, 32 * 1024 * 1024))
            profile["gate_review"] = gate
            if gate.get("auth_ui_present") and not gate.get("client_gate_tested"):
                gaps.append("gate_review_incomplete")
            if gate.get("reason") in {"response_missing_or_oversize", "unsupported_encoding", "html_parse_incomplete",
                                      "script_static_analysis_incomplete"}:
                gaps.append("gate_structure_unexamined")
            if gate.get("encrypted_payload_observed"):
                gaps.append("encrypted_payload_unexamined")
            if (profile.get("structure", {}).get("script_elements", 0)
                    and profile.get("content") != "SENSITIVE_CANDIDATE" and capture_complete):
                from .browser import observe
                def browser_fetch(target, active_scope, **kwargs):
                    parent_depth = (job.get("checkpoint") or {}).get("depth", 0)
                    if target != original_url and parent_depth >= 3:
                        gaps.append("runtime_dependency_depth_limit")
                        raise PolicyError("dependency depth limit")
                    response = collect(target, active_scope, **kwargs)
                    if target != original_url:
                        case.enqueue_url(target, parent=job["job_id"],
                            evidence="observation:" + response.observation["observation_id"],
                            depth=parent_depth + 1, scope=active_scope)
                    if not case.queue.reserve(run_id, analysis_bytes=len(response.body)):
                        raise PolicyError("analysis budget exhausted")
                    return response
                current_run = case.queue.get_run(run_id)
                elapsed = time.time() - datetime.fromisoformat(current_run["started_at"].replace("Z", "+00:00")).timestamp()
                duration = min(3.0, max(0.05, current_run["budget"]["max_seconds"] - elapsed))
                runtime = observe(original_url, scope, duration=duration, max_total_bytes=scope.max_bytes,
                                  fetcher=browser_fetch, target_id=job["asset_ref"])
                profile["browser_review"] = runtime
                if runtime.get("content") == "SENSITIVE_CANDIDATE":
                    profile["content"] = "SENSITIVE_CANDIDATE"
                if not runtime.get("complete"):
                    gaps.append("runtime_review_incomplete")
    if redirect_ref:
        refs.append(("redirect", redirect_ref))
    observation.update(profile)
    observation["capture_complete"] = capture_complete
    gaps.extend(profile.get("pending_reviews", []))
    if not observation.get("capture_complete"):
        observation["analysis_complete"] = False
        gaps.append("capture_incomplete")
    if not profile.get("analysis_complete", False):
        gaps.append("content_analysis_incomplete")
    observation["text_analysis_complete"] = bool(profile.get("text_analysis_complete", profile.get("analysis_complete")) and capture_complete)
    observation["dependency_review_complete"] = not refs and not gaps
    observation["gaps"] = sorted(set(gaps))
    observation["review_dimensions"] = {
        "capture": "complete" if capture_complete else "partial",
        "text": "complete" if observation["text_analysis_complete"] else "partial",
        "structure": "complete" if profile.get("structure_analysis_complete", profile.get("analysis_complete")) else "partial",
        "media": "complete" if profile.get("image_review_complete") in (True, "not_applicable", "not_applicable_for_text_pages") else "unverified",
        "gate": profile.get("gate_review", {}).get("status", "not_applicable"),
        "sensitivity": "candidate" if profile.get("content") == "SENSITIVE_CANDIDATE" else "not_determined",
        "publication_approval": "not_determined",
        "server_authorization": "not_tested",
    }
    # Use an observation reference while scheduling children, then commit the final
    # result last. A crash can repeat scheduling, but dedupe prevents duplicate jobs.
    evidence = "observation:" + observation["observation_id"]
    depth = (job.get("checkpoint") or {}).get("depth", 0)
    redirect_count = (job.get("checkpoint") or {}).get("redirect_count", 0)
    affected_material_stop = any(signal.get("code") in {
        "PRIVATE_KEY_CANDIDATE", "SERVER_SECRET_CANDIDATE", "GITHUB_SECRET_CANDIDATE", "KR_RESIDENT_VALUE_CANDIDATE"}
        for signal in profile.get("signals", []))
    if affected_material_stop and refs:
        gaps.append("references_held_after_sensitive_evidence")
    for relationship, relative in refs:
        try:
            absolute = bool(urlsplit(relative).scheme)
        except ValueError:
            gaps.append("unsafe_reference_rejected")
            continue
        script_context = "javascript" in ctype.lower() or "ecmascript" in ctype.lower()
        if not absolute and relationship != "redirect" and (invalid_document_base or (script_context and not document_base)):
            gaps.append("relative_reference_document_context_unresolved")
            continue
        reference_base = original_url if relationship == "redirect" else (document_base if script_context else url)
        candidate = urljoin(reference_base, relative)
        if urlsplit(candidate).scheme == "https":
            if relationship == "redirect" and redirect_count >= scope.max_redirects:
                gaps.append("redirect_budget_exhausted")
            elif depth < 3 or relationship in {"redirect", "repository_commit_detail"}:
                queued = case.enqueue_url(candidate, parent=job["job_id"], evidence=evidence,
                    depth=depth if relationship in {"redirect", "repository_commit_detail"} else depth + 1,
                    redirect_count=redirect_count + 1 if relationship == "redirect" else 0, scope=scope,
                    job_type={"repository_snapshot": "repository_tree", "repository_patch": "repository_patch",
                              "repository_commit_detail": "repository_commit_detail"}.get(relationship, "capture"),
                    document_base_ref=document_base_ref if relationship in {"script_src", "redirect"} else None,
                    review_reason="SENSITIVE_MATERIAL_FOLLOWUP_REVIEW" if affected_material_stop else None)
                if queued is None:
                    gaps.append("unsafe_reference_rejected")
            else:
                gaps.append("dependency_depth_limit")
    retry = observation.get("reason") in _RETRY_REASONS
    if gaps and not retry and job["job_type"] != "content_review":
        case.queue.enqueue("content_review", job["asset_ref"], scope_id=case.scope_id,
            policy_id=scope.policy_id, parent_job_id=job["job_id"], origin_evidence_ref=evidence,
            state="blocked_input", dedupe_key="review:" + job["job_id"],
            checkpoint={"reason_codes": sorted(set(gaps)),
                        "context_digest": _review_context(scope, capability, case.queue.get_run(run_id)["budget"]),
                        "document_base_ref": document_base_ref,
                        "analysis_kind": (job.get("checkpoint") or {}).get("analysis_kind", job["job_type"]), "depth": depth})
    observation["gaps"] = sorted(set(gaps))
    observation["review_complete"] = not gaps and bool(observation.get("analysis_complete"))
    observation["retry_required"] = retry
    reference = case.save_result(job, observation)
    _project_observation(case, job, observation)
    if retry:
        raise _RetryCapture(reference)
    return reference


def _project_observation(case, job, observation):
    """Replay a committed sanitized result into Ledger idempotently after a crash."""
    asset_id = "asset_" + job["asset_ref"].split(":")[-1]
    case.ledger.register_asset(asset_id, provider="audit", scope_id=case.scope_id,
        target_id=job["asset_ref"], policy_id=observation["policy_id"])
    # A candidate classification is never promoted to confirmed sensitivity.
    case.ledger.import_observation(observation, asset_id=asset_id,
        event_id="audit-observation-" + observation["observation_id"])


def _discover(case, job, run_id, health, api_fetch=None):
    from .github_discovery import GitHubBroker, DiscoveryError, Response
    from .search_plan import run_plan
    sent_requests = 0

    def metered(url, headers):
        nonlocal sent_requests
        if api_fetch is None:
            from .github_discovery import _validate_channel_health
            path = urlsplit(url).path
            channel = "github-user-search" if path == "/search/users" else (
                "github-repository-search" if path == "/search/repositories" else "github-repositories")
            errors = _validate_channel_health(health, [channel])
            if errors:
                raise DiscoveryError(errors[0])
        if not case.queue.reserve(run_id, requests=1, download_bytes=2_097_152):
            raise DiscoveryError("REQUEST_LIMIT_EXCEEDED")
        sent_requests += 1
        # One transport broker per request: its terminal search error must not
        # poison independently eligible core API calls in the outer planner.
        broker = GitHubBroker(fetch=api_fetch, max_requests=1, max_response_bytes=2_097_152)
        try:
            return broker.get(url)
        except DiscoveryError as exc:
            if exc.code == "RATE_LIMITED":
                due = datetime.fromisoformat(broker.retry_after_at.replace("Z", "+00:00")).timestamp() if broker.retry_after_at else time.time() + 60
                return Response(429, {}, {"retry-after": str(max(1, int(due - time.time()) + 1))})
            raise

    path = case.root / "search-plan.json"
    plan = read_json(path)
    completed_before = {j["work_id"] for j in plan.get("jobs", []) if j.get("state") == "completed"}
    # Do not bypass channel controls merely because our budget wrapper is injected.
    if api_fetch is None and health is None:
        return None, "blocked_input", "CHANNEL_HEALTH_REQUIRED"
    result = run_plan(plan, fetch=metered, locator_store=case.locators,
        request_budget=30, max_batches=10, resume_all_deferred=True, retry_failed=True,
        persist=lambda value: write_json(path, value), channel_health=health, live_fetch=api_fetch is None,
        respect_retry_after=True)
    write_json(path, result)
    for run in result.get("runs", []):
        for candidate in run.get("result", {}).get("candidates", []):
            from .repository_assets import tree_url
            repository_tree = tree_url(candidate)
            if repository_tree:
                case.enqueue_url(repository_tree, parent=job["job_id"], job_type="repository_tree")
                from .repository_history import history_url
                history = history_url(candidate)
                if history:
                    case.enqueue_url(history, parent=job["job_id"], job_type="repository_history")
            ref = candidate.get("locator_ref")
            if ref:
                case.enqueue_url(case.locators.get(case.scope_id, ref), parent=job["job_id"])
            for deployment in candidate.get("deployment_candidates", []):
                ref = deployment.get("locator_ref")
                if ref:
                    case.enqueue_url(case.locators.get(case.scope_id, ref), parent=job["job_id"])
    summary = {"status": result["status"], "next_work": result.get("last_execution", {}).get("next_work", {}),
               "requests_used": sent_requests,
               "planner_request_attempts": result.get("last_execution", {}).get("requests_used", 0)}
    reference = case.save_result(job, summary)
    pending = any(j["channel"] == "github" and j["state"] in {"planned", "deferred", "failed"} for j in result["jobs"])
    for channel in result.get("required_channels", []):
        if channel != "github" and any(j["channel"] == channel and j["state"] not in {"completed", "not_applicable"} for j in result["jobs"]):
            case.queue.enqueue("channel_review", channel, scope_id=case.scope_id, state="blocked_input",
                               dedupe_key="channel:" + channel, checkpoint={"reason_codes": ["CHANNEL_IMPORT_REQUIRED"]})
    progressed = any(j.get("state") == "completed" and j["work_id"] not in completed_before for j in result["jobs"])
    if pending and progressed:
        # Progress is a completed batch, not a failed attempt. Continue with a new
        # durable job; rate-limited/no-progress attempts keep the retry counter.
        stop = result.get("last_execution", {}).get("stop_reason")
        if stop != "provider_rate_limited":
            case.queue.enqueue("discovery", "search-plan", scope_id=case.scope_id,
                dedupe_key="discovery:after:" + job["job_id"], origin_evidence_ref=reference)
            return reference, "succeeded", None
    return reference, ("retry_wait" if pending else "succeeded"), ("DISCOVERY_REMAINING" if pending else None)


def import_channel(case, report, health):
    """Bind an external channel observation to this case without granting scope.

    Run while the case's discovery coordinator is stopped. Candidate enqueueing
    precedes the atomic plan checkpoint; repeating an interrupted import is safe.
    """
    from .discovery_channels import make_plan_import
    from .search_plan import import_results
    path = case.root / "search-plan.json"
    plan = read_json(path)
    payload = make_plan_import(report, plan, health)
    candidates = report.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 10_000:
        raise ValueError("invalid_channel_candidates")
    if report["coverage"].get("result_count") != len(candidates):
        raise ValueError("channel_candidate_count_mismatch")
    # Resolve and validate every locator before making any case mutations.
    urls = [_normalize_url(case.locators.get(case.scope_id, item["locator_ref"]))[0]
            for item in candidates]
    digest = hashlib.sha256(json.dumps({"report": report, "health": health},
        sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    evidence = "audit-channel-" + digest
    receipts = plan.get("audit_import_receipts", [])
    previous = next(j for j in plan["jobs"] if j["work_id"] == report["query_work_id"])
    if digest not in receipts and previous.get("observed_at"):
        prior_time = datetime.fromisoformat(previous["observed_at"].replace("Z", "+00:00"))
        imported_time = datetime.fromisoformat(report["observed_at"].replace("Z", "+00:00"))
        if imported_time <= prior_time:
            raise ValueError("stale_channel_observation")
    updated = plan if digest in receipts else import_results(plan, payload)
    for url in urls:
        case.enqueue_url(url, evidence="event:" + evidence)
    channel = report["channel_id"]
    case.queue.enqueue("channel_review", channel, scope_id=case.scope_id, state="blocked_input",
        dedupe_key="channel-import:" + digest, checkpoint={"reason_codes": ["CHANNEL_IMPORT_REQUIRED"]})
    if digest not in receipts:
        updated["audit_import_receipts"] = [*receipts, digest]
        write_json(path, updated)
    summary = {"channel": channel, "work_id": report["query_work_id"],
               "candidate_count": len(set(urls)), "report_sha256": digest,
               "execution_attestation": "operator_supplied_not_independently_verified"}
    with case.ledger.db:
        case.ledger._event("AUDIT_CHANNEL_IMPORTED", report["query_work_id"], summary, event_id=evidence)
    return {"status": "imported", "evidence_ref": "event:" + evidence, **summary}


def _channel_complete(case, channel):
    jobs = [j for j in read_json(case.root / "search-plan.json")["jobs"] if j["channel"] == channel]
    return bool(jobs) and all(j["state"] in {"completed", "not_applicable"} for j in jobs)


def _patch_lineage_blocked(case, job):
    from .github_history import patch_requires_material_hold
    if (job.get("checkpoint") or {}).get("analysis_kind", job["job_type"]) != "repository_patch":
        return False
    url = case.locators.get(case.scope_id, job["asset_ref"])
    prefix = url.rsplit("/", 1)[0]
    for row in case.ledger.db.execute("SELECT report_json FROM audit_results"):
        report = json.loads(row[0])
        if (report.get("hold_repository_patch_lineage") and report.get("target_id")
                and patch_requires_material_hold(report.get("signal_codes", []))):
            prior = case.locators.get(case.scope_id, report["target_id"])
            if prior.rsplit("/", 1)[0] == prefix:
                return True
    return False


def run_case(case, budget, *, scope=None, capability=None, health=None, fetcher=None, api_fetch=None, agent="cli", wait_for_retry=False, inspection_only=False):
    from .repository_workflow import preflight, repository_job_authorized
    readiness = preflight(case, scope)
    run_id = case.queue.start_run(budget)
    _apply_active_cooldowns(case)
    review_context = _review_context(scope, capability, case.queue.get_run(run_id)["budget"])
    worker = agent + "-" + uuid.uuid4().hex
    original_budget = scope.budget if scope is not None else None
    started = time.monotonic()
    if scope is not None:
        scope._budget = _RequestBudget(case.queue, run_id, original_budget, scope.max_bytes)
    reason = "no_ready_work"
    job = None
    try:
        # Previously blocked scope jobs become ready only after current authorization.
        for job in case.queue.status()["jobs"]:
            if job["job_type"] == "capture" and job["state"] not in {"succeeded", "running"} and job["priority"] != 1:
                target = case.locators.get(case.scope_id, job["asset_ref"])
                if Path(urlsplit(target).path).suffix.lower() in _MEDIA_SUFFIXES:
                    with case.ledger.db:
                        case.ledger.db.execute("UPDATE audit_jobs SET priority=1 WHERE job_id=? AND state NOT IN ('succeeded','running')", (job["job_id"],))
                        case.ledger._event("AUDIT_MEDIA_PRIORITY_UPDATED", job["job_id"], {"priority": 1})
            if job["state"] == "succeeded" and job["job_type"] in {"capture", "repository_tree", "repository_history", "repository_patch", "repository_commit_detail"} and scope:
                previous = case.prior_result(job)
                if previous and previous[1].get("engine_review_version", 0) < 3:
                    candidate = case.locators.get(case.scope_id, job["asset_ref"])
                    try:
                        scope.authorize(candidate)
                    except PolicyError:
                        continue
                    upgrade_key = "engine-review:3:" + job["asset_ref"]
                    # enqueue() resumes an existing blocked_input job. A review
                    # with unchanged context must remain blocked until its actual
                    # missing evidence or dependencies change.
                    if not case.ledger.db.execute(
                            "SELECT 1 FROM audit_jobs WHERE dedupe_key=? LIMIT 1", (upgrade_key,)).fetchone():
                        case.queue.enqueue("content_review", job["asset_ref"], scope_id=case.scope_id,
                            policy_id=scope.policy_id, parent_job_id=job["job_id"],
                            origin_evidence_ref=previous[0], state="ready", priority=25,
                            dedupe_key=upgrade_key, resume_existing=False,
                            checkpoint={"analysis_kind": job["job_type"], "depth": (job.get("checkpoint") or {}).get("depth", 0),
                                        "document_base_ref": (job.get("checkpoint") or {}).get("document_base_ref"),
                                        "reason_codes": ["engine_review_upgrade"], "context_digest": review_context})
            if job["state"] == "blocked_scope" and scope is not None:
                if "SENSITIVE_MATERIAL_FOLLOWUP_REVIEW" in (job.get("checkpoint") or {}).get("reason_codes", []):
                    continue
                try:
                    candidate = case.locators.get(case.scope_id, job["asset_ref"])
                    scope.authorize(candidate)
                    if repository_job_authorized(case, candidate, scope) is False:
                        continue
                except (PolicyError, ValueError):
                    continue
                case.queue.unblock(job["job_id"], policy_id=scope.policy_id)
            if job["state"] == "blocked_input" and job["job_type"] == "discovery" and (health or api_fetch):
                case.queue.unblock(job["job_id"])
            if job["state"] == "blocked_input" and job["job_type"] == "channel_review" and _channel_complete(case, job["asset_ref"]):
                case.queue.unblock(job["job_id"])
            if (job["state"] == "blocked_input" and scope and
                    "SENSITIVE_PATCH_LINEAGE_REVIEW" in (job.get("checkpoint") or {}).get("reason_codes", [])
                    and not _patch_lineage_blocked(case, job)):
                try:
                    candidate = scope.authorize(case.locators.get(case.scope_id, job["asset_ref"]))
                    if repository_job_authorized(case, candidate, scope) is not False:
                        case.queue.unblock(job["job_id"], policy_id=scope.policy_id)
                except PolicyError:
                    pass
            if job["state"] == "blocked_input" and job["job_type"] == "content_review" and scope:
                checkpoint = job.get("checkpoint") or {}
                reasons = set(checkpoint.get("reason_codes", []))
                automatic = {"gate_review_incomplete", "runtime_review_incomplete", "analysis_budget_exhausted",
                             "capture_incomplete", "pdf_text_dependency_missing", "pdf_isolation_unavailable",
                             "gate_structure_unexamined", "structured_data_incomplete", "structure_parse_incomplete",
                             "content_analysis_incomplete", "analysis_byte_limit", "image_or_base64_review"}
                if reasons & automatic and checkpoint.get("context_digest") != review_context:
                    try:
                        scope.authorize(case.locators.get(case.scope_id, job["asset_ref"]))
                    except PolicyError:
                        continue
                    case.queue.unblock(job["job_id"], policy_id=scope.policy_id)
        while True:
            job = case.queue.claim(run_id, worker_id=worker,
                job_types=_INSPECTION_JOB_TYPES if inspection_only else None)
            if job is None:
                status = case.queue.status()
                current = case.queue.get_run(run_id)
                next_action = status["next_action_at"]
                if inspection_only:
                    eligible_retries = [item["next_eligible_at"] for item in status["jobs"]
                        if item["job_type"] in _INSPECTION_JOB_TYPES and item["state"] == "retry_wait"
                        and item.get("next_eligible_at")]
                    next_action = min(eligible_retries) if eligible_retries else None
                if wait_for_retry and next_action and current["state"] == "running":
                    delay = datetime.fromisoformat(next_action.replace("Z", "+00:00")).timestamp() - time.time()
                    remaining = current["budget"]["max_seconds"] - (time.monotonic() - started)
                    if 0 < delay < remaining and current["requests"] < current["budget"]["max_requests"]:
                        time.sleep(min(5, delay))
                        continue
                break
            state, error, refs, retry_due = "succeeded", None, [], None
            try:
                if job["job_type"] == "discovery":
                    ref, state, error = _discover(case, job, run_id, health, api_fetch)
                    if ref:
                        refs.append(ref)
                    # New targets discovered during this run use the same supplied scope.
                    if scope:
                        for target in case.queue.status()["jobs"]:
                            if target["state"] == "blocked_scope":
                                if "SENSITIVE_MATERIAL_FOLLOWUP_REVIEW" in (target.get("checkpoint") or {}).get("reason_codes", []):
                                    continue
                                try:
                                    candidate = case.locators.get(case.scope_id, target["asset_ref"])
                                    scope.authorize(candidate)
                                    if repository_job_authorized(case, candidate, scope) is False:
                                        continue
                                except (PolicyError, ValueError):
                                    continue
                                case.queue.unblock(target["job_id"], policy_id=scope.policy_id)
                elif job["job_type"] == "channel_review":
                    if _channel_complete(case, job["asset_ref"]):
                        refs.append(case.save_result(job, {"channel": job["asset_ref"],
                            "channel_plan_complete": True, "public_index_exhaustive": False}))
                    else:
                        state, error = "blocked_input", "CHANNEL_IMPORT_REQUIRED"
                elif job["job_type"] in {"capture", "repository_tree", "repository_history", "repository_patch", "repository_commit_detail", "content_review"} and scope is not None:
                    if _patch_lineage_blocked(case, job):
                        state, error = "blocked_input", "SENSITIVE_PATCH_LINEAGE_REVIEW"
                        job["checkpoint"] = {**(job.get("checkpoint") or {}),
                                             "reason_codes": [error]}
                    else:
                        refs.append(_capture(case, job, scope, run_id, capability, fetcher))
                    if job["job_type"] == "content_review" and error != "SENSITIVE_PATCH_LINEAGE_REVIEW":
                        latest = case.prior_result(job)
                        gaps = latest[1].get("gaps", []) if latest else ["review_incomplete"]
                        if gaps:
                            state, error = "blocked_input", "REVIEW_INCOMPLETE"
                        job["checkpoint"] = {**(job.get("checkpoint") or {}),
                            "reason_codes": gaps, "context_digest": review_context}
                else:
                    state, error = "blocked_scope", "SCOPE_REQUIRED"
            except PolicyError:
                state, error = "blocked_scope", "SCOPE_OR_BUDGET_REJECTED"
            except _RetryCapture as exc:
                if exc.reference:
                    refs.append(exc.reference)
                state, error = "retry_wait", "TRANSPORT_RETRY"
                retry_due = exc.due_at
            except sqlite3.OperationalError as exc:
                code = getattr(exc, "sqlite_errorcode", None)
                if isinstance(code, int) and (code & 0xff) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    state, error = "retry_wait", "STATE_STORE_BUSY"
                    delay = min(60, 5 * (2 ** min(max(job["attempts"] - 1, 0), 4)))
                    retry_due = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()
                else:
                    state, error = "failed_terminal", "STATE_STORE_ERROR"
            except sqlite3.Error:
                state, error = "failed_terminal", "STATE_STORE_ERROR"
            except (ValueError, OSError, ImportError):
                state, error = "blocked_input", "HANDLER_INPUT_OR_DEPENDENCY_FAILED"
            except Exception:
                state, error = "failed_terminal", "HANDLER_FAILED"
            due = (retry_due if state == "retry_wait" and retry_due else
                   datetime.fromtimestamp(time.time() + 60, timezone.utc).isoformat()
                   if state == "retry_wait" else None)
            if due and job["job_type"] == "discovery":
                remaining = read_json(case.root / "search-plan.json").get("jobs", [])
                future = [item["next_eligible_at"] for item in remaining if item.get("next_eligible_at")]
                if future:
                    due = max(due, min(future))
            finished = case.queue.finish(job["job_id"], job["lease_owner"], state=state, result_refs=refs,
                                         error_code=error, next_eligible_at=due, checkpoint=job.get("checkpoint"))
            if not finished:
                with case.ledger.db:
                    case.ledger._event("AUDIT_LATE_WORKER", job["job_id"], {"reason_code": "LEASE_LOST"})
    except KeyboardInterrupt:
        reason = "user_stop"
        if job:
            case.queue.finish(job["job_id"], job["lease_owner"], state="retry_wait",
                              error_code="USER_STOPPED", next_eligible_at=datetime.now(timezone.utc).isoformat())
    finally:
        case.queue.end_run(run_id, reason)
        case.transient_responses.clear()
        if scope is not None:
            scope._budget = original_budget
    return {"run_id": run_id, "run": case.queue.get_run(run_id),
            "inspection_only": inspection_only, "preflight": readiness, **case_status(case)}


def case_status(case):
    """Queue success alone never establishes completed discovery or inspection."""
    from .search_plan import _status as plan_status
    status = case.queue.status()
    latest = {}
    for row in case.ledger.db.execute("SELECT report_json FROM audit_results ORDER BY rowid"):
        report = json.loads(row[0])
        if report.get("target_id"):
            latest[report["target_id"]] = report
    plan = read_json(case.root / "search-plan.json")
    plan_states = Counter(j.get("state", "unknown") for j in plan.get("jobs", []))
    search_remaining = sum(value for key, value in plan_states.items() if key not in {"completed", "not_applicable"})
    search_complete = plan_status(plan) == "COMPLETE"
    reasons = Counter()
    for job in status["jobs"]:
        if job["state"] != "succeeded":
            codes = (job.get("checkpoint") or {}).get("reason_codes", [])
            reasons.update(set(codes or [job.get("last_error_code") or job["state"]]))
    incomplete_targets = sum(bool(item.get("gaps")) or not item.get("capture_complete")
                             or not item.get("analysis_complete") or item.get("engine_review_version", 0) < 3
                             for item in latest.values())
    status.update(queue_complete=status["complete"], complete=bool(status["complete"] and search_complete and not search_remaining and not incomplete_targets),
                  search_complete=search_complete,
                  search_plan_states=dict(sorted(plan_states.items())), search_work_remaining=search_remaining,
                  latest_target_count=len(latest), incomplete_target_count=incomplete_targets,
                  unresolved_reason_counts=dict(sorted(reasons.items())),
                  completion_definition="bounded_scheduled_work_only_not_company_wide_or_publication_approval")
    from .repository_workflow import repository_status
    status["repository_review"] = repository_status(case)
    if status["repository_review"].get("repositories"):
        status["complete"] = bool(status["complete"] and status["repository_review"].get("complete", False))
    status["next_actions"] = _next_actions(status)
    return status


def _next_actions(status):
    """Explicit resolution work, never an automatic scope or budget expansion."""
    reasons = status.get("unresolved_reason_counts", {})
    actions = []
    current = status.get("current_run") or {}
    limits = current.get("budget") or {}
    if (any("BUDGET" in reason.upper() for reason in reasons)
            or current.get("reason") in {"budget_exhausted", "time_exhausted", "jobs_exhausted"}
            or any(current.get(key, 0) >= limits.get("max_" + key, float("inf"))
                   for key in ("requests", "download_bytes", "analysis_bytes"))):
        actions.append({"action": "resume_with_explicit_budget", "requires": "review_remaining_work_and_current_scope"})
    if status.get("next_action_at"):
        actions.append({"action": "resume_after", "at": status["next_action_at"],
                        "requires": "fresh_scope_controls_and_explicit_budget"})
    if any("scope" in reason.lower() for reason in reasons):
        actions.append({"action": "review_missing_scope", "requires": "repository_preflight_and_ownership_evidence"})
    if any("RATE" in reason or "RETRY" in reason or "REMAINING" in reason for reason in reasons):
        actions.append({"action": "inspect_retry_state", "requires": "provider_due_time_and_new_budget"})
    if any("INPUT" in reason or "REVIEW" in reason for reason in reasons):
        actions.append({"action": "resolve_review_gaps", "requires": "actual_missing_evidence_or_dependency"})
    if status.get("search_work_remaining"):
        actions.append({"action": "review_remaining_discovery", "requires": "relevance_review_before_expansion"})
    return actions


def report_case(case):
    status = case_status(case)
    jobs = {job["job_id"]: job for job in status["jobs"]}
    results = [{"result_ref": row[0], "job_id": row[1], "report": json.loads(row[2]),
                "job_state": jobs[row[1]]["state"], "completion_recorded": row[0] in jobs[row[1]]["result_refs"]}
               for row in case.ledger.db.execute("SELECT * FROM audit_results ORDER BY rowid")]
    return {"schema_version": "1.0", "case_id": case.meta["case_id"], "mode": case.meta["mode"],
            "coverage": status, "results": results,
            "channel_imports": [json.loads(row[0]) for row in case.ledger.db.execute(
                "SELECT payload_json FROM events WHERE event_type='AUDIT_CHANNEL_IMPORTED' ORDER BY rowid")],
            "limitations": ["defined_scope_and_time_only", "publication_approval_requires_review",
                            "model_host_parity_not_measured"]}


def main(argv=None):
    from .probe import _SafeParser
    parser = _SafeParser(prog="open-detective audit")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "plan", "run", "resume", "worker", "import", "status", "report", "evaluate", "bind-repositories", "preflight"):
        command = sub.add_parser(name)
        command.add_argument("--case", required=True)
        if name == "init":
            command.add_argument("--intake", required=True)
            command.add_argument("--mode", choices=("discovery", "recheck"), default="discovery")
        elif name == "plan":
            command.add_argument("--profile", choices=("thorough",), default="thorough")
        elif name in {"run", "resume", "worker"}:
            command.add_argument("--budget", required=True)
            command.add_argument("--scope")
            command.add_argument("--capabilities")
            command.add_argument("--channel-health")
            command.add_argument("--agent", choices=("cli", "codex", "claude"), default="cli")
            command.add_argument("--inspection-only", action="store_true")
        elif name == "bind-repositories":
            command.add_argument("--manifest", required=True)
            command.add_argument("--scope")
        elif name == "preflight":
            command.add_argument("--scope", required=True)
        elif name == "import":
            command.add_argument("--input", required=True)
            command.add_argument("--channel-health", required=True)
        elif name == "report":
            command.add_argument("--output", required=True)
            command.add_argument("--final", action="store_true",
                                 help="require completed inspection; still export gaps on failure")
        elif name == "evaluate":
            command.add_argument("--reference", required=True)
        else:
            command.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            answer = init_case(args.case, read_json(args.intake), args.mode)
        else:
            with Case(args.case) as case:
                if args.command in {"run", "resume", "worker"}:
                    answer = run_case(case, read_json(args.budget),
                        scope=Scope.load(args.scope) if args.scope else None,
                        capability=read_json(args.capabilities) if args.capabilities else None,
                        health=read_json(args.channel_health) if args.channel_health else None, agent=args.agent,
                        wait_for_retry=args.command == "worker", inspection_only=args.inspection_only)
                elif args.command == "bind-repositories":
                    from .repository_workflow import bind_repositories
                    answer = bind_repositories(case, read_json(args.manifest),
                        scope=Scope.load(args.scope) if args.scope else None)
                elif args.command == "preflight":
                    from .repository_workflow import preflight
                    answer = preflight(case, Scope.load(args.scope))
                elif args.command == "import":
                    answer = import_channel(case, read_json(args.input), read_json(args.channel_health))
                elif args.command == "report":
                    # Resolve both sides: Windows short directory names and
                    # lexical '..' aliases can identify the same state file.
                    if Path(args.output).resolve() in {(case.root / name).resolve() for name in (
                            "case.json", "search-plan.json", "repository-bindings.json", "ledger.sqlite", "locators.sqlite")}:
                        raise ValueError("case_state_overwrite_rejected")
                    answer = report_case(case)
                    answer["final_review_status"] = "complete" if answer["coverage"]["complete"] else "incomplete"
                    write_json(args.output, answer)
                    if args.final and not answer["coverage"]["complete"]:
                        print(json.dumps({"status": "incomplete", "report_written": True,
                                          "reason": "final_review_requirements_unmet"}))
                        return 3
                    answer = {"status": "written", "result_count": len(answer["results"])}
                elif args.command == "evaluate":
                    # This is the only code path that opens the held-out reference.
                    reference = read_json(args.reference)
                    wanted = set(reference.get("locator_refs", []))
                    known = {row[1]: row[0] for row in case.locators.db.execute(
                        "SELECT ref,url FROM locators WHERE scope_id=?", (case.scope_id,))}
                    wanted.update(known.get(url, "unseen:" + str(index))
                                  for index, url in enumerate(reference.get("urls", [])))
                    found = {j["asset_ref"] for j in case.queue.status()["jobs"] if j["job_type"] == "capture"}
                    answer = {"expected": len(wanted), "found": len(wanted & found), "missed": len(wanted - found),
                              "additional": len(found - wanted), "evaluation_only": True}
                else:
                    answer = case_status(case)
        print(json.dumps(answer, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error):
        print(json.dumps({"error": "audit_input_or_state_invalid"}))
        return 2
