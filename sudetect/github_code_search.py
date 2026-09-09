"""Explicitly credentialed public code-search metadata; never target measurement."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .github_discovery import _NoRedirect, _normalize_response, _repo_slug

CHANNEL = "github_code"
MAX_REQUESTS = 10
MAX_ASSETS = 5000
MAX_BODY = 2 * 1024 * 1024
MAX_QUERY = 512
_RESUMABLE_DEFERRED = {"REQUEST_BUDGET", "TIME_BUDGET", "BYTE_BUDGET", "RATE_LIMITED", "explicit_token_required"}
# These failures can change after the operator explicitly asks to retry: a
# replacement explicit token can fix authentication, a transport failure can
# be transient, and the two cursor failures require a fresh cursor.  Never
# promote scope, publicness, metadata, or provider-coverage failures.
_RETRYABLE_FAILED = {"AUTH_FAILED", "REQUEST_FAILED", "SEARCH_INDEX_CHANGED", "SEARCH_RESULTS_OVERLAP"}
LIMITATIONS = ["public_code_search_metadata_only", "default_branch_only",
               "indexed_files_smaller_than_384KB", "provider_max_1000_results_per_query",
               "index_freshness_and_unindexed_assets_unknown", "not_anonymous_target_observation",
               "ownership_and_sensitive_content_not_established"]


def stamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("input_too_large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid_input")
    return value


def _term(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 180:
        raise ValueError("invalid_search_term")
    # Identity strings are data, never caller-supplied search qualifiers.
    if any(ord(c) < 32 for c in value) or any(c in value for c in '"\\:'):
        raise ValueError("invalid_search_term")
    return '"' + " ".join(value.split()) + '"'


def _repository(value):
    if not isinstance(value, str) or value.count("/") != 1:
        raise ValueError("invalid_repository")
    owner, name = value.split("/")
    slug = _repo_slug(owner, name)
    if slug is None or slug != value:
        raise ValueError("invalid_repository")
    return slug


def enable_code_search(plan, repositories=()):
    """Add repository-scoped jobs and quarantine legacy unscoped jobs."""
    from .search_plan import _id, _status
    out = json.loads(json.dumps(plan))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", out.get("scope_id", "")):
        raise ValueError("invalid_scope")
    jobs = out["jobs"]
    if len(jobs) > 10000:
        raise ValueError("too_many_jobs")
    requested = [_repository(value) for value in repositories]
    configured = [_repository(value) for value in out.get("code_repositories", [])]
    repository_by_key = {}
    for value in configured + requested:
        repository_by_key.setdefault(value.casefold(), value)
    repositories = list(repository_by_key.values())
    out["code_repositories"] = repositories
    existing = {j["work_id"] for j in jobs}
    for job in jobs:
        if job.get("channel") == CHANNEL and not job.get("repository"):
            job["state"] = "deferred"
            job["deferred_reason"] = ("superseded_by_repository_scoped_jobs" if repositories
                                      else "repository_scope_required")
    seeds = [(d, "operator-domain-seed") for d in out.get("identity", {}).get("domains", [])]
    seeds += [(j["value"], j.get("generation_rationale", "existing-query"))
              for j in jobs if j.get("channel") == "github" and j.get("kind") == "search_query"]
    budget = out.get("budgets", {}).get("github_queries", 4)
    count = 0
    seen = set()
    for repository in repositories:
        for value, rationale in seeds:
            query = _term(value) + " repo:" + repository + " in:file"
            if query.casefold() in seen:
                continue
            seen.add(query.casefold())
            jid = _id("wrk", out["plan_id"], CHANNEL, "search_query", query)
            if jid not in existing:
                if len(jobs) >= 10000:
                    raise ValueError("too_many_jobs")
                jobs.append({"work_id": jid, "channel": CHANNEL, "kind": "search_query", "value": query,
                             "repository": repository, "generation_rationale": rationale,
                             "state": "planned" if count < budget else "deferred",
                             "deferred_reason": "explicit_code_runner_required" if count < budget else "query_budget_exceeded",
                             "request_budget": 1, "result_count": None, "pages": None,
                             "end_condition": None, "error_code": None})
                existing.add(jid)
            count += 1
    if CHANNEL not in out["required_channels"]:
        out["required_channels"].append(CHANNEL)
    out["status"] = _status(out)
    return out


class CodeError(ValueError):
    pass


class Broker:
    """Only explicit search tokens, only a fixed GET search endpoint, no redirects."""
    def __init__(self, token, *, limit=10, fetcher=None):
        self.token = token
        self.limit = limit
        self.fetcher = fetcher
        self.requests = 0
        self.bytes = 0
        self.deadline = time.monotonic() + 60
        self.retry_at = None
        self.public_preflights = 0
        self.public_repositories = set()

    def _request(self, url, headers):
        if self.requests >= self.limit:
            raise CodeError("REQUEST_BUDGET")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CodeError("TIME_BUDGET")
        if self.bytes >= 8 * 1024 * 1024:
            raise CodeError("BYTE_BUDGET")
        self.requests += 1
        try:
            if self.fetcher is not None:
                response = _normalize_response(self.fetcher(url, headers))
                body = json.dumps(response.payload).encode()
                status, payload, response_headers = response.status, response.payload, response.headers
            else:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
                request = urllib.request.Request(url, headers=headers, method="GET")
                with opener.open(request, timeout=min(10, remaining)) as raw:
                    from .transport import _read_bounded
                    body, complete = _read_bounded(raw, min(MAX_BODY, 8 * 1024 * 1024 - self.bytes),
                                                  min(self.deadline, time.monotonic() + 10))
                    status, response_headers = raw.status, dict(raw.headers)
                if not complete:
                    self.bytes += len(body)
                    raise CodeError("BYTE_BUDGET")
                payload = json.loads(body) if len(body) <= MAX_BODY else None
            self.bytes += len(body)
            if len(body) > MAX_BODY or self.bytes > 8 * 1024 * 1024:
                raise CodeError("BYTE_BUDGET")
        except urllib.error.HTTPError as exc:
            status, response_headers, payload = exc.code, dict(exc.headers), None
        except CodeError:
            raise
        except Exception:
            raise CodeError("REQUEST_FAILED") from None
        response_headers = {str(k).lower(): str(v) for k, v in response_headers.items()}
        if status in (403, 429):
            reset = response_headers.get("x-ratelimit-reset", "")
            if reset.isdigit() and len(reset) <= 12:
                self.retry_at = int(reset)
            retry = response_headers.get("retry-after", "")
            if retry.isdigit() and len(retry) <= 8:
                self.retry_at = int(time.time()) + int(retry)
            raise CodeError("RATE_LIMITED" if status == 429 or retry or response_headers.get("x-ratelimit-remaining") == "0" else "ACCESS_DENIED")
        if status == 401:
            raise CodeError("AUTH_FAILED")
        if 300 <= status < 400:
            raise CodeError("REDIRECT_BLOCKED")
        return status, payload

    def preflight(self, repository):
        repository = _repository(repository)
        key = repository.casefold()
        if key in self.public_repositories:
            return
        url = "https://api.github.com/repos/" + urllib.parse.quote(repository, safe="/")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "open-detective-code-search/1"}
        before = self.requests
        try:
            status, payload = self._request(url, headers)
        finally:
            if self.requests > before:
                self.public_preflights += 1
        if (status != 200 or not isinstance(payload, dict) or payload.get("private") is not False
                or payload.get("visibility", "public") != "public"
                or not isinstance(payload.get("full_name"), str)
                or payload["full_name"].casefold() != key):
            raise CodeError("REPOSITORY_NOT_PUBLIC")
        self.public_repositories.add(key)

    def get(self, query, page):
        match = re.fullmatch(r'"[^"\\:\x00-\x1f]{1,180}" repo:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+) in:file', query) if isinstance(query, str) and len(query) <= MAX_QUERY else None
        if match is None:
            raise CodeError("QUERY_INVALID")
        try:
            repository = _repository(match.group(1))
        except ValueError:
            raise CodeError("QUERY_INVALID") from None
        if type(page) is not int or not 1 <= page <= 10:
            raise CodeError("PAGE_LIMIT")
        self.preflight(repository)
        url = "https://api.github.com/search/code?" + urllib.parse.urlencode({"q": query, "per_page": 100, "page": page})
        headers = {"Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "open-detective-code-search/1"}
        status, payload = self._request(url, headers)
        if status != 200:
            raise CodeError("SEARCH_FAILED")
        if (not isinstance(payload, dict) or type(payload.get("total_count")) is not int or payload["total_count"] < 0
                or type(payload.get("incomplete_results")) is not bool or not isinstance(payload.get("items"), list)
                or len(payload["items"]) > 100 or payload["total_count"] < len(payload["items"])):
            raise CodeError("MALFORMED_RESPONSE")
        return payload


def _file(item):
    """Accept only public repository metadata and a matching provider blob URL."""
    if not isinstance(item, dict) or not isinstance(item.get("repository"), dict):
        raise CodeError("INVALID_FILE_METADATA")
    repo = item["repository"]
    if repo.get("private") is not False or repo.get("visibility", "public") != "public":
        raise CodeError("NONPUBLIC_OR_UNKNOWN_REPOSITORY")
    owner = repo.get("owner", {})
    slug = _repo_slug(owner.get("login") if isinstance(owner, dict) else None, repo.get("name"))
    if not slug or repo.get("full_name", slug).casefold() != slug.casefold() or type(repo.get("id")) is not int or repo["id"] <= 0:
        raise CodeError("INVALID_REPOSITORY_METADATA")
    path, sha, url = item.get("path"), item.get("sha"), item.get("html_url")
    if (not isinstance(path, str) or not 1 <= len(path) <= 2048 or "\\" in path
            or any(p in ("", ".", "..") for p in path.split("/")) or any(ord(c) < 32 for c in path)
            or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha)
            or not isinstance(url, str) or len(url) > 8192):
        raise CodeError("INVALID_FILE_METADATA")
    parsed = urllib.parse.urlsplit(url)
    prefix = "/" + slug + "/blob/"
    decoded = urllib.parse.unquote(parsed.path)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment
            or not decoded.casefold().startswith(prefix.casefold()) or not decoded.endswith("/" + path)):
        raise CodeError("INVALID_FILE_LOCATION")
    ref = decoded[len(prefix):-(len(path) + 1)]
    if not ref or any(x in ("", ".", "..") for x in ref.split("/")) or any(ord(c) < 33 for c in ref):
        raise CodeError("INVALID_FILE_LOCATION")
    return repo["id"], slug, path, sha, url, bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ref))


def _control(value):
    if not isinstance(value, dict) or set(value) != {"control_id", "query", "repository", "path", "expires_at"}:
        raise ValueError("invalid_code_control")
    if not all(isinstance(v, str) for v in value.values()):
        raise ValueError("invalid_code_control")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["control_id"]):
        raise ValueError("invalid_code_control")
    parts = value["repository"].split("/")
    if len(parts) != 2 or _repo_slug(*parts) is None or not isinstance(value["path"], str) or not value["path"]:
        raise ValueError("invalid_code_control")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("expired_code_control")
    return _term(value["query"]) + " repo:" + _repository(value["repository"]) + " in:file"


def run_code(plan, *, token_env, control, locator_store, request_budget=10,
             resume_query_budget=0, retry_failed=False, fetcher=None, persist=None):
    from .search_plan import _status
    if type(request_budget) is not int or not 1 <= request_budget <= 10:
        raise ValueError("invalid_request_budget")
    if type(resume_query_budget) is not int or not 0 <= resume_query_budget <= 10:
        raise ValueError("invalid_resume_budget")
    if not isinstance(token_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", token_env):
        raise ValueError("invalid_token_environment_name")
    out = json.loads(json.dumps(plan))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", out.get("scope_id", "")):
        raise ValueError("invalid_scope")
    if CHANNEL not in out.get("required_channels", []):
        raise ValueError("code_channel_not_enabled")
    jobs = [j for j in out["jobs"] if j.get("channel") == CHANNEL]
    configured_repositories = {_repository(value).casefold() for value in out.get("code_repositories", [])}
    runnable = []
    scope_gap = False
    for job in jobs:
        if retry_failed and job["state"] == "failed" and job.get("error_code") in _RETRYABLE_FAILED:
            if job.get("error_code") in {"SEARCH_INDEX_CHANGED", "SEARCH_RESULTS_OVERLAP"}:
                job.pop("code_cursor", None)
            job["state"] = "planned"
        if (job["state"] == "deferred" and job.get("repository") and
                (job.get("deferred_reason") in _RESUMABLE_DEFERRED or
                 (job.get("deferred_reason") == "query_budget_exceeded" and resume_query_budget))):
            if job.get("deferred_reason") == "query_budget_exceeded":
                resume_query_budget -= 1
            job["state"] = "planned"
        if job.get("state") != "planned":
            continue
        repository = job.get("repository")
        try:
            scoped_repository = _repository(repository)
            match = re.fullmatch(r'"[^"\\:\x00-\x1f]{1,180}" repo:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+) in:file', str(job.get("value", "")))
            if (match is None or _repository(match.group(1)).casefold() != scoped_repository.casefold()
                    or scoped_repository.casefold() not in configured_repositories):
                raise ValueError("invalid_scope")
        except ValueError:
            job.update(state="deferred", deferred_reason="repository_scope_required")
            scope_gap = True
            continue
        job["repository"] = scoped_repository
        runnable.append(job)
    run = {"run_id": "code_" + uuid.uuid4().hex, "observed_at": stamp(), "source_ref": "github_api:explicit_code_search",
           "status": "PARTIAL", "requests": 0, "bytes": 0, "public_preflights": 0, "errors": [], "control": {"control_id": control["control_id"], "state": "NOT_CHECKED"},
           "synthetic": fetcher is not None}
    out.setdefault("code_runs", []).append(run)
    assets = out.setdefault("code_assets", [])
    scope_id = out["scope_id"]
    def finish(error=None):
        if error and error not in run["errors"]:
            run["errors"].append(error)
        out["status"] = _status(out)
        out["updated_at"] = stamp()
        out["last_code_execution"] = {"run_id": run["run_id"], "requests": run["requests"], "errors": run["errors"]}
        if persist:
            persist(out)
        return out
    if not runnable:
        run["status"] = "NO_RUNNABLE_WORK"
        return finish("REPOSITORY_SCOPE_REQUIRED" if scope_gap else None)
    token = os.environ.get(token_env)
    if not token or len(token) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        for job in jobs:
            if job["state"] == "planned":
                job.update(state="deferred", deferred_reason="explicit_token_required")
        return finish("EXPLICIT_TOKEN_REQUIRED")
    control_query = _control(control)
    out["code_repository_locator_refs"] = {
        repository: locator_store.put(scope_id, "https://github.com/" + repository)
        for repository in sorted({_repository(value) for value in out.get("code_repositories", [])}, key=str.casefold)
    }
    # A persisted per-plan window prevents immediate resume from resetting its budget.
    now = time.time()
    window = out.get("code_rate_window", {}) if fetcher is None else {}
    if now - window.get("started", 0) >= 60 or now < window.get("started", 0):
        window = {"started": now, "used": 0}
    allowance = min(request_budget, MAX_REQUESTS - window.get("used", 0))
    if allowance <= 0:
        run["retry_after_epoch"] = window["started"] + 60
        return finish("RATE_WINDOW_EXHAUSTED")
    broker = Broker(token, limit=allowance, fetcher=fetcher)
    def checkpoint():
        run.update(requests=broker.requests, bytes=broker.bytes, public_preflights=broker.public_preflights)
        if fetcher is None:
            out["code_rate_window"] = {"started": window["started"], "used": window["used"] + broker.requests}
        if persist:
            persist(out)
    try:
        check = broker.get(control_query, 1)
        checkpoint()
        matches = [_file(item) for item in check["items"]]
        if (check["incomplete_results"] or any(x[1].casefold() != control["repository"].casefold() for x in matches)
                or not any(x[2] == control["path"] for x in matches)):
            raise CodeError("CONTROL_EXPECTATION_FAILED")
        run["control"].update(state="SYNTHETIC_OK" if fetcher else "OK", observed_at=stamp())
    except (CodeError, ValueError, TypeError, AttributeError) as exc:
        checkpoint()
        run["control"]["state"] = "FAILED"
        if isinstance(exc, CodeError):
            run["control"]["error_code"] = str(exc)
        if broker.retry_at:
            run["retry_after_epoch"] = broker.retry_at
        return finish("CODE_CONTROL_FAILED")
    for job in runnable:
        query = job["value"]
        repository = job["repository"]
        digest = hashlib.sha256(query.encode()).hexdigest()
        cursor = job.setdefault("code_cursor", {"query_sha256": digest, "next_page": 1, "items": 0, "pages": 0})
        if cursor["query_sha256"] != digest:
            raise ValueError("changed_query_cursor")
        attempt = {"run_id": run["run_id"], "observed_at": stamp(), "source_ref": run["source_ref"], "pages": 0, "errors": []}
        job.setdefault("attempts", []).append(attempt)
        try:
            while True:
                page = cursor["next_page"]
                payload = broker.get(query, page)
                checkpoint()
                if "total_count" in cursor and cursor["total_count"] != payload["total_count"]:
                    raise CodeError("SEARCH_INDEX_CHANGED")
                cursor["total_count"] = payload["total_count"]
                invalid = None
                page_assets = []
                accepted = []
                for item in payload["items"]:
                    try:
                        repo_id, slug, path, sha, url, immutable = _file(item)
                        if slug.casefold() != repository.casefold():
                            raise CodeError("OFF_SCOPE_REPOSITORY")
                    except (CodeError, ValueError, AttributeError, TypeError) as exc:
                        invalid = "OFF_SCOPE_REPOSITORY" if str(exc) == "OFF_SCOPE_REPOSITORY" else "INVALID_OR_NONPUBLIC_ITEMS"
                        continue
                    accepted.append((repo_id, slug, path, sha, url, immutable))
                if invalid:
                    raise CodeError(invalid)
                for repo_id, slug, path, sha, url, immutable in accepted:
                    repo_ref = locator_store.put(scope_id, "https://github.com/" + slug)
                    asset_id = "file_" + uuid.uuid5(uuid.UUID(repo_ref.split(":")[1]), str(repo_id) + "/" + path).hex
                    if asset_id in cursor.get("seen_assets", []) or asset_id in page_assets:
                        raise CodeError("SEARCH_RESULTS_OVERLAP")
                    page_assets.append(asset_id)
                    asset = next((a for a in assets if a["asset_id"] == asset_id), None)
                    if asset is None:
                        if len(assets) >= MAX_ASSETS:
                            raise CodeError("ASSET_LIMIT")
                        asset = {"asset_id": asset_id, "kind": "repository_file", "repository_id": repo_id,
                                 "repository_locator_ref": repo_ref, "ownership": "ownership_pending",
                                 "public_exposure": "not_measured", "content": "NOT_INSPECTED", "evidence_refs": [], "revisions": []}
                        assets.append(asset)
                    location = locator_store.put(scope_id, url)
                    revision = {"git_blob_sha": sha, "locator_ref": location, "locator_mutability": "immutable" if immutable else "branch_ref_mutable"}
                    if revision not in asset["revisions"]:
                        asset["revisions"].append(revision)
                    asset.update(locator_ref=location, git_blob_sha=sha, observed_at=stamp())
                    evidence = {"work_id": job["work_id"], "run_id": run["run_id"], "page": page}
                    if evidence not in asset["evidence_refs"]:
                        asset["evidence_refs"].append(evidence)
                if payload["incomplete_results"]:
                    raise CodeError("SEARCH_INCOMPLETE")
                cursor.setdefault("seen_assets", []).extend(page_assets)
                cursor["pages"] += 1
                cursor["items"] += len(payload["items"])
                attempt["pages"] += 1
                if cursor["items"] >= payload["total_count"] and payload["total_count"] <= 1000:
                    job.update(state="completed", error_code=None, end_condition="page_exhausted", result_count=cursor["items"],
                               pages=cursor["pages"], observed_at=stamp(), source_ref=run["source_ref"])
                    break
                if len(payload["items"]) < 100:
                    raise CodeError("PAGINATION_INCOMPLETE")
                cursor["next_page"] += 1
                if cursor["next_page"] > 10:
                    raise CodeError("PROVIDER_RESULT_CAP")
                checkpoint()
        except CodeError as exc:
            code = str(exc)
            attempt["errors"].append(code)
            job.update(state="deferred" if code in {"REQUEST_BUDGET", "TIME_BUDGET", "BYTE_BUDGET", "RATE_LIMITED"} else "failed",
                       deferred_reason=code, error_code=code, result_count=cursor["items"], pages=cursor["pages"],
                       end_condition=None, observed_at=stamp(), source_ref=run["source_ref"])
            run["errors"].append(code)
            if code in {"REQUEST_BUDGET", "TIME_BUDGET", "BYTE_BUDGET", "RATE_LIMITED", "AUTH_FAILED", "ACCESS_DENIED"}:
                break
        checkpoint()
    checkpoint()
    if broker.retry_at:
        run["retry_after_epoch"] = broker.retry_at
    run["status"] = "COMPLETE" if not run["errors"] and all(j["state"] == "completed" for j in jobs) else "PARTIAL"
    return finish()


def export_report(plan):
    jobs = [j for j in plan["jobs"] if j["channel"] == CHANNEL]
    configured = {}
    for value in plan.get("code_repositories", []):
        try:
            repository = _repository(value)
        except ValueError:
            continue
        configured.setdefault(repository.casefold(), repository)

    def valid_scoped_job(job):
        try:
            repository = _repository(job.get("repository"))
            match = re.fullmatch(r'"[^"\\:\x00-\x1f]{1,180}" repo:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+) in:file',
                                 str(job.get("value", "")))
            if match is None or _repository(match.group(1)).casefold() != repository.casefold():
                return None
        except ValueError:
            return None
        return repository if repository.casefold() in configured else None

    def configured_reference_key(value):
        try:
            return _repository(value).casefold() in configured
        except ValueError:
            return False

    scoped = [(job, valid_scoped_job(job)) for job in jobs]
    active = [job for job, repository in scoped if repository is not None]
    scope_gap_jobs = sum(bool(repository is None and
                               job.get("deferred_reason") != "superseded_by_repository_scoped_jobs")
                         for job, repository in scoped)
    raw_refs = plan.get("code_repository_locator_refs") or {}
    refs = sorted({ref for repository, ref in raw_refs.items()
                   if (isinstance(ref, str) and re.fullmatch(r"opaque:[0-9a-f]{32}", ref)
                       and configured_reference_key(repository))})
    completed = sum(j.get("state") == "completed" for j in active)
    active_repositories = {valid_scoped_job(job).casefold() for job in active}
    return {"schema_version": "1.0", "scope_id": plan["scope_id"], "plan_id": plan["plan_id"],
            "assets": plan.get("code_assets", []), "runs": plan.get("code_runs", []),
            "jobs": [{k: j.get(k) for k in ("work_id", "state", "result_count", "pages", "end_condition", "error_code", "deferred_reason")}
                     for j in jobs],
            "selected_repository_scope": {"repository_count": len(configured),
                                           "repository_locator_refs": refs,
                                           "attempted_repository_count": len({j.get("repository").casefold() for j in active if j.get("attempts")})},
            "job_counts": {"completed": completed, "pending": sum(j.get("state") != "completed" for j in active),
                           "legacy_superseded": sum(j.get("deferred_reason") == "superseded_by_repository_scoped_jobs" for j in jobs),
                           "scope_gap": scope_gap_jobs},
            "global_search_performed": False,
            "limitations": LIMITATIONS,
            "coverage": "selected_scope_complete" if (not scope_gap_jobs and configured and set(configured) <= active_repositories
                                                          and all(j["state"] == "completed" for j in active)) else "partial"}
