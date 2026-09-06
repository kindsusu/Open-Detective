"""Bounded anonymous discovery of public GitHub accounts and repositories.

This collector only reads public metadata from ``api.github.com``.  Its output is
an ownership-review queue: repository and Pages URLs are candidates, never proof
that an organization owns a repository or that a Pages site is reachable.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping


_SCOPE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SAFE_ERRORS = {
    "ACCESS_DENIED",
    "BODY_LIMIT_EXCEEDED",
    "INPUT_INVALID",
    "MALFORMED_RESPONSE",
    "NOT_FOUND_OBSERVED",
    "PAGE_LIMIT_EXCEEDED",
    "PAGINATION_INVALID",
    "RATE_LIMITED",
    "REDIRECT_BLOCKED",
    "REQUEST_FAILED",
    "REQUEST_LIMIT_EXCEEDED",
    "RESULT_LIMIT_EXCEEDED",
    "SEARCH_INCOMPLETE",
    "TIME_LIMIT_EXCEEDED",
}
_API_VERSION = "2022-11-28"


class DiscoveryError(RuntimeError):
    """Expected failure with a report-safe error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in _SAFE_ERRORS else "REQUEST_FAILED"


@dataclass(frozen=True)
class Response:
    status: int
    payload: Any
    headers: Mapping[str, str]
    body_bytes: int = 0


Fetch = Callable[[str, Mapping[str, str]], Any]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_account(value: Any) -> str | None:
    if (not isinstance(value, str) or not _ACCOUNT_RE.fullmatch(value)
            or "--" in value):
        return None
    return value


def _valid_repo(value: Any) -> str | None:
    if not isinstance(value, str) or not _REPO_RE.fullmatch(value) or value in {".", ".."}:
        return None
    return value


def _repo_slug(owner: Any, repo: Any) -> str | None:
    account = _valid_account(owner)
    name = _valid_repo(repo)
    return f"{account}/{name}" if account and name else None


def _normalize_response(value: Any) -> Response:
    if isinstance(value, Response):
        return Response(value.status, value.payload,
                        {str(k).lower(): str(v) for k, v in value.headers.items()},
                        value.body_bytes)
    if isinstance(value, tuple):
        if len(value) == 3:
            status, payload, headers = value
            return Response(int(status), payload,
                            {str(k).lower(): str(v) for k, v in dict(headers).items()})
        if len(value) == 4:
            status, payload, headers, body_bytes = value
            return Response(int(status), payload,
                            {str(k).lower(): str(v) for k, v in dict(headers).items()},
                            int(body_bytes))
    if isinstance(value, Mapping) and "status" in value and "payload" in value:
        return Response(
            int(value["status"]), value["payload"],
            {str(k).lower(): str(v) for k, v in dict(value.get("headers", {})).items()},
            int(value.get("body_bytes", 0)),
        )
    return Response(200, value, {})


class GitHubBroker:
    """Stateless fixed-host GET broker with hard request/body/time budgets."""

    def __init__(self, *, fetch: Fetch | None = None, max_requests: int = 30,
                 timeout: float = 10.0, max_duration: float = 60.0,
                 max_response_bytes: int = 2 * 1024 * 1024,
                 max_total_bytes: int = 16 * 1024 * 1024):
        if isinstance(max_requests, bool) or not 1 <= max_requests <= 30:
            raise DiscoveryError("INPUT_INVALID")
        self.fetch = fetch
        self.max_requests = max_requests
        self.timeout = min(max(float(timeout), 0.1), 20.0)
        self.max_duration = min(max(float(max_duration), 0.1), 120.0)
        self.max_response_bytes = min(max(int(max_response_bytes), 1), 2 * 1024 * 1024)
        self.max_total_bytes = min(max(int(max_total_bytes), 1), 16 * 1024 * 1024)
        self.requests_used = 0
        self.bytes_used = 0
        self._started = time.monotonic()
        self._terminal_error: str | None = None

    @staticmethod
    def _validate_url(url: str, *, pagination_candidate: bool = False) -> None:
        try:
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except (TypeError, ValueError):
            raise DiscoveryError("INPUT_INVALID") from None
        if (parsed.scheme != "https" or parsed.hostname != "api.github.com"
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.fragment):
            raise DiscoveryError("INPUT_INVALID")
        singleton = all(len(values) == 1 for values in query.values())
        if not singleton:
            raise DiscoveryError("INPUT_INVALID")
        path = parsed.path
        allowed = False
        if path in {"/search/users", "/search/repositories"}:
            try:
                per_page = int(query.get("per_page", ["0"])[0])
                page = int(query.get("page", ["0"])[0])
            except (ValueError, IndexError):
                raise DiscoveryError("INPUT_INVALID") from None
            allowed = (set(query) == {"q", "per_page", "page"}
                       and 1 <= per_page <= 100
                       and 1 <= page <= (11 if pagination_candidate else 10)
                       and 1 <= len(query.get("q", [""])[0]) <= 256)
        elif re.fullmatch(r"/users/[^/]+/repos", path):
            owner = urllib.parse.unquote(path.split("/")[2])
            allowed = (_valid_account(owner) is not None
                       and set(query) == {"type", "sort", "direction", "per_page", "page"}
                       and query.get("type") == ["owner"]
                       and query.get("sort") == ["full_name"]
                       and query.get("direction") == ["asc"]
                       and query.get("per_page") == ["100"]
                       and query.get("page", [""])[0].isdigit()
                       and 1 <= int(query["page"][0]) <= 100)
        elif re.fullmatch(r"/user/[1-9][0-9]*/repos", path):
            # GitHub can canonicalize a username collection to an immutable
            # numeric-user collection in its Link header.
            allowed = (set(query) == {"type", "sort", "direction", "per_page", "page"}
                       and query.get("type") == ["owner"]
                       and query.get("sort") == ["full_name"]
                       and query.get("direction") == ["asc"]
                       and query.get("per_page") == ["100"]
                       and query.get("page", [""])[0].isdigit()
                       and 1 <= int(query["page"][0]) <= 100)
        elif re.fullmatch(r"/repos/[^/]+/[^/]+", path):
            parts = [urllib.parse.unquote(part) for part in path.split("/")[2:]]
            allowed = not query and _repo_slug(*parts) is not None
        if not allowed:
            raise DiscoveryError("INPUT_INVALID")

    def get(self, url: str) -> Response:
        self._validate_url(url)
        if self._terminal_error is not None:
            raise DiscoveryError(self._terminal_error)
        if self.requests_used >= self.max_requests:
            raise DiscoveryError("REQUEST_LIMIT_EXCEEDED")
        if time.monotonic() - self._started >= self.max_duration:
            raise DiscoveryError("TIME_LIMIT_EXCEEDED")
        self.requests_used += 1
        headers = {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "User-Agent": "su-detect-github-discovery/1 (anonymous public metadata)",
            "X-GitHub-Api-Version": _API_VERSION,
        }
        if self.fetch is not None:
            try:
                response = _normalize_response(self.fetch(url, headers))
            except DiscoveryError:
                raise
            except Exception as exc:
                raise DiscoveryError("REQUEST_FAILED") from exc
        else:
            request = urllib.request.Request(url, headers=headers, method="GET")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), _NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
            try:
                remaining = self.max_duration - (time.monotonic() - self._started)
                if remaining <= 0:
                    raise DiscoveryError("TIME_LIMIT_EXCEEDED")
                with opener.open(request, timeout=min(self.timeout, remaining)) as raw:
                    body = raw.read(self.max_response_bytes + 1)
                    if len(body) > self.max_response_bytes:
                        raise DiscoveryError("BODY_LIMIT_EXCEEDED")
                    try:
                        payload = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        raise DiscoveryError("MALFORMED_RESPONSE") from None
                    response = Response(
                        int(raw.status), payload,
                        {str(k).lower(): str(v) for k, v in raw.headers.items()}, len(body),
                    )
            except urllib.error.HTTPError as exc:
                response_headers = {
                    str(k).lower(): str(v)
                    for k, v in (exc.headers.items() if exc.headers else ())
                }
                code = self._http_error_code(exc.code, response_headers)
                if code == "RATE_LIMITED":
                    self._terminal_error = code
                raise DiscoveryError(code) from None
            except DiscoveryError:
                raise
            except Exception as exc:
                raise DiscoveryError("REQUEST_FAILED") from exc
        if not 200 <= response.status < 300:
            code = self._http_error_code(response.status, response.headers)
            if code == "RATE_LIMITED":
                self._terminal_error = code
            raise DiscoveryError(code)
        size = response.body_bytes
        if size < 0 or size > self.max_response_bytes:
            raise DiscoveryError("BODY_LIMIT_EXCEEDED")
        self.bytes_used += size
        if self.bytes_used > self.max_total_bytes:
            raise DiscoveryError("BODY_LIMIT_EXCEEDED")
        return response

    @staticmethod
    def _http_error_code(status: int, headers: Mapping[str, str]) -> str:
        if 300 <= status < 400:
            return "REDIRECT_BLOCKED"
        if status == 404:
            return "NOT_FOUND_OBSERVED"
        if status == 429:
            return "RATE_LIMITED"
        if status == 403:
            remaining = str(headers.get("x-ratelimit-remaining", "")).strip()
            if remaining == "0" or "retry-after" in headers:
                return "RATE_LIMITED"
            return "ACCESS_DENIED"
        return "REQUEST_FAILED"


def _known_pages_url(value: Any) -> tuple[str, str, str] | None:
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        host = (parsed.hostname or "").lower()
        if (parsed.scheme != "https" or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            return None
        if host == "github.com":
            segments = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
            if len(segments) != 2:
                return None
            owner, repo = segments
            if _valid_account(owner) is None or _valid_repo(repo) is None:
                return None
            clean = f"https://github.com/{urllib.parse.quote(owner, safe='-')}/{urllib.parse.quote(repo, safe='._-')}"
            return owner, repo, clean
        if not host.endswith(".github.io"):
            return None
        owner = host[:-len(".github.io")]
        if _valid_account(owner) is None:
            return None
        segments = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
        repo = segments[0] if segments else f"{owner}.github.io"
        if _valid_repo(repo) is None:
            return None
        # Retain only the canonical Pages project root.  A deeper known path can
        # contain an opaque or capability-bearing identifier.
        clean = (f"https://{host}/" if repo.casefold() == f"{owner}.github.io".casefold()
                 else f"https://{host}/{urllib.parse.quote(repo, safe='._-')}/")
        return owner, repo, clean
    except (UnicodeError, ValueError):
        return None


def _clean_homepage(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or any(ord(ch) < 32 for ch in value)):
            return None
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                return None
        except ValueError:
            if host == "localhost" or host.endswith(".local"):
                return None
        # Homepage metadata is only a pivot hint.  Keeping an arbitrary path can
        # copy a capability URL, so shared output contains the clean HTTPS origin.
        return f"https://{host}"
    except (UnicodeError, ValueError):
        return None


def _next_link(header: str | None, current_url: str,
               allowed_user_id: int | None = None) -> str | None:
    if not header:
        return None
    matches: list[str] = []
    for part in header.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', part)
        if not match:
            raise DiscoveryError("PAGINATION_INVALID")
        if match.group(2) == "next":
            matches.append(match.group(1))
    if len(matches) > 1:
        raise DiscoveryError("PAGINATION_INVALID")
    if not matches:
        return None
    candidate = matches[0]
    try:
        GitHubBroker._validate_url(candidate, pagination_candidate=True)
    except DiscoveryError:
        # Operator input was already validated; an unsafe provider cursor is a
        # pagination failure rather than an input failure.
        raise DiscoveryError("PAGINATION_INVALID") from None
    old = urllib.parse.urlsplit(current_url)
    new = urllib.parse.urlsplit(candidate)
    old_q = urllib.parse.parse_qs(old.query)
    new_q = urllib.parse.parse_qs(new.query)
    try:
        expected_page = int(old_q["page"][0]) + 1
    except (KeyError, ValueError, IndexError):
        raise DiscoveryError("PAGINATION_INVALID") from None
    same_resource = new.path == old.path
    canonical_match = re.fullmatch(r"/user/([1-9][0-9]*)/repos", new.path)
    canonical_user_resource = (re.fullmatch(r"/users/[^/]+/repos", old.path)
                               and canonical_match is not None
                               and allowed_user_id is not None
                               and int(canonical_match.group(1)) == allowed_user_id)
    if (not (same_resource or canonical_user_resource) or set(new_q) != set(old_q)
            or any(new_q[key] != old_q[key] for key in old_q if key != "page")
            or new_q.get("page") != [str(expected_page)]):
        raise DiscoveryError("PAGINATION_INVALID")
    return candidate


def _candidate(repo: Mapping[str, Any]) -> dict[str, Any] | None:
    owner_obj = repo.get("owner")
    owner = owner_obj.get("login") if isinstance(owner_obj, Mapping) else None
    name = repo.get("name")
    slug = _repo_slug(owner, name)
    full_name = repo.get("full_name")
    if slug is None or not isinstance(full_name, str) or full_name.casefold() != slug.casefold():
        return None
    if repo.get("private") is not False:
        return None
    pages_url = (f"https://{owner.lower()}.github.io/" if name.casefold() == f"{owner}.github.io".casefold()
                 else f"https://{owner.lower()}.github.io/{urllib.parse.quote(name, safe='._-')}/")
    return {
        "slug": slug,
        "github_url": f"https://github.com/{owner}/{name}",
        "has_pages": repo.get("has_pages") is True,
        "pages_url_candidate": pages_url,
        "pages_url_status": "candidate_not_confirmed",
        "homepage": _clean_homepage(repo.get("homepage")),
        "workflow": "ownership_pending",
        "scope_label": "authorized_public_metadata_discovery",
        "ownership": "pending",
    }


def _query_url(path: str, **params: str) -> str:
    return "https://api.github.com" + path + "?" + urllib.parse.urlencode(params)


def discover(scope_id: str, *, seeds: Iterable[str] = (), accounts: Iterable[str] = (),
             known_urls: Iterable[str] = (), max_requests: int = 30,
             fetch: Fetch | None = None, max_accounts: int = 10,
             max_results: int = 1000, max_pages: int = 10) -> dict[str, Any]:
    """Discover public GitHub metadata from bounded, operator-supplied clues."""
    observed_at = _utc_now()
    report: dict[str, Any] = {
        "schema_version": "1.0", "provider": "github_public", "scope_id": scope_id,
        "status": "COMPLETE", "observed_at": observed_at,
        "scope_label": "authorized_public_metadata_discovery",
        "ownership": "pending", "candidates": [], "accounts": [], "edges": [],
        "coverage": {}, "errors": [], "methods_executed": [],
        "limitations": [
            "public_metadata_only", "company_ownership_pending",
            "pages_url_candidates_not_fetched_or_confirmed",
            "third_party_homepages_not_fetched", "negative_results_are_channel_bounded",
        ],
    }
    try:
        if not isinstance(scope_id, str) or not _SCOPE_RE.fullmatch(scope_id):
            raise DiscoveryError("INPUT_INVALID")
        if (isinstance(max_accounts, bool) or not 1 <= max_accounts <= 10
                or isinstance(max_results, bool) or not 1 <= max_results <= 1000
                or isinstance(max_pages, bool) or not 1 <= max_pages <= 10):
            raise DiscoveryError("INPUT_INVALID")
        seed_list = list(dict.fromkeys(value.strip() for value in seeds
                                       if isinstance(value, str) and value.strip()))
        account_inputs = list(dict.fromkeys(value for value in accounts if isinstance(value, str)))
        known_inputs = list(dict.fromkeys(value for value in known_urls if isinstance(value, str)))
        if len(seed_list) > 10 or len(account_inputs) > 10 or len(known_inputs) > 100:
            raise DiscoveryError("INPUT_INVALID")
        if any(len(seed) > 128 or any(ord(ch) < 32 for ch in seed) for seed in seed_list):
            raise DiscoveryError("INPUT_INVALID")
        if any(_valid_account(account) is None for account in account_inputs):
            raise DiscoveryError("INPUT_INVALID")
        parsed_known = []
        for value in known_inputs:
            parsed = _known_pages_url(value)
            if parsed is None:
                raise DiscoveryError("INPUT_INVALID")
            parsed_known.append(parsed)
        broker = GitHubBroker(fetch=fetch, max_requests=max_requests)
    except DiscoveryError as exc:
        report["status"] = "FAILED"
        report["errors"] = [exc.code]
        report["coverage"]["input"] = {"state": "FAILED", "items": 0}
        return report

    found_accounts: dict[str, str] = {}
    expansion_accounts: list[str] = []
    expansion_priority: dict[str, int] = {}
    account_sources: dict[str, set[str]] = {}
    candidates: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    errors: list[str] = []
    successful_requests = 0
    total_rows = 0

    deferred: list[dict[str, str]] = []

    def add_account(login: Any, source: str, *, priority: int = 3) -> bool:
        valid = _valid_account(login)
        if valid is None:
            errors.append("MALFORMED_RESPONSE")
            return False
        key = valid.casefold()
        if key not in expansion_priority:
            if len(expansion_accounts) >= max_accounts:
                worst = max(expansion_accounts, key=lambda value: (expansion_priority[value.casefold()], expansion_accounts.index(value)))
                if priority >= expansion_priority[worst.casefold()]:
                    errors.append("RESULT_LIMIT_EXCEEDED")
                    deferred.append({"kind":"account_expansion","value":valid,"reason":"not_scheduled_due_to_cap"})
                    return False
                expansion_accounts.remove(worst)
                worst_key = worst.casefold()
                expansion_priority.pop(worst_key, None)
                found_accounts.pop(worst_key, None)
                account_sources.pop(worst_key, None)
                errors.append("RESULT_LIMIT_EXCEEDED")
                deferred.append({"kind":"account_expansion","value":worst,"reason":"not_scheduled_due_to_cap",
                                 "detail":"displaced_by_stronger_evidence"})
            expansion_accounts.append(valid)
            expansion_priority[key] = priority
        elif priority < expansion_priority.get(key, priority):
            expansion_priority[key] = priority
        canonical = found_accounts.setdefault(key, valid)
        account_sources.setdefault(key, set())
        account_sources.setdefault(key, set()).add(source)
        edges.add((source, f"account:{canonical}", "identified_account"))
        return True

    def add_repo(row: Any, source: str, *, priority: int = 2) -> bool:
        nonlocal total_rows
        if not isinstance(row, Mapping):
            errors.append("MALFORMED_RESPONSE")
            return False
        item = _candidate(row)
        if item is None:
            errors.append("MALFORMED_RESPONSE")
            return False
        owner = item["slug"].split("/", 1)[0]
        # Candidate retention and account expansion have separate limits. A
        # repository remains review evidence if its owner cannot be expanded.
        add_account(owner, source, priority=priority)
        key = item["slug"].casefold()
        if key not in candidates and len(candidates) >= max_results:
            errors.append("RESULT_LIMIT_EXCEEDED")
            return False
        candidates.setdefault(key, item)
        edges.add((f"account:{owner}", f"repo:{item['slug']}", "public_repository"))
        edges.add((source, f"repo:{item['slug']}", "reported_repository"))
        total_rows += 1
        return True

    for account in account_inputs:
        add_account(account, f"explicit_account:{account}", priority=1)
    known_repos: dict[str, tuple[str, str]] = {}
    for owner, repo, clean_url in parsed_known:
        source = f"known_url:{clean_url}"
        add_account(owner, source, priority=0)
        known_repos.setdefault(f"{owner.casefold()}/{repo.casefold()}", (f"{owner}/{repo}", source))

    def execute_pages(method: str, first_url: str, item_key: str,
                      consume: Callable[[Any, str], None]) -> None:
        nonlocal successful_requests
        requests_before = broker.requests_used
        url: str | None = first_url
        pages = items = 0
        state = "COMPLETE"
        expected_total: int | None = None
        method_error: str | None = None
        try:
            while url:
                if pages >= max_pages:
                    raise DiscoveryError("PAGE_LIMIT_EXCEEDED")
                response = broker.get(url)
                successful_requests += 1
                payload = response.payload
                rows = payload.get(item_key) if isinstance(payload, Mapping) else payload
                if not isinstance(rows, list):
                    raise DiscoveryError("MALFORMED_RESPONSE")
                before_errors = len(errors)
                if isinstance(payload, Mapping):
                    if payload.get("incomplete_results") is True:
                        errors.append("SEARCH_INCOMPLETE")
                        state = "PARTIAL"
                    total_count = payload.get("total_count")
                    if (isinstance(total_count, int) and not isinstance(total_count, bool)
                            and total_count > 1000):
                        errors.append("RESULT_LIMIT_EXCEEDED")
                        state = "PARTIAL"
                    if isinstance(total_count, int) and not isinstance(total_count, bool) and total_count >= 0:
                        expected_total = min(total_count, 1000)
                    elif total_count is not None:
                        raise DiscoveryError("MALFORMED_RESPONSE")
                allowed_user_id: int | None = None
                current = urllib.parse.urlsplit(url)
                user_match = re.fullmatch(r"/users/([^/]+)/repos", current.path)
                if user_match and rows:
                    requested_owner = urllib.parse.unquote(user_match.group(1)).casefold()
                    owner_ids: set[int] = set()
                    all_rows_match = True
                    for row in rows:
                        owner = row.get("owner") if isinstance(row, Mapping) else None
                        owner_id = owner.get("id") if isinstance(owner, Mapping) else None
                        if (not isinstance(owner, Mapping)
                                or not isinstance(owner.get("login"), str)
                                or owner["login"].casefold() != requested_owner
                                or not isinstance(owner_id, int) or isinstance(owner_id, bool)
                                or owner_id <= 0):
                            all_rows_match = False
                            break
                        owner_ids.add(owner_id)
                    if all_rows_match and len(owner_ids) == 1:
                        allowed_user_id = owner_ids.pop()
                source = f"github_api:{method}:page:{pages + 1}"
                for row in rows:
                    consume(row, source)
                if len(errors) > before_errors:
                    state = "PARTIAL"
                    if method_error is None:
                        method_error = errors[before_errors]
                pages += 1
                items += len(rows)
                next_url = _next_link(response.headers.get("link"), url, allowed_user_id)
                if next_url is None:
                    if expected_total is not None and items < expected_total:
                        raise DiscoveryError("PAGINATION_INVALID")
                    if expected_total is None and len(rows) == 100:
                        raise DiscoveryError("PAGINATION_INVALID")
                elif pages >= max_pages:
                    raise DiscoveryError("PAGE_LIMIT_EXCEEDED")
                url = next_url
        except DiscoveryError as exc:
            if exc.code == "NOT_FOUND_OBSERVED" and pages == 0 and method.startswith(
                    "list_public_repositories:"):
                method_error = None
                state = "COMPLETE"
                end_condition = "not_found_observed"
            else:
                errors.append(exc.code)
                method_error = method_error or exc.code
                state = "PARTIAL" if pages else "FAILED"
                end_condition = None
        else:
            end_condition = "page_exhausted" if state == "COMPLETE" else None
        report["coverage"][method] = {"state": state, "pages": pages, "items": items,
                                      "end_condition": end_condition,
                                      "error_code": method_error,
                                      "requests": broker.requests_used - requests_before}
        report["methods_executed"].append(method)

    # Exact known repositories run before any broad, potentially paginated search.
    for slug, source in known_repos.values():
        owner, repo = slug.split("/", 1)
        method = f"repository_detail:{owner}/{repo}"
        requests_before = broker.requests_used
        try:
            response = broker.get(
                f"https://api.github.com/repos/{urllib.parse.quote(owner, safe='-')}/"
                f"{urllib.parse.quote(repo, safe='._-')}"
            )
            successful_requests += 1
            if not add_repo(response.payload, source, priority=0):
                raise DiscoveryError("MALFORMED_RESPONSE")
            state, items = "COMPLETE", 1
        except DiscoveryError as exc:
            if exc.code == "NOT_FOUND_OBSERVED":
                method_error = None
                state, items = "COMPLETE", 0
                end_condition = "not_found_observed"
            else:
                errors.append(exc.code)
                method_error = exc.code
                state, items = "FAILED", 0
                end_condition = None
        else:
            method_error = None
            end_condition = "page_exhausted"
        report["coverage"][method] = {"state": state, "pages": 1 if items else 0, "items": items,
                                      "end_condition": end_condition,
                                      "error_code": method_error,
                                      "requests": broker.requests_used - requests_before}
        report["methods_executed"].append(method)

    # Exact operator accounts run before broad searches can consume the global
    # request budget. Strong known URL details already ran above.
    listed_accounts: set[str] = set()
    for account in list(expansion_accounts):
        if expansion_priority[account.casefold()] > 1:
            continue
        execute_pages(
            f"list_public_repositories:{account}",
            _query_url(f"/users/{urllib.parse.quote(account, safe='-')}/repos",
                       type="owner", sort="full_name", direction="asc", per_page="100", page="1"),
            "", add_repo,
        )
        listed_accounts.add(account.casefold())

    # Repository hits outrank user-name hits. Run the two search families in
    # priority order so low-quality user rows cannot consume every account slot.
    for index, seed in enumerate(seed_list, 1):
        execute_pages(
            f"search_repositories:{index}",
            _query_url("/search/repositories", q=f"{seed} in:name,description,readme", per_page="100", page="1"),
            "items", lambda row, source: add_repo(row, source, priority=2),
        )
    for index, seed in enumerate(seed_list, 1):
        execute_pages(
            f"search_users:{index}",
            _query_url("/search/users", q=f"{seed} in:login,fullname", per_page="100", page="1"),
            "items", lambda row, source: add_account(row.get("login") if isinstance(row, Mapping) else None, source, priority=3),
        )

    # Snapshot before listing: search results may discover more accounts, but the
    # hard cap prevents an API response from turning this into mass enumeration.
    # Strong known inputs reserve listing capacity even when weak search/account
    # guesses already filled the ordinary expansion queue.
    listing_accounts = [account for account in dict.fromkeys(expansion_accounts)
                        if account.casefold() not in listed_accounts][:max_accounts]
    for account in listing_accounts:
        method = f"list_public_repositories:{account}"
        execute_pages(
            method,
            _query_url(
                f"/users/{urllib.parse.quote(account, safe='-')}/repos",
                type="owner", sort="full_name", direction="asc", per_page="100", page="1",
            ),
            "", add_repo,
        )

    expansion_deferred = [item for item in deferred if item["kind"] == "account_expansion"]
    report["coverage"]["account_expansion"] = {
        "state": "PARTIAL" if expansion_deferred else "COMPLETE",
        "scheduled": len(listed_accounts) + len(listing_accounts),
        "deferred": len(expansion_deferred),
        "end_condition": "account_limit_reached" if expansion_deferred else "queue_exhausted",
        "error_code": "RESULT_LIMIT_EXCEEDED" if expansion_deferred else None,
    }

    absent_accounts = {
        method.removeprefix("list_public_repositories:").casefold()
        for method, coverage in report["coverage"].items()
        if (method.startswith("list_public_repositories:")
            and coverage.get("end_condition") == "not_found_observed")
    }

    report["accounts"] = [
        {"login": account, "github_url": f"https://github.com/{account}",
         "workflow": "ownership_pending", "scope_label": "authorized_public_metadata_discovery",
         "sources": sorted(account_sources[key]),
         "metadata_observation": "not_found" if key in absent_accounts else "observed_or_unresolved"}
        for key, account in sorted(found_accounts.items())
    ]
    report["candidates"] = sorted(candidates.values(), key=lambda item: item["slug"].casefold())
    report["edges"] = [
        {"source": source, "target": target, "relationship": relationship}
        for source, target, relationship in sorted(edges)
    ]
    report["deferred"] = deferred
    report["errors"] = sorted(set(code for code in errors if code in _SAFE_ERRORS))
    report["coverage"]["totals"] = {
        "state": "COMPLETE" if not report["errors"] else ("PARTIAL" if successful_requests else "FAILED"),
        "requests": broker.requests_used, "max_requests": broker.max_requests,
        "response_bytes": broker.bytes_used, "accounts": len(report["accounts"]),
        "unique_repositories": len(report["candidates"]), "rows_processed": total_rows,
    }
    if report["errors"]:
        report["status"] = "PARTIAL" if successful_requests else "FAILED"
    elif not report["methods_executed"]:
        report["status"] = "FAILED"
        report["errors"] = ["INPUT_INVALID"]
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded anonymous GitHub public-metadata discovery")
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--account", action="append", default=[])
    parser.add_argument("--known-url", action="append", default=[])
    parser.add_argument("--max-requests", type=int, default=30)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    report = discover(
        args.scope_id, seeds=args.seed, accounts=args.account,
        known_urls=args.known_url, max_requests=args.max_requests,
    )
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["status"] != "FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
