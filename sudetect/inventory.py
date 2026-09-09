"""Authenticated, read-only control-plane inventory collectors.

The collectors intentionally return only normalized and sanitized metadata.  A
caller that needs the exact locator must keep it in an approved local system and
use ``locator_ref`` to correlate it; raw provider responses are never returned.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


SCHEMA_VERSION = "1.0"
_SCOPE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_ALLOWED_HOSTS = {"api.vercel.com", "api.github.com"}
_SAFE_ERROR_CODES = {
    "AUTH_FAILED",
    "CURSOR_LOOP",
    "IMPORT_INVALID",
    "IMPORT_SOURCE_INCOMPLETE",
    "IMPORT_PROVENANCE_MISSING",
    "MALFORMED_RESPONSE",
    "PAGE_LIMIT_EXCEEDED",
    "PAGINATION_UNCONFIRMED",
    "PERMISSION_DENIED",
    "RATE_LIMITED",
    "REDIRECT_BLOCKED",
    "REQUEST_FAILED",
    "SCOPE_INVALID",
    "TOKEN_MISSING",
    "TREE_TRUNCATED",
}
_NAMESPACE = uuid.UUID("28cc46c4-1cee-49ec-9957-8615f7fdbe10")
MAX_GITHUB_TREE_FILES_PER_REPOSITORY = 1000
MAX_GITHUB_TREE_FILES_PER_REPORT = 5000

_TREE_FILE_CANDIDATE_KINDS = {
    "data_file": frozenset({
        "csv", "db", "json", "jsonl", "ndjson", "parquet", "sqlite", "sql", "tsv", "xls", "xlsx",
    }),
    "document": frozenset({"doc", "docx", "md", "pdf", "ppt", "pptx", "rtf", "txt"}),
    "source_code": frozenset({
        "c", "cc", "cpp", "cs", "css", "go", "h", "hpp", "html", "java", "js", "jsx", "kt", "php",
        "py", "rb", "rs", "sh", "swift", "ts", "tsx", "vue",
    }),
    "config": frozenset({"cfg", "conf", "env", "ini", "properties", "toml", "yaml", "yml"}),
}
_SAFE_TREE_FILE_EXTENSIONS = frozenset().union(*_TREE_FILE_CANDIDATE_KINDS.values())


class InventoryError(RuntimeError):
    """An expected collector failure carrying a safe, non-secret code."""

    def __init__(self, code: str, *, status: int | None = None):
        super().__init__(code)
        self.code = code if code in _SAFE_ERROR_CODES else "REQUEST_FAILED"
        self.status = status


@dataclass(frozen=True)
class Response:
    status: int
    payload: Any
    headers: Mapping[str, str]


Fetch = Callable[[str, Mapping[str, str]], Any]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_scope(scope_id: str) -> str:
    if not isinstance(scope_id, str) or not _SCOPE_RE.fullmatch(scope_id):
        raise InventoryError("SCOPE_INVALID")
    return scope_id


def _provider_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _PROVIDER_ID_RE.fullmatch(value) else None


def _evidence_ref(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", value) else None


def _provenance_id(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", value) else None


def _utc_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_code(status: int) -> str:
    if status == 401:
        return "AUTH_FAILED"
    if status == 403:
        return "PERMISSION_DENIED"
    if status == 429:
        return "RATE_LIMITED"
    if 300 <= status < 400:
        return "REDIRECT_BLOCKED"
    return "REQUEST_FAILED"


def _normalize_response(value: Any) -> Response:
    if isinstance(value, Response):
        return value
    if isinstance(value, tuple):
        if len(value) == 3:
            status, payload, headers = value
            return Response(int(status), payload, {str(k).lower(): str(v) for k, v in dict(headers).items()})
        if len(value) == 2:
            payload, headers = value
            return Response(200, payload, {str(k).lower(): str(v) for k, v in dict(headers).items()})
    if isinstance(value, Mapping) and {"status", "payload"}.issubset(value):
        return Response(
            int(value["status"]),
            value["payload"],
            {str(k).lower(): str(v) for k, v in dict(value.get("headers", {})).items()},
        )
    return Response(200, value, {})


class Broker:
    """Fixed-host HTTPS broker with no proxy, redirect, cookie, or netrc use."""

    def __init__(self, token: str, provider: str, fetch: Fetch | None = None, timeout: float = 20.0, scope_id: str | None = None):
        self._token = token
        self.provider = provider
        self.fetch = fetch
        self.timeout = timeout
        self.scope_id = scope_id

    def get(self, url: str) -> Response:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS or parsed.port not in (None, 443):
            raise InventoryError("REQUEST_FAILED")
        expected = "api.vercel.com" if self.provider == "vercel" else "api.github.com"
        if parsed.hostname != expected or parsed.username or parsed.password or parsed.fragment:
            raise InventoryError("REQUEST_FAILED")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if self.provider == "vercel":
            allowed = (
                parsed.path == "/v10/projects"
                or parsed.path == "/v6/deployments"
                or bool(re.fullmatch(r"/v9/projects/[^/]+(?:/domains)?", parsed.path))
                or bool(re.fullmatch(r"/v2/deployments/[^/]+/aliases", parsed.path))
            )
            allowed_keys = {"teamId"}
            if parsed.path == "/v10/projects": allowed_keys |= {"limit", "from"}
            elif parsed.path == "/v6/deployments": allowed_keys |= {"projectId", "limit", "until"}
            elif parsed.path.endswith("/domains"): allowed_keys |= {"limit", "until"}
            singleton_values = all(len(values) == 1 for values in query.values())
            if not allowed or query.get("teamId") != [self.scope_id] or not set(query).issubset(allowed_keys) or not singleton_values:
                raise InventoryError("REQUEST_FAILED")
        else:
            allowed = (
                parsed.path == "/user"
                or bool(re.fullmatch(r"/user/repos", parsed.path))
                or bool(re.fullmatch(r"/orgs/[^/]+/repos", parsed.path))
                or bool(re.fullmatch(r"/repos/[^/]+/[^/]+/git/trees/[^/]+", parsed.path))
            )
            query_ok = False
            if parsed.path == "/user":
                query_ok = not query
            elif parsed.path == "/user/repos":
                query_ok = query.get("affiliation") == ["owner"] and query.get("visibility") == ["all"] and query.get("per_page") == ["100"] and len(query.get("page", [])) == 1 and query["page"][0].isdigit() and set(query) == {"affiliation","visibility","per_page","page"}
            elif parsed.path.startswith("/orgs/"):
                path_owner = urllib.parse.unquote(parsed.path.split("/")[2])
                query_ok = path_owner.casefold() == str(self.scope_id).casefold() and query.get("type") == ["all"] and query.get("per_page") == ["100"] and len(query.get("page", [])) == 1 and query["page"][0].isdigit() and set(query) == {"type","per_page","page"}
            elif "/git/trees/" in parsed.path:
                path_owner = urllib.parse.unquote(parsed.path.split("/")[2])
                query_ok = path_owner.casefold() == str(self.scope_id).casefold() and query == {"recursive":["1"]}
            if not allowed or not query_ok:
                raise InventoryError("REQUEST_FAILED")
        headers = {"Accept": "application/json", "User-Agent": "open-detective-inventory/1"}
        if self.provider == "vercel":
            headers["Authorization"] = f"Bearer {self._token}"
        else:
            headers["Authorization"] = f"Bearer {self._token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if self.fetch is not None:
            try:
                response = _normalize_response(self.fetch(url, headers))
            except InventoryError:
                raise
            except Exception as exc:
                raise InventoryError("REQUEST_FAILED") from exc
        else:
            request = urllib.request.Request(url, headers=headers, method="GET")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
            try:
                with opener.open(request, timeout=self.timeout) as raw:
                    body = raw.read(8 * 1024 * 1024 + 1)
                    if len(body) > 8 * 1024 * 1024:
                        raise InventoryError("MALFORMED_RESPONSE")
                    response = Response(
                        int(raw.status),
                        json.loads(body.decode("utf-8")),
                        {str(k).lower(): str(v) for k, v in raw.headers.items()},
                    )
            except urllib.error.HTTPError as exc:
                raise InventoryError(_safe_code(exc.code), status=exc.code) from None
            except InventoryError:
                raise
            except Exception as exc:
                raise InventoryError("REQUEST_FAILED") from exc
        if not 200 <= response.status < 300:
            raise InventoryError(_safe_code(response.status), status=response.status)
        return response


def _locator_ref(locator: str) -> str:
    key = os.environ.get("SUDETECT_LOCATOR_HMAC_KEY")
    if key:
        digest = hmac.new(key.encode(), locator.encode(), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"
    # Do not expose an unkeyed locator digest: tokenized paths often have low
    # enough entropy for dictionary matching.  This UUID is an opaque local
    # correlation identifier; deployments should set the HMAC key when stable
    # cross-system correlation is required.
    return f"opaque:{uuid.uuid4().hex}"


def _stable_id(prefix: str, *parts: object) -> str:
    identity = "\x1f".join(str(part) for part in parts)
    return f"{prefix}_{uuid.uuid5(_NAMESPACE, identity).hex}"


def _github_tree_file(path: Any) -> tuple[str, str | None, str] | None:
    """Return a safely encoded blob path and report-safe file type hints."""
    if not isinstance(path, str) or not path or len(path) > 4096 or path.startswith(("/", "\\")):
        return None
    parts = path.split("/")
    if any(not part or part in {".", ".."} or "\\" in part
           or any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts):
        return None
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in parts)
    basename = parts[-1]
    suffix = basename.rsplit(".", 1)[1].casefold() if "." in basename else None
    if suffix not in _SAFE_TREE_FILE_EXTENSIONS:
        suffix = None
    candidate_kind = "other"
    if suffix is not None:
        for kind, extensions in _TREE_FILE_CANDIDATE_KINDS.items():
            if suffix in extensions:
                candidate_kind = kind
                break
    return encoded_path, suffix, candidate_kind


def _public_origin(locator: str) -> str | None:
    try:
        candidate = locator if "://" in locator else "https://" + locator
        parsed = urllib.parse.urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
        default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
        return f"{parsed.scheme}://{host}{'' if port is None or default else ':' + str(port)}"
    except (UnicodeError, ValueError):
        return None


def _exact_url(locator: str) -> str | None:
    """Return a normalized requestable URL; never turn provider IDs into URLs."""
    try:
        candidate = locator if "://" in locator else "https://" + locator
        parsed = urllib.parse.urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        # Validate the port while preserving path/query/fragment for private handoff.
        _ = parsed.port
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        default = (parsed.scheme == "https" and parsed.port == 443) or (parsed.scheme == "http" and parsed.port == 80)
        netloc = host + ("" if parsed.port is None or default else f":{parsed.port}")
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "", parsed.query, parsed.fragment))
    except (UnicodeError, ValueError):
        return None


def _asset(
    provider: str,
    scope_id: str,
    kind: str,
    locator: str,
    *,
    owner_evidence: str,
    project_id: str | None = None,
    deployment_id: str | None = None,
    environment: str | None = None,
    identity: str | None = None,
    locator_store: Any | None = None,
    **safe_metadata: Any,
) -> dict[str, Any]:
    stable_locator = identity or deployment_id or project_id or locator
    exact_url = _exact_url(locator)
    if exact_url is None:
        locator_ref = _locator_ref(locator)
        handoff_state = "not_applicable"
    elif locator_store is None:
        locator_ref = _locator_ref(exact_url)
        handoff_state = "blocked"
    else:
        locator_ref = locator_store.put(scope_id, exact_url)
        handoff_state = "ready"
    result: dict[str, Any] = {
        "asset_id": _stable_id("ast", provider, scope_id, kind, stable_locator),
        "kind": kind,
        "url": _public_origin(locator),
        "locator_ref": locator_ref,
        "handoff_state": handoff_state,
        "owner_evidence": owner_evidence,
        "project_id": project_id,
        "deployment_id": deployment_id,
        "environment": environment,
    }
    result.update({k: v for k, v in safe_metadata.items() if v is not None})
    return result


def _base_report(provider: str, scope_id: str, observed_at: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "inventory_id": _stable_id("inv", provider, scope_id, observed_at),
        "provider": provider,
        "scope_id": scope_id,
        "status": "COMPLETE",
        "observed_at": observed_at,
        "assets": [],
        "edges": [],
        "coverage": {},
        "errors": [],
    }


def _finish(report: dict[str, Any], *, attempted: bool, successes: int) -> dict[str, Any]:
    report["errors"] = sorted(set(code for code in report["errors"] if code in _SAFE_ERROR_CODES))
    if report["errors"]:
        report["status"] = "PARTIAL" if successes else "FAILED"
    elif not attempted:
        report["status"] = "FAILED"
        report["errors"] = ["REQUEST_FAILED"]
    report["assets"].sort(key=lambda item: item["asset_id"])
    report["edges"].sort(key=lambda item: item["edge_id"])
    return report


def _edge(source: str, target: str, relationship: str, observed_at: str, evidence: str) -> dict[str, Any]:
    return {
        "edge_id": _stable_id("edg", source, target, relationship),
        "source_asset_id": source,
        "target_asset_id": target,
        "relationship": relationship,
        "observed_at": observed_at,
        "owner_evidence": evidence,
    }


def _vercel_next(payload: Mapping[str, Any]) -> str | None:
    """Return a provider cursor only from a structurally valid page marker."""
    pagination = payload.get("pagination")
    if not isinstance(pagination, Mapping):
        raise InventoryError("MALFORMED_RESPONSE")
    count = pagination.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0 or "next" not in pagination:
        raise InventoryError("MALFORMED_RESPONSE")
    value = pagination["next"]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)) or str(value) == "":
        raise InventoryError("MALFORMED_RESPONSE")
    return str(value)


def _strict_mapping_items(payload: Mapping[str, Any], key: str) -> tuple[list[Mapping[str, Any]], bool]:
    """Keep valid rows while marking any missing/malformed collection incomplete."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        raise InventoryError("MALFORMED_RESPONSE")
    valid = [item for item in raw if isinstance(item, Mapping)]
    return valid, len(valid) != len(raw)


def _project_page(payload: Any, *, limit: int) -> tuple[list[Mapping[str, Any]], str | None, bool, bool]:
    """Accept both documented v10 project response variants.

    The legacy array variant has no continuation marker.  A full page therefore
    cannot establish the end of inventory and is reported as incomplete.
    """
    if isinstance(payload, list):
        items = [item for item in payload if isinstance(item, Mapping)]
        malformed = len(items) != len(payload)
        # The SDK still accepts a legacy bare-array response, but it carries no
        # cursor/end marker.  Preserve its rows without claiming completeness.
        return items, None, malformed, True
    if not isinstance(payload, Mapping):
        raise InventoryError("MALFORMED_RESPONSE")
    items, malformed = _strict_mapping_items(payload, "projects")
    try:
        cursor = _vercel_next(payload)
    except InventoryError:
        cursor = None
        malformed = True
    return items, cursor, malformed, False


def _valid_project(item: Mapping[str, Any]) -> bool:
    return _provider_id(item.get("id")) is not None


def _valid_deployment(item: Mapping[str, Any]) -> bool:
    deployment_id = _provider_id(item.get("uid") or item.get("id"))
    locator = item.get("url")
    return deployment_id is not None and isinstance(locator, str) and _public_origin(locator) is not None


def _valid_alias(item: Mapping[str, Any]) -> bool:
    created = item.get("created")
    return (
        _provider_id(item.get("uid")) is not None
        and isinstance(item.get("alias"), str)
        and bool(item["alias"])
        and not isinstance(created, (Mapping, list, bool))
        and created not in (None, "")
    )


def _valid_domain(item: Mapping[str, Any]) -> bool:
    return isinstance(item.get("name"), str) and bool(item["name"]) and isinstance(item.get("verified"), bool)


def collect_vercel(scope_id: str, token: str, *, fetch: Fetch | None = None, max_pages: int = 1000,
                   locator_store: Any | None = None) -> dict[str, Any]:
    scope_id = _validate_scope(scope_id)
    observed_at = _utc_now()
    report = _base_report("vercel", scope_id, observed_at)
    broker = Broker(token, "vercel", fetch, scope_id=scope_id)
    team = urllib.parse.quote(scope_id, safe="")
    projects: list[Mapping[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    pages = 0
    project_malformed = False
    attempted = True
    try:
        while True:
            query = {"limit": "100", "teamId": scope_id}
            if cursor is not None:
                query["from"] = cursor
            url = "https://api.vercel.com/v10/projects?" + urllib.parse.urlencode(query)
            payload = broker.get(url).payload
            page_projects, cursor, malformed, pagination_unconfirmed = _project_page(payload, limit=100)
            valid_projects = [item for item in page_projects if _valid_project(item)]
            projects.extend(valid_projects)
            if malformed or len(valid_projects) != len(page_projects):
                project_malformed = True
                report["errors"].append("MALFORMED_RESPONSE")
            pages += 1
            if pagination_unconfirmed:
                report["errors"].append("PAGINATION_UNCONFIRMED")
                break
            if cursor is None:
                break
            if cursor in seen:
                raise InventoryError("CURSOR_LOOP")
            seen.add(cursor)
            if pages >= max_pages:
                raise InventoryError("PAGE_LIMIT_EXCEEDED")
    except InventoryError as exc:
        report["errors"].append(exc.code)
    report["coverage"]["projects"] = {
        "state": "COMPLETE" if not report["errors"] and not project_malformed else ("PARTIAL" if projects or pages else "FAILED"),
        "pages": pages,
        "items": len(projects),
    }

    successful_channels = 1 if projects or (pages and not report["errors"]) else 0
    for project in projects:
        project_id = _provider_id(project.get("id")) or ""
        if not project_id:
            report["errors"].append("MALFORMED_RESPONSE")
            continue
        protection_source: Mapping[str, Any] = project
        protection_error: str | None = None
        project_key = urllib.parse.quote(project_id, safe="")
        try:
            detail = broker.get(f"https://api.vercel.com/v9/projects/{project_key}?teamId={team}").payload
            if not isinstance(detail, Mapping):
                raise InventoryError("MALFORMED_RESPONSE")
            protection_source = detail
        except InventoryError as exc:
            protection_error = exc.code
            report["errors"].append(exc.code)
        report["coverage"][f"protection:{project_id}"] = {
            "state": "COMPLETE" if protection_error is None else ("PARTIAL" if _protection_summary(project) else "FAILED"),
        }
        project_asset = _asset(
            "vercel", scope_id, "project", f"vercel-project://{project_id}",
            owner_evidence="vercel_authenticated_team_inventory",
            project_id=project_id, identity=project_id,
            locator_store=locator_store,
            protection=_protection_summary(protection_source),
        )
        report["assets"].append(project_asset)
        dep_cursor: str | None = None
        dep_seen: set[str] = set()
        dep_pages = 0
        deployments: list[Mapping[str, Any]] = []
        dep_error: str | None = None
        dep_malformed = False
        try:
            while True:
                query = {"projectId": project_id, "limit": "100", "teamId": scope_id}
                if dep_cursor is not None:
                    query["until"] = dep_cursor
                payload = broker.get("https://api.vercel.com/v6/deployments?" + urllib.parse.urlencode(query)).payload
                if not isinstance(payload, Mapping):
                    raise InventoryError("MALFORMED_RESPONSE")
                page_deployments, malformed = _strict_mapping_items(payload, "deployments")
                valid_deployments = [item for item in page_deployments if _valid_deployment(item)]
                deployments.extend(valid_deployments)
                if malformed or len(valid_deployments) != len(page_deployments):
                    dep_malformed = True
                    report["errors"].append("MALFORMED_RESPONSE")
                dep_pages += 1
                dep_cursor = _vercel_next(payload)
                if dep_cursor is None:
                    break
                if dep_cursor in dep_seen:
                    raise InventoryError("CURSOR_LOOP")
                dep_seen.add(dep_cursor)
                if dep_pages >= max_pages:
                    raise InventoryError("PAGE_LIMIT_EXCEEDED")
        except InventoryError as exc:
            dep_error = exc.code
            report["errors"].append(exc.code)
        report["coverage"][f"deployments:{project_id}"] = {
            "state": "COMPLETE" if dep_error is None and not dep_malformed else ("PARTIAL" if deployments or dep_pages else "FAILED"),
            "pages": dep_pages,
            "items": len(deployments),
        }
        if deployments or dep_error is None:
            successful_channels += 1

        for deployment in deployments:
            deployment_id = _provider_id(deployment.get("uid") or deployment.get("id")) or ""
            host = str(deployment.get("url") or "")
            if not deployment_id or not host:
                report["errors"].append("MALFORMED_RESPONSE")
                continue
            environment = str(deployment.get("target") or "preview")
            deployment_asset = _asset(
                "vercel", scope_id, "deployment", host,
                owner_evidence="vercel_authenticated_deployment_inventory",
                project_id=project_id, deployment_id=deployment_id,
                environment=environment, identity=deployment_id,
                locator_store=locator_store,
            )
            report["assets"].append(deployment_asset)
            report["edges"].append(_edge(project_asset["asset_id"], deployment_asset["asset_id"], "deployed_as", observed_at, "vercel_api"))
            aliases = deployment.get("alias") if isinstance(deployment.get("alias"), list) else []
            alias_error: str | None = None
            alias_malformed = (
                "alias" in deployment
                and (
                    not isinstance(deployment.get("alias"), list)
                    or any(not isinstance(value, str) or not value for value in aliases)
                )
            )
            if alias_malformed:
                report["errors"].append("MALFORMED_RESPONSE")
            alias_pages = 0
            try:
                query = {"teamId": scope_id}
                alias_payload = broker.get(
                    f"https://api.vercel.com/v2/deployments/{urllib.parse.quote(deployment_id, safe='')}/aliases?"
                    + urllib.parse.urlencode(query)
                ).payload
                if not isinstance(alias_payload, Mapping):
                    raise InventoryError("MALFORMED_RESPONSE")
                alias_items, malformed = _strict_mapping_items(alias_payload, "aliases")
                page_aliases = [item["alias"] for item in alias_items if _valid_alias(item)]
                malformed = malformed or len(page_aliases) != len(alias_items)
                aliases = list(aliases) + page_aliases
                if malformed:
                    alias_malformed = True
                    report["errors"].append("MALFORMED_RESPONSE")
                alias_pages = 1
            except InventoryError as exc:
                alias_error = exc.code
                report["errors"].append(exc.code)
            valid_aliases = sorted({str(a) for a in aliases if isinstance(a, str) and a})
            report["coverage"][f"aliases:{deployment_id}"] = {
                "state": "COMPLETE" if alias_error is None and not alias_malformed else ("PARTIAL" if valid_aliases or alias_pages else "FAILED"),
                "pages": alias_pages, "items": len(valid_aliases),
            }
            for alias in valid_aliases:
                alias_asset = _asset(
                    "vercel", scope_id, "deployment_alias", alias,
                    owner_evidence="vercel_authenticated_alias_inventory",
                    project_id=project_id, deployment_id=deployment_id,
                    environment=environment, identity=f"{deployment_id}:{alias.lower()}",
                    locator_store=locator_store,
                )
                report["assets"].append(alias_asset)
                report["edges"].append(_edge(deployment_asset["asset_id"], alias_asset["asset_id"], "has_alias", observed_at, "vercel_api"))

        domains_error: str | None = None
        domains: list[Mapping[str, Any]] = []
        domain_pages = 0
        domain_malformed = False
        try:
            domain_cursor: str | None = None
            domain_seen: set[str] = set()
            while True:
                query = {"teamId": scope_id, "limit": "100"}
                if domain_cursor is not None:
                    query["until"] = domain_cursor
                payload = broker.get(
                    f"https://api.vercel.com/v9/projects/{project_key}/domains?" + urllib.parse.urlencode(query)
                ).payload
                if not isinstance(payload, Mapping):
                    raise InventoryError("MALFORMED_RESPONSE")
                page_domains, malformed = _strict_mapping_items(payload, "domains")
                valid_domains = [item for item in page_domains if _valid_domain(item)]
                domains.extend(valid_domains)
                if malformed or len(valid_domains) != len(page_domains):
                    domain_malformed = True
                    report["errors"].append("MALFORMED_RESPONSE")
                domain_pages += 1
                domain_cursor = _vercel_next(payload)
                if domain_cursor is None:
                    break
                if domain_cursor in domain_seen:
                    raise InventoryError("CURSOR_LOOP")
                domain_seen.add(domain_cursor)
                if domain_pages >= max_pages:
                    raise InventoryError("PAGE_LIMIT_EXCEEDED")
        except InventoryError as exc:
            domains_error = exc.code
            report["errors"].append(exc.code)
        report["coverage"][f"domains:{project_id}"] = {
            "state": "COMPLETE" if domains_error is None and not domain_malformed else ("PARTIAL" if domains or domain_pages else "FAILED"),
            "pages": domain_pages, "items": len(domains)
        }
        for domain in domains:
            name = domain.get("name")
            if not _valid_domain(domain):
                continue
            domain_asset = _asset(
                "vercel", scope_id, "project_domain", name,
                owner_evidence="vercel_authenticated_project_domain_inventory",
                project_id=project_id, identity=f"{project_id}:{name.lower()}",
                locator_store=locator_store,
                verified=bool(domain.get("verified")),
            )
            report["assets"].append(domain_asset)
            report["edges"].append(_edge(project_asset["asset_id"], domain_asset["asset_id"], "has_domain", observed_at, "vercel_api"))
    return _finish(report, attempted=attempted, successes=successful_channels)


def _protection_summary(project: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("passwordProtection", "ssoProtection", "deploymentProtection", "trustedIps")
    return {key: bool(project.get(key)) for key in keys if key in project}


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"', part)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def collect_github(
    scope_id: str,
    token: str,
    *,
    fetch: Fetch | None = None,
    include_trees: bool = False,
    max_pages: int = 1000,
    locator_store: Any | None = None,
) -> dict[str, Any]:
    scope_id = _validate_scope(scope_id)
    observed_at = _utc_now()
    report = _base_report("github", scope_id, observed_at)
    broker = Broker(token, "github", fetch, scope_id=scope_id)
    owner = urllib.parse.quote(scope_id, safe="")
    # `/user/repos?affiliation=owner` is the only account listing that includes
    # private repositories.  Select it only when the authenticated login exactly
    # matches the approved scope; organization scopes use the organization API.
    account_scope = False
    try:
        identity = broker.get("https://api.github.com/user").payload
        account_scope = isinstance(identity, Mapping) and str(identity.get("login", "")).casefold() == scope_id.casefold()
    except InventoryError as exc:
        report["errors"].append(exc.code)
    if account_scope:
        url: str | None = "https://api.github.com/user/repos?affiliation=owner&visibility=all&per_page=100&page=1"
        page_base = "https://api.github.com/user/repos?affiliation=owner&visibility=all&per_page=100&page="
        owner_evidence = "github_authenticated_account_inventory"
    else:
        url = f"https://api.github.com/orgs/{owner}/repos?type=all&per_page=100&page=1"
        page_base = f"https://api.github.com/orgs/{owner}/repos?type=all&per_page=100&page="
        owner_evidence = "github_authenticated_organization_inventory"
    seen: set[str] = set()
    repos: list[Mapping[str, Any]] = []
    pages = 0
    try:
        while url:
            if url in seen:
                raise InventoryError("CURSOR_LOOP")
            page = urllib.parse.urlsplit(url)
            expected_path = "/user/repos" if account_scope else f"/orgs/{owner}/repos"
            if page.scheme != "https" or page.hostname != "api.github.com" or page.port not in (None,443) or page.path != expected_path:
                raise InventoryError("MALFORMED_RESPONSE")
            seen.add(url)
            response = broker.get(url)
            if not isinstance(response.payload, list):
                raise InventoryError("MALFORMED_RESPONSE")
            repos.extend(x for x in response.payload if isinstance(x, Mapping))
            pages += 1
            url = _next_link(response.headers.get("link"))
            if url is None and len(response.payload) == 100:
                url = page_base + str(pages + 1)
            if pages >= max_pages and url:
                raise InventoryError("PAGE_LIMIT_EXCEEDED")
    except InventoryError as exc:
        report["errors"].append(exc.code)
    report["coverage"]["repositories"] = {
        "state": "COMPLETE" if not report["errors"] else ("PARTIAL" if repos else "FAILED"),
        "pages": pages,
        "items": len(repos),
        "includes_private": True,
        "scope_kind": "account" if account_scope else "organization",
        "coverage_limitations": [
            "token_visibility_only",
            "permission_denied_indistinguishable_from_unlisted_resources",
            "zero_items_is_a_bounded_observation",
        ],
    }
    successes = 1 if repos or (pages and not report["errors"]) else 0
    emitted_tree_files = 0
    for repo in repos:
        repo_id = repo.get("id")
        full_name = repo.get("full_name")
        if repo_id is None or not isinstance(full_name, str) or "/" not in full_name:
            report["errors"].append("MALFORMED_RESPONSE")
            continue
        if full_name.split("/", 1)[0].casefold() != scope_id.casefold():
            report["errors"].append("PERMISSION_DENIED")
            continue
        visibility = str(repo.get("visibility") or ("private" if repo.get("private") else "public"))
        asset = _asset(
            "github", scope_id, "repository", f"https://github.com/{full_name}",
            owner_evidence=owner_evidence,
            identity=str(repo_id),
            locator_store=locator_store,
            visibility=visibility,
            archived=bool(repo.get("archived")),
        )
        # Repository existence and policy metadata only: do not emit its name or raw API response.
        report["assets"].append(asset)
        if not include_trees:
            continue
        branch = repo.get("default_branch")
        tree_state = "FAILED"
        item_count = 0
        emitted_for_repository = 0
        file_assets_truncated = False
        if isinstance(branch, str) and branch:
            api_name = "/".join(urllib.parse.quote(part, safe="") for part in full_name.split("/", 1))
            try:
                response = broker.get(
                    f"https://api.github.com/repos/{api_name}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1"
                ).payload
                if not isinstance(response, Mapping) or not isinstance(response.get("tree"), list):
                    raise InventoryError("MALFORMED_RESPONSE")
                tree_rows = response["tree"]
                item_count = len(tree_rows)
                malformed_rows = any(not isinstance(row, Mapping) for row in tree_rows)
                blob_rows = [row for row in tree_rows
                             if isinstance(row, Mapping) and row.get("type") == "blob"]
                seen_file_paths: set[str] = set()
                for row in blob_rows:
                    parsed_file = _github_tree_file(row.get("path"))
                    blob_sha = row.get("sha")
                    if (parsed_file is None or not isinstance(blob_sha, str)
                            or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", blob_sha) is None):
                        malformed_rows = True
                        continue
                    if (emitted_for_repository >= MAX_GITHUB_TREE_FILES_PER_REPOSITORY
                            or emitted_tree_files >= MAX_GITHUB_TREE_FILES_PER_REPORT):
                        file_assets_truncated = True
                        continue
                    encoded_path, extension, candidate_kind = parsed_file
                    if encoded_path in seen_file_paths:
                        malformed_rows = True
                        continue
                    seen_file_paths.add(encoded_path)
                    size = row.get("size")
                    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
                        malformed_rows = True
                        size = None
                    normalized_sha = blob_sha.lower()
                    blob_url = (
                        f"https://github.com/{api_name}/blob/"
                        f"{urllib.parse.quote(branch, safe='')}/{encoded_path}"
                    )
                    file_asset = _asset(
                        "github", scope_id, "repository_file", blob_url,
                        owner_evidence=owner_evidence,
                        identity=f"{repo_id}:{encoded_path}",
                        locator_store=locator_store,
                        repository_asset_id=asset["asset_id"],
                        visibility=visibility,
                        candidate_kind=candidate_kind,
                        extension=extension,
                        byte_size=size,
                        git_object_sha=normalized_sha,
                        locator_mutability="branch_ref_mutable",
                        public_exposure="not_measured",
                    )
                    report["assets"].append(file_asset)
                    report["edges"].append(_edge(
                        asset["asset_id"], file_asset["asset_id"], "contains", observed_at,
                        "github_authenticated_tree_inventory",
                    ))
                    emitted_for_repository += 1
                    emitted_tree_files += 1
                if malformed_rows:
                    report["errors"].append("MALFORMED_RESPONSE")
                if response.get("truncated") is True or file_assets_truncated:
                    report["errors"].append("TREE_TRUNCATED")
                    tree_state = "PARTIAL"
                elif malformed_rows:
                    tree_state = "PARTIAL"
                else:
                    tree_state = "COMPLETE"
                    successes += 1
            except InventoryError as exc:
                report["errors"].append(exc.code)
        else:
            report["errors"].append("MALFORMED_RESPONSE")
        report["coverage"][f"tree:{asset['asset_id']}"] = {
            "state": tree_state,
            "items": item_count,
            "content_retained": False,
            "file_assets_emitted": emitted_for_repository,
            "file_asset_limit_per_repository": MAX_GITHUB_TREE_FILES_PER_REPOSITORY,
            "file_asset_limit_per_report": MAX_GITHUB_TREE_FILES_PER_REPORT,
            "file_assets_truncated": file_assets_truncated,
        }
    return _finish(report, attempted=True, successes=successes)


def import_inventory(scope_id: str, source: str | Path | Mapping[str, Any], *,
                     locator_store: Any | None = None) -> dict[str, Any]:
    scope_id = _validate_scope(scope_id)
    observed_at = _utc_now()
    report = _base_report("import", scope_id, observed_at)
    try:
        if isinstance(source, Mapping):
            payload = dict(source)
        else:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping) or not isinstance(payload.get("assets"), list):
            raise ValueError
        source_name = _provenance_id(payload.get("source"))
        retrieved_at = _utc_timestamp(payload.get("retrieved_at"))
        owner_scope = payload.get("owner_scope")
        completeness = payload.get("completeness")
        source_provenance_complete = (
            source_name is not None
            and retrieved_at is not None
            and owner_scope == scope_id
            and completeness in {"COMPLETE", "PARTIAL", "UNKNOWN"}
        )
        if not source_provenance_complete:
            report["errors"].append("IMPORT_PROVENANCE_MISSING")
        imported = 0
        invalid = 0
        imported_incomplete = False
        for item in payload["assets"]:
            if not isinstance(item, Mapping):
                invalid += 1
                continue
            locator = item.get("url")
            kind = item.get("kind")
            evidence = item.get("owner_evidence")
            item_source = _provenance_id(item.get("source") or source_name)
            item_retrieved_at = _utc_timestamp(item.get("retrieved_at") or retrieved_at)
            item_owner_scope = item.get("owner_scope", owner_scope)
            item_completeness = item.get("completeness", completeness)
            source_record_id = _provenance_id(item.get("source_record_id") or item.get("external_id"))
            allowed_kinds = {"custom_share", "deployment", "deployment_alias", "project_domain", "repository", "asset"}
            if (
                not isinstance(locator, str)
                or kind not in allowed_kinds
                or _evidence_ref(evidence) is None
                or item.get("scope_decision") != "approved"
                or item_source is None
                or item_retrieved_at is None
                or item_owner_scope != scope_id
                or item_completeness not in {"COMPLETE", "PARTIAL", "UNKNOWN"}
                or source_record_id is None
            ):
                invalid += 1
                continue
            report["assets"].append(_asset(
                "import", scope_id, kind, locator, owner_evidence=evidence,
                project_id=_provider_id(item.get("project_id")),
                deployment_id=_provider_id(item.get("deployment_id")),
                environment=item.get("environment") if item.get("environment") in {"production","preview","development","unknown"} else None,
                identity=source_record_id,
                locator_store=locator_store,
                source=item_source,
                retrieved_at=item_retrieved_at,
                owner_scope=item_owner_scope,
                completeness=item_completeness,
                source_record_id=source_record_id,
                scope_decision="approved",
            ))
            imported_incomplete = imported_incomplete or item_completeness in {"PARTIAL", "UNKNOWN"}
            imported += 1
        if invalid:
            report["errors"].append("IMPORT_INVALID")
        if completeness in {"PARTIAL", "UNKNOWN"} or imported_incomplete:
            report["errors"].append("IMPORT_SOURCE_INCOMPLETE")
        state = "COMPLETE"
        if report["errors"]:
            state = "PARTIAL" if imported else "FAILED"
        report["coverage"]["normalized_import"] = {
            "state": state,
            "items": imported,
            "invalid_items": invalid,
            "source": source_name,
            "retrieved_at": retrieved_at,
            "owner_scope": owner_scope if owner_scope == scope_id else None,
            "source_completeness": completeness if source_provenance_complete else "UNKNOWN",
        }
        return _finish(report, attempted=True, successes=1 if imported else 0)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        report["coverage"]["normalized_import"] = {"state": "FAILED", "items": 0}
        report["errors"].append("IMPORT_INVALID")
        return _finish(report, attempted=True, successes=0)


def collect(
    provider: str,
    scope_id: str,
    *,
    token_env: str | None = None,
    input_path: str | Path | None = None,
    include_trees: bool = False,
    fetch: Fetch | None = None,
    locator_store: Any | None = None,
) -> dict[str, Any]:
    if provider == "import":
        if input_path is None:
            return _failed(provider, scope_id, "IMPORT_INVALID")
        return import_inventory(scope_id, input_path, locator_store=locator_store)
    if provider not in {"vercel", "github"}:
        return _failed(provider, scope_id, "REQUEST_FAILED")
    try:
        _validate_scope(scope_id)
    except InventoryError as exc:
        return _failed(provider, str(scope_id), exc.code)
    token = os.environ.get(token_env or "") if token_env else None
    if not token:
        return _failed(provider, scope_id, "TOKEN_MISSING")
    if provider == "vercel":
        return collect_vercel(scope_id, token, fetch=fetch, locator_store=locator_store)
    return collect_github(scope_id, token, fetch=fetch, include_trees=include_trees, locator_store=locator_store)


def _failed(provider: str, scope_id: str, code: str) -> dict[str, Any]:
    report = _base_report(provider, scope_id, _utc_now())
    report["status"] = "FAILED"
    report["errors"] = [code if code in _SAFE_ERROR_CODES else "REQUEST_FAILED"]
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a sanitized owner inventory.")
    parser.add_argument("--provider", required=True, choices=("vercel", "github", "import"))
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--token-env", help="Environment variable containing the provider token")
    parser.add_argument("--input", dest="input_path", help="Normalized JSON export for --provider import")
    parser.add_argument("--include-trees", action="store_true", help="Collect Git tree completeness metadata")
    parser.add_argument("--locator-store", help="Owner-controlled local exact-URL mapping database")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.locator_store:
            from .locators import LocatorStore
            with LocatorStore(args.locator_store) as store:
                report = collect(args.provider, args.scope_id, token_env=args.token_env,
                    input_path=args.input_path, include_trees=args.include_trees, locator_store=store)
        else:
            report = collect(args.provider, args.scope_id, token_env=args.token_env,
                input_path=args.input_path, include_trees=args.include_trees)
    except (OSError, ValueError):
        report = _failed(args.provider, args.scope_id, "REQUEST_FAILED")
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["status"] != "FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
