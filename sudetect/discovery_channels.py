"""Bounded public JSON discovery adapters.

Exact candidate URLs are written only to a :class:`LocatorStore`.  Returned
reports contain opaque references and bounded provenance, and never authorize
subsequent target measurement.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import re
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .channel_health import extract_health_provenance, validate_health
from .policy import Budget, PolicyError, Scope, _normalize_url
from .transport import FetchResult, fetch as transport_fetch

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DNS = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$")
_MAX_CONFIG_BYTES = 1_048_576
_NS = uuid.UUID("672d3553-e2c5-4b1c-b116-33e15f76b1f4")


def _stamp(now: datetime | None) -> str:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid time")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _exclusive_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("unsafe output")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _bounded_int(value: object, low: int, high: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _domain(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid domain")
    try:
        result = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid domain") from None
    if not _DNS.fullmatch(result) or result.count(".") < 1:
        raise ValueError("invalid domain")
    return result


def _pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 256:
        raise ValueError("invalid JSON pointer")
    current = value
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        elif isinstance(current, Mapping) and token in current:
            current = current[token]
        else:
            return None
    return current


def _validate_https_endpoint(url: object) -> str:
    if not isinstance(url, str) or len(url) > 4096:
        raise ValueError("invalid endpoint")
    normalized, _ = _normalize_url(url)
    return normalized


def load_channel_config(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    """Load and strictly validate a channel configuration."""
    if isinstance(source, Mapping):
        raw = json.loads(json.dumps(source))
    else:
        with Path(source).open("rb") as handle:
            data = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(data) > _MAX_CONFIG_BYTES:
            raise ValueError("channel config too large")
        raw = json.loads(data)
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("invalid channel config")
    allowed = {"version", "scope_id", "provider", "channel_id", "source_id", "expected_control_ids", "query", "endpoint", "limits"}
    if set(raw) - allowed:
        raise ValueError("unknown channel config field")
    provider = raw.get("provider")
    if provider not in {"certspotter", "generic_json_export"}:
        raise ValueError("unsupported provider")
    scope_id = _identifier(raw.get("scope_id"), "scope id")
    channel_id = _identifier(raw.get("channel_id"), "channel id")
    source_id = _identifier(raw.get("source_id"), "source id")
    control_ids = raw.get("expected_control_ids")
    if (not isinstance(control_ids, list) or not control_ids or len(control_ids) != len(set(control_ids)) or
            any(not isinstance(x, str) or not _ID.fullmatch(x) for x in control_ids)):
        raise ValueError("invalid expected control ids")
    query = raw.get("query")
    if not isinstance(query, dict) or set(query) != {"work_id", "value"}:
        raise ValueError("invalid query")
    work_id = _identifier(query.get("work_id"), "work id")
    if not isinstance(query.get("value"), str) or not 1 <= len(query["value"]) <= 512 or any(ord(c) < 32 for c in query["value"]):
        raise ValueError("invalid query value")
    limits = raw.get("limits", {})
    if not isinstance(limits, dict) or set(limits) - {"max_requests", "max_pages", "max_body_bytes", "max_candidates"}:
        raise ValueError("invalid limits")
    clean_limits = {
        "max_requests": _bounded_int(limits.get("max_requests", 6), 1, 30, "request limit"),
        "max_pages": _bounded_int(limits.get("max_pages", 6), 1, 30, "page limit"),
        "max_body_bytes": _bounded_int(limits.get("max_body_bytes", 262144), 1, 4_194_304, "body limit"),
        "max_candidates": _bounded_int(limits.get("max_candidates", 1000), 1, 10000, "candidate limit"),
    }
    endpoint = raw.get("endpoint")
    if not isinstance(endpoint, dict):
        raise ValueError("invalid endpoint")
    if provider == "certspotter":
        if channel_id != "certificate_transparency" or set(endpoint) - {"url", "include_subdomains"}:
            raise ValueError("invalid CertSpotter configuration")
        endpoint_url = _validate_https_endpoint(endpoint.get("url", "https://api.certspotter.com/v1/issuances"))
        p = urlsplit(endpoint_url)
        if p.hostname != "api.certspotter.com" or p.path != "/v1/issuances" or p.query:
            raise ValueError("invalid CertSpotter endpoint family")
        query_value = _domain(query["value"])
        clean_endpoint = {"url": endpoint_url, "include_subdomains": endpoint.get("include_subdomains", True)}
        if not isinstance(clean_endpoint["include_subdomains"], bool):
            raise ValueError("invalid include_subdomains")
    else:
        keys = {"url", "query_param", "page_param", "start_page", "results_pointer", "url_pointer", "record_id_pointer", "has_more_pointer"}
        if set(endpoint) - keys or not {"url", "query_param", "results_pointer", "url_pointer"} <= set(endpoint):
            raise ValueError("invalid generic endpoint")
        endpoint_url = _validate_https_endpoint(endpoint["url"])
        if not all(isinstance(endpoint.get(k), str) and 1 <= len(endpoint[k]) <= 128 for k in ("query_param",)):
            raise ValueError("invalid query binding")
        for k in ("results_pointer", "url_pointer", "record_id_pointer", "has_more_pointer"):
            if k in endpoint and (not isinstance(endpoint[k], str) or len(endpoint[k]) > 256):
                raise ValueError("invalid extraction pointer")
        if "page_param" in endpoint and (not isinstance(endpoint["page_param"], str) or not endpoint["page_param"]):
            raise ValueError("invalid page binding")
        start = endpoint.get("start_page", 1)
        _bounded_int(start, 0, 1_000_000, "start page")
        clean_endpoint = dict(endpoint)
        clean_endpoint["url"] = endpoint_url
        query_value = query["value"]
    return {"version": 1, "scope_id": scope_id, "provider": provider, "channel_id": channel_id,
            "source_id": source_id, "expected_control_ids": sorted(control_ids), "query": {"work_id": work_id, "value": query_value},
            "endpoint": clean_endpoint, "limits": clean_limits}


def _with_params(base: str, additions: list[tuple[str, str]]) -> str:
    p = urlsplit(base)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    names = {k for k, _ in additions}
    if any(k in names for k, _ in pairs):
        raise ValueError("endpoint predefines controlled parameter")
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs + additions, doseq=True), ""))


def _call_fetcher(fetcher: Callable[..., FetchResult], url: str, scope: Scope, budget: Budget, maximum: int) -> FetchResult:
    try:
        return fetcher(url, scope, budget=budget, max_bytes=maximum)
    except TypeError:
        # Compact injected fixture adapter. Production always uses transport.fetch.
        return fetcher(url, scope)


def _decode_result(result: FetchResult, maximum: int) -> tuple[Any | None, str | None]:
    observation = result.observation if isinstance(result.observation, Mapping) else {}
    if observation.get("http_status") != 200:
        return None, "HTTP_ERROR"
    if observation.get("capture_complete") is not True or len(result.body) > maximum:
        return None, "BODY_TRUNCATED"
    encoding = result.headers.get("content-encoding", "identity").lower()
    if encoding not in {"", "identity"}:
        return None, "UNSUPPORTED_ENCODING"
    try:
        return json.loads(result.body), None
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None, "INVALID_JSON"


def _candidate(scope_id: str, source_id: str, work_id: str, record_ref: str, url: str, store: Any) -> dict[str, Any] | None:
    try:
        normalized, _ = _normalize_url(url)
    except (PolicyError, ValueError):
        return None
    ref = store.put(scope_id, normalized)
    candidate_id = "cand_" + uuid.uuid5(_NS, "\x1f".join((source_id, record_ref, normalized))).hex
    return {"candidate_id": candidate_id, "locator_ref": ref, "handoff_state": "ready",
            "source_id": source_id, "query_work_id": work_id,
            "record_ref": "sha256:" + hashlib.sha256(record_ref.encode()).hexdigest()}

def _query_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def run_discovery(config: str | Path | Mapping[str, Any], *, scope: Scope,
                  channel_health: Mapping[str, Any], locator_store: Any,
                  fetcher: Callable[..., FetchResult] = transport_fetch,
                  now: datetime | None = None) -> dict[str, Any]:
    """Execute one declared, query-bound stream under endpoint scope and limits."""
    cfg = load_channel_config(config)
    if validate_health(channel_health, [cfg["channel_id"]], now=now):
        raise ValueError("channel health invalid")
    health = extract_health_provenance(channel_health, [cfg["channel_id"]])
    if len(health) != 1 or health[0].get("control_id") not in cfg["expected_control_ids"]:
        raise ValueError("channel health provenance unavailable")
    scope.authorize(cfg["endpoint"]["url"])
    limits, provider = cfg["limits"], cfg["provider"]
    budget = Budget(min(limits["max_requests"], scope.max_requests))
    pages = 0
    candidates: dict[str, dict[str, Any]] = {}
    rejected_records = 0
    end_condition: str | None = None
    error_code: str | None = None
    cursor: str | None = None
    page = int(cfg["endpoint"].get("start_page", 1))
    while pages < limits["max_pages"] and budget.used < budget.maximum:
        if provider == "certspotter":
            additions = [("domain", cfg["query"]["value"]), ("include_subdomains", str(cfg["endpoint"]["include_subdomains"]).lower()), ("expand", "dns_names")]
            if cursor is not None:
                additions.append(("after", cursor))
        else:
            additions = [(cfg["endpoint"]["query_param"], cfg["query"]["value"])]
            if cfg["endpoint"].get("page_param"):
                additions.append((cfg["endpoint"]["page_param"], str(page)))
        try:
            url = _with_params(cfg["endpoint"]["url"], additions)
            scope.authorize(url)
            if validate_health(channel_health, [cfg["channel_id"]], now=now):
                error_code = "CHANNEL_HEALTH_INVALID"
                break
            before_requests = budget.used
            result = _call_fetcher(fetcher, url, scope, budget, limits["max_body_bytes"])
        except (PolicyError, OSError, ValueError):
            error_code = "REQUEST_FAILED"
            break
        # A compact injected fixture may omit Budget consumption; charge exactly
        # one request only when this call made no change. Redirecting fixtures
        # can consume more and their actual delta is preserved.
        if fetcher is not transport_fetch and budget.used == before_requests:
            try:
                budget.consume()
            except PolicyError:
                error_code = "REQUEST_LIMIT_EXCEEDED"
                break
        pages += 1
        payload, error = _decode_result(result, limits["max_body_bytes"])
        if error:
            error_code = error
            break
        rows = payload if provider == "certspotter" else _pointer(payload, cfg["endpoint"]["results_pointer"])
        if not isinstance(rows, list):
            error_code = "RESPONSE_SHAPE_MISMATCH"
            break
        if not rows:
            if provider == "certspotter":
                end_condition = "provider_empty"
            else:
                marker_pointer = cfg["endpoint"].get("has_more_pointer")
                marker = _pointer(payload, marker_pointer) if marker_pointer else None
                if marker is False:
                    end_condition = "page_exhausted"
                elif marker is True and cfg["endpoint"].get("page_param"):
                    page += 1
                    continue
                else:
                    error_code = "PAGINATION_UNDECLARED" if not marker_pointer else "PAGINATION_MISMATCH"
            break
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                rejected_records += 1
                continue
            if provider == "certspotter":
                record = row.get("id")
                names = row.get("dns_names")
                if isinstance(record, int) and not isinstance(record, bool) and record >= 0:
                    record = str(record)
                if not isinstance(record, str) or not record.isdigit() or len(record)>64 or not isinstance(names, list):
                    error_code = "RESPONSE_SHAPE_MISMATCH"
                    break
                if cursor is not None and int(record) <= int(cursor):
                    error_code = "CURSOR_NOT_ADVANCING"
                    break
                cursor = record
                urls = []
                for name in names:
                    if not isinstance(name, str) or name.startswith("*."):
                        continue
                    try:
                        host = _domain(name)
                    except ValueError:
                        continue
                    root = cfg["query"]["value"]
                    if host == root or (cfg["endpoint"]["include_subdomains"] and host.endswith("." + root)):
                        urls.append("https://" + host + "/")
                record_ref = record
            else:
                url_value = _pointer(row, cfg["endpoint"]["url_pointer"])
                urls = [url_value] if isinstance(url_value, str) else []
                raw_ref = _pointer(row, cfg["endpoint"].get("record_id_pointer", ""))
                record_ref = str(raw_ref) if isinstance(raw_ref, (str, int)) and not isinstance(raw_ref, bool) else f"page:{page}:row:{index}"
            for exact in urls:
                item = _candidate(cfg["scope_id"], cfg["source_id"], cfg["query"]["work_id"], record_ref, exact, locator_store)
                if item:
                    candidates[item["candidate_id"]] = item
                    if len(candidates) >= limits["max_candidates"]:
                        end_condition = "candidate_limit_reached"
                        break
                else:
                    rejected_records += 1
            if error_code or end_condition == "candidate_limit_reached":
                break
        if error_code or end_condition:
            break
        if provider == "certspotter":
            if cursor is None:
                error_code = "CURSOR_MISSING"
                break
        else:
            marker_pointer = cfg["endpoint"].get("has_more_pointer")
            if not marker_pointer:
                error_code = "PAGINATION_UNDECLARED"
                break
            marker = _pointer(payload, marker_pointer)
            if marker is False:
                end_condition = "page_exhausted"
                break
            if marker is not True or not cfg["endpoint"].get("page_param"):
                error_code = "PAGINATION_MISMATCH"
                break
            page += 1
    if end_condition is None and error_code is None:
        error_code = "REQUEST_LIMIT_EXCEEDED" if budget.used >= budget.maximum else "PAGE_LIMIT_EXCEEDED"
    observed_at = _stamp(now)
    if rejected_records and error_code is None:
        error_code = "RECORDS_REJECTED"
    complete = end_condition in {"provider_empty", "page_exhausted"} and rejected_records == 0
    state = "completed" if complete else "failed"
    coverage = {"state": "COMPLETE" if complete else "PARTIAL", "pages": pages,
                "result_count": len(candidates), "provider_total_count": None,
                "rejected_records": rejected_records,
                "end_condition": end_condition, "error_code": error_code,
                "limitations": (["public_index_not_exhaustive", "certificate_names_are_ownership_candidates"] if provider == "certspotter" else
                                ["operator_configured_json_export", "native_search_coverage_not_claimed"]),
                "health_provenance": health}
    report = {"version": 1, "run_id": "dcrun_" + uuid.uuid4().hex, "scope_id": cfg["scope_id"],
              "provider": provider, "channel_id": cfg["channel_id"], "source_id": cfg["source_id"],
              "query_work_id": cfg["query"]["work_id"], "query_sha256": _query_digest(cfg["query"]["value"]), "observed_at": observed_at,
              "status": coverage["state"], "requests_used": budget.used, "coverage": coverage,
              "synthetic": fetcher is not transport_fetch,
              "candidates": list(candidates.values())}
    # This projection is private-plan compatible while retaining only the already
    # allowlisted health provenance in the shared discovery report.
    if not report["synthetic"]:
        report["search_plan_import"] = {"channel_health_provenance": health, "jobs": [{
            "work_id": cfg["query"]["work_id"], "state": state, "result_count": len(candidates),
            "pages": pages, "end_condition": end_condition, "error_code": error_code,
            "observed_at": observed_at, "source_ref": cfg["source_id"]}]}
    return report

def make_plan_import(report: Mapping[str, Any], plan: Mapping[str, Any], channel_health: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a live report to the exact private plan job and health record."""
    if not isinstance(report, Mapping) or report.get("synthetic") is not False:
        raise ValueError("live discovery report required")
    if not isinstance(plan, Mapping) or plan.get("scope_id") != report.get("scope_id") or not isinstance(plan.get("jobs"), list):
        raise ValueError("plan scope mismatch")
    matches=[j for j in plan["jobs"] if isinstance(j,Mapping) and j.get("work_id")==report.get("query_work_id")]
    if len(matches)!=1 or matches[0].get("channel")!=report.get("channel_id") or not isinstance(matches[0].get("value"),str) or _query_digest(matches[0]["value"])!=report.get("query_sha256"):
        raise ValueError("plan query mismatch")
    try: observed=datetime.fromisoformat(str(report.get("observed_at","")).replace("Z","+00:00"))
    except (ValueError,OverflowError): raise ValueError("invalid observation time") from None
    if observed.tzinfo is None or validate_health(channel_health,[str(report["channel_id"])],now=observed):
        raise ValueError("channel health invalid")
    controls=extract_health_provenance(channel_health,[str(report["channel_id"])])
    coverage=report.get("coverage")
    if not isinstance(coverage,Mapping) or controls!=coverage.get("health_provenance"):
        raise ValueError("health provenance mismatch")
    complete=report.get("status")=="COMPLETE"
    return {"channel_health":json.loads(json.dumps(channel_health)),"jobs":[{"work_id":report["query_work_id"],
        "state":"completed" if complete else "failed","result_count":coverage.get("result_count"),"pages":coverage.get("pages"),
        "end_condition":coverage.get("end_condition"),"error_code":coverage.get("error_code"),"observed_at":report["observed_at"],"source_ref":report.get("source_id")}]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded public JSON discovery stream")
    parser.add_argument("--config", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--channel-health", required=True)
    parser.add_argument("--locator-store", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--plan"); parser.add_argument("--import-output")
    args = parser.parse_args(argv)
    try:
        from .channel_health import load_health_report
        from .locators import LocatorStore
        cfg = load_channel_config(args.config)
        with LocatorStore(args.locator_store) as store:
            report = run_discovery(cfg, scope=Scope.load(args.scope),
                                   channel_health=load_health_report(args.channel_health),
                                   locator_store=store)
        if bool(args.plan)!=bool(args.import_output): raise ValueError("plan and import output required together")
        private_import=None
        if args.plan:
            private_import=make_plan_import(report,json.loads(Path(args.plan).read_text(encoding="utf-8")),load_health_report(args.channel_health))
        target = Path(args.output)
        _exclusive_json(target, report)
        if private_import is not None: _exclusive_json(Path(args.import_output),private_import)
        print(json.dumps({k: report[k] for k in ("run_id", "status", "provider", "channel_id", "requests_used")}))
        return 0 if report["status"] == "COMPLETE" else 3
    except (ValueError, OSError, json.JSONDecodeError):
        print(json.dumps({"error": "discovery_channel_failed"}))
        return 2
