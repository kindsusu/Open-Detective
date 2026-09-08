"""Anonymous positive controls for deciding whether discovery channels are healthy.

This module deliberately stores only opaque identifiers and outcome codes.  Control
URLs and response markers are input to an observation, never report data.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit

from .policy import PolicyError, Scope
from .transport import FetchResult, fetch


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_CONFIG_BYTES = 1_048_576
_MAX_AGE = 86_400
_DEFAULT_AGE = 3_600
_MAX_JSON_DEPTH = 128
_GITHUB_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid_time")
    return value.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_stamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (ValueError, OverflowError):
        return None
    try:
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _bounded_json(text: str) -> Any:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH: raise ValueError
        elif char in "]}":
            depth -= 1
            if depth < 0: raise ValueError
    if quoted or depth != 0: raise ValueError
    return json.loads(text)


def _load_json(source: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    if isinstance(source, Mapping):
        data = dict(source)
        try:
            encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise ValueError("invalid_config") from None
        if len(encoded) > _MAX_CONFIG_BYTES:
            raise ValueError("invalid_config")
        try:
            checked = _bounded_json(encoded.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise ValueError("invalid_config") from None
        if not isinstance(checked, dict): raise ValueError("invalid_config")
        return checked, encoded
    try:
        with Path(source).open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ValueError
        data = _bounded_json(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("invalid_config") from None
    if not isinstance(data, dict):
        raise ValueError("invalid_config")
    return data, raw


def load_health_report(path: str | Path) -> dict[str, Any]:
    """Load a bounded health report; callers validate its schema separately."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ValueError
        data = _bounded_json(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("invalid_report") from None
    if not isinstance(data, dict):
        raise ValueError("invalid_report")
    return data


def _valid_number(value: object) -> bool:
    if isinstance(value, bool): return False
    if isinstance(value, int): return value.bit_length() <= 1024
    return isinstance(value, float) and math.isfinite(value)


def _valid_expectation(value: object) -> bool:
    if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str):
        return False
    kind = value["kind"]
    if kind == "body_contains":
        if set(value) != {"kind", "value"} or not isinstance(value.get("value"), str) or not value["value"].strip() or len(value["value"]) > 4096:
            return False
        try:
            value["value"].encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if kind == "json_pointer":
        if set(value) != {"kind", "pointer", "equals"} or not isinstance(value.get("pointer"), str):
            return False
        expected = value.get("equals")
        scalar = (isinstance(expected, str) and bool(expected)) or isinstance(expected, bool) or _valid_number(expected)
        return scalar and len(value["pointer"]) <= 1024 and _pointer_tokens(value["pointer"]) is not None
    return False


def _pointer_tokens(pointer: str) -> list[str] | None:
    if pointer == "":
        return []
    if not pointer.startswith("/") or pointer.count("/") > 64:
        return None
    result: list[str] = []
    for part in pointer[1:].split("/"):
        if len(part) > 256:
            return None
        out = []
        index = 0
        while index < len(part):
            char = part[index]
            if char != "~":
                out.append(char); index += 1; continue
            if index + 1 >= len(part) or part[index + 1] not in "01":
                return None
            out.append("~" if part[index + 1] == "0" else "/")
            index += 2
        result.append("".join(out))
    return result


def _positive_query(value: str, maximum: int) -> bool:
    return value.isascii() and value.isdecimal() and not value.startswith("0") and 1 <= int(value) <= maximum


def _github_control_url(channel_id: str, url: str) -> bool:
    """Bind the three GitHub discovery controls to their intended public API families."""
    if channel_id not in {"github-repositories", "github-user-search", "github-repository-search"}:
        return True
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "api.github.com" or (parts.port or 443) != 443 or parts.fragment:
            return False
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, UnicodeError):
        return False
    query: dict[str, str] = {}
    for key, value in pairs:
        if key in query: return False
        query[key] = value
    path = parts.path.rstrip("/") or "/"
    if channel_id == "github-repositories":
        segments = path.split("/")
        repository_path = (len(segments) == 4 and segments[1] == "repos" and _GITHUB_NAME.fullmatch(segments[2]) and
                           _GITHUB_REPOSITORY.fullmatch(segments[3]) and segments[3] not in {".", ".."})
        listing_path = len(segments) == 4 and segments[1] in {"users", "orgs"} and segments[3] == "repos" and _GITHUB_NAME.fullmatch(segments[2])
        if not (repository_path or listing_path): return False
        return set(query) <= {"per_page", "page"} and all(_positive_query(value, 100 if key == "per_page" else 1_000_000) for key, value in query.items())
    expected_path = "/search/users" if channel_id == "github-user-search" else "/search/repositories"
    if path != expected_path or not isinstance(query.get("q"), str) or not query["q"].strip() or len(query["q"]) > 256:
        return False
    if not set(query) <= {"q", "per_page", "page", "sort", "order"}: return False
    if "per_page" in query and not _positive_query(query["per_page"], 100): return False
    if "page" in query and not _positive_query(query["page"], 1_000_000): return False
    allowed_sort = {"followers", "repositories", "joined"} if channel_id == "github-user-search" else {"stars", "forks", "help-wanted-issues", "updated"}
    return ("sort" not in query or query["sort"] in allowed_sort) and ("order" not in query or query["order"] in {"asc", "desc"})


def _validate_config(config: Mapping[str, Any], scope: Scope) -> tuple[list[dict[str, Any]], int]:
    if set(config) - {"controls", "max_age_seconds"}:
        raise ValueError("invalid_config")
    controls = config.get("controls")
    age = config.get("max_age_seconds", _DEFAULT_AGE)
    if isinstance(age, bool) or not isinstance(age, int) or not 1 <= age <= _MAX_AGE:
        raise ValueError("invalid_config")
    if not isinstance(controls, list) or not 1 <= len(controls) <= 16 or len(controls) > scope.max_requests:
        raise ValueError("invalid_config")
    clean: list[dict[str, Any]] = []
    channels: set[str] = set()
    controls_seen: set[str] = set()
    for item in controls:
        if not isinstance(item, Mapping) or set(item) != {"channel_id", "control_id", "url", "expect"}:
            raise ValueError("invalid_config")
        channel_id, control_id, url, expected = item.get("channel_id"), item.get("control_id"), item.get("url"), item.get("expect")
        if (not isinstance(channel_id, str) or not _ID.fullmatch(channel_id) or channel_id in channels or
                not isinstance(control_id, str) or not _ID.fullmatch(control_id) or control_id in controls_seen or
                not isinstance(url, str) or len(url) > 4096 or not _valid_expectation(expected)):
            raise ValueError("invalid_config")
        try:
            authorized = scope.authorize(url)
        except PolicyError:
            raise ValueError("invalid_config") from None
        if not _github_control_url(channel_id, authorized):
            raise ValueError("invalid_config")
        channels.add(channel_id); controls_seen.add(control_id)
        clean.append({"channel_id": channel_id, "control_id": control_id, "url": authorized, "expect": dict(expected)})
    return clean, age


def _matches(body: bytes, expected: Mapping[str, Any]) -> bool:
    kind = expected["kind"]
    if kind == "body_contains":
        return expected["value"].encode("utf-8") in body
    try:
        value = _bounded_json(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return False
    tokens = _pointer_tokens(expected["pointer"])
    if tokens is None:
        return False
    for token in tokens:
        if isinstance(value, dict):
            if token not in value: return False
            value = value[token]
        elif isinstance(value, list):
            if not token.isascii() or not token.isdecimal() or (len(token) > 1 and token.startswith("0")):
                return False
            index = int(token)
            if index >= len(value): return False
            value = value[index]
        else:
            return False
    return type(value) is type(expected["equals"]) and value == expected["equals"]


def _status(result: FetchResult, expected: Mapping[str, Any]) -> tuple[str, str]:
    observation = result.observation if isinstance(result.observation, Mapping) else {}
    code = observation.get("http_status")
    complete = observation.get("capture_complete") is True
    headers = result.headers if isinstance(result.headers, Mapping) else {}
    encoding = headers.get("content-encoding", "identity")
    identity = isinstance(encoding, str) and encoding.casefold() in {"", "identity"}
    if code == 200 and complete and identity and _matches(result.body, expected):
        return "OK", "expectation_matched"
    if code is None or code in (404, 410):
        return "DEAD", "control_unreachable"
    if code != 200:
        return "DEGRADED", "http_status_unexpected"
    if not complete:
        return "DEGRADED", "capture_incomplete"
    return "DEGRADED", "expectation_mismatch"


def _observation_id(value: object) -> str | None:
    if not isinstance(value, str): return None
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        return None


_CONTROL_FIELDS = frozenset({"channel_id", "control_id", "status", "observed_at", "expires_at", "observation_id", "policy_id", "reason_code", "capture_complete", "http_status"})


def _valid_control(item: object) -> bool:
    """Validate serialized control shape without raising on hostile values."""
    if not isinstance(item, Mapping) or set(item) != _CONTROL_FIELDS: return False
    channel, control, status, reason, policy = (item.get("channel_id"), item.get("control_id"), item.get("status"), item.get("reason_code"), item.get("policy_id"))
    if not all(isinstance(value, str) for value in (channel, control, status, reason, policy)): return False
    if not _ID.fullmatch(channel) or not _ID.fullmatch(control) or status not in {"OK", "DEGRADED", "DEAD"} or not _ID.fullmatch(reason) or not (0 < len(policy) <= 128): return False
    observation = item.get("observation_id")
    if observation is not None and _observation_id(observation) is None: return False
    http_status = item.get("http_status")
    if not isinstance(item.get("capture_complete"), bool) or (http_status is not None and (isinstance(http_status, bool) or not isinstance(http_status, int) or not 0 <= http_status <= 599)): return False
    return _parse_stamp(item.get("observed_at")) is not None and _parse_stamp(item.get("expires_at")) is not None


def extract_health_provenance(report: object, required_channels: Iterable[str]) -> list[dict[str, object]]:
    """Return safe, shape-validated control provenance for discovery gates.

    The policy identifier is deliberately excluded because scopes allow operator text;
    consumers get only identifiers with fixed UUID/ID grammar.
    """
    try:
        required = list(required_channels) if not isinstance(required_channels, (str, bytes)) else []
    except TypeError:
        return []
    if not required or any(not isinstance(channel, str) or not _ID.fullmatch(channel) for channel in required) or len(set(required)) != len(required): return []
    if not isinstance(report, Mapping) or not isinstance(report.get("controls"), list) or len(report["controls"]) > 16: return []
    controls: dict[str, Mapping[str, Any]] = {}
    seen_ids: set[str] = set()
    for item in report["controls"]:
        if not _valid_control(item): return []
        channel, control = item["channel_id"], item["control_id"]
        if channel in controls or control in seen_ids: return []
        controls[channel] = item; seen_ids.add(control)
    output = []
    for channel in required:
        item = controls.get(channel)
        if item is None: return []
        output.append({"channel_id": channel, "control_id": item["control_id"], "observation_id": item["observation_id"], "status": item["status"], "observed_at": item["observed_at"], "expires_at": item["expires_at"]})
    return output


def run_checks(config: str | Path | Mapping[str, Any], scope: str | Path | Scope, *, fetcher: Callable[..., FetchResult] | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Run each pre-authorized control once.  An injected fetcher makes output synthetic."""
    current = _utc(now)
    loaded_scope = scope if isinstance(scope, Scope) else Scope.load(scope)
    raw_config, _ = _load_json(config)
    controls, max_age = _validate_config(raw_config, loaded_scope)  # Validate every URL before any request.
    active_fetcher = fetcher or fetch
    entries: list[dict[str, Any]] = []
    for control in controls:
        try:
            result = active_fetcher(control["url"], loaded_scope, follow_redirects=False)
            if not isinstance(result, FetchResult):
                raise TypeError
            health, reason = _status(result, control["expect"])
            observation = result.observation if isinstance(result.observation, Mapping) else {}
            http_status = observation.get("http_status")
            if isinstance(http_status, bool) or not isinstance(http_status, int) or not 0 <= http_status <= 599:
                http_status = None
            capture_complete = observation.get("capture_complete") is True
            observation_id = _observation_id(observation.get("observation_id"))
        except Exception:
            health, reason, http_status, capture_complete, observation_id = "DEAD", "control_unreachable", None, False, None
        observed = current if now is not None else _utc()
        expires = observed + timedelta(seconds=max_age)
        entries.append({"channel_id": control["channel_id"], "control_id": control["control_id"], "status": health,
                        "observed_at": _stamp(observed), "expires_at": _stamp(expires), "observation_id": observation_id,
                        "policy_id": loaded_scope.policy_id, "reason_code": reason, "capture_complete": capture_complete,
                        "http_status": http_status})
    finished = current if now is not None else _utc()
    return {"schema_version": "1.0", "kind": "channel_health", "status": "OK" if all(x["status"] == "OK" for x in entries) else "PARTIAL",
            "observed_at": _stamp(finished), "expires_at": _stamp(finished + timedelta(seconds=max_age)), "controls": entries,
            "synthetic": fetcher is not None or now is not None}


def _validate_health(report: object, required_channels: Iterable[str], now: datetime | None = None) -> list[str]:
    """Return only safe, fail-closed health errors suitable for a discovery gate."""
    errors: set[str] = set()
    current = _utc(now)
    try:
        required = list(required_channels) if not isinstance(required_channels, (str, bytes)) else []
    except TypeError:
        required = []
    required_valid = bool(required) and all(isinstance(value, str) and _ID.fullmatch(value) for value in required)
    if not required_valid: errors.add("invalid")
    elif len(set(required)) != len(required): errors.add("invalid")
    if not isinstance(report, Mapping): return ["invalid"]
    top_fields = {"schema_version", "kind", "status", "observed_at", "expires_at", "controls", "synthetic"}
    if set(report) != top_fields or report.get("schema_version") != "1.0" or report.get("kind") != "channel_health" or report.get("synthetic") is not False:
        errors.add("invalid")
    observed, expires = _parse_stamp(report.get("observed_at")), _parse_stamp(report.get("expires_at"))
    if observed is None or expires is None: errors.add("invalid")
    else:
        if observed > current or expires > current + timedelta(seconds=_MAX_AGE): errors.add("future")
        if expires <= observed or expires - observed > timedelta(seconds=_MAX_AGE) or expires <= current: errors.add("stale")
        if current - observed > timedelta(seconds=_MAX_AGE): errors.add("stale")
    controls = report.get("controls")
    if not isinstance(controls, list) or not 1 <= len(controls) <= 16: return sorted(errors | {"invalid"})
    by_channel: dict[str, Mapping[str, Any]] = {}
    seen_control_ids: set[str] = set()
    for item in controls:
        if not _valid_control(item):
            errors.add("invalid"); continue
        assert isinstance(item, Mapping)
        if item["channel_id"] in by_channel or item["control_id"] in seen_control_ids:
            errors.add("invalid"); continue
        item_observed, item_expires = _parse_stamp(item.get("observed_at")), _parse_stamp(item.get("expires_at"))
        if item_observed is None or item_expires is None:
            errors.add("invalid"); continue
        if item_observed > current or item_expires > current + timedelta(seconds=_MAX_AGE): errors.add("future")
        if item_expires <= item_observed or item_expires - item_observed > timedelta(seconds=_MAX_AGE) or item_expires <= current or current - item_observed > timedelta(seconds=_MAX_AGE): errors.add("stale")
        if observed is not None and expires is not None and (item_observed > observed or item_expires > expires): errors.add("invalid")
        by_channel[item["channel_id"]] = item
        seen_control_ids.add(item["control_id"])
    expected_status = "OK" if controls and all(isinstance(item, Mapping) and item.get("status") == "OK" for item in controls) else "PARTIAL"
    if report.get("status") != expected_status: errors.add("invalid")
    if not required_valid:
        return sorted(errors)
    for channel in required:
        item = by_channel.get(channel)
        if item is None:
            errors.add("missing"); continue
        if item.get("status") == "DEAD": errors.add("dead")
        elif item.get("status") == "DEGRADED": errors.add("degraded")
        elif not (item.get("http_status") == 200 and item.get("capture_complete") is True and item.get("reason_code") == "expectation_matched" and _observation_id(item.get("observation_id")) is not None): errors.add("invalid")
    return sorted(errors)


def validate_health(report: object, required_channels: Iterable[str], now: datetime | None = None) -> list[str]:
    """Fail closed for all malformed report and required-channel input shapes."""
    try:
        return _validate_health(report, required_channels, now)
    except Exception:
        return ["invalid"]


def _load_previous(path: str | None) -> Mapping[str, Any] | None:
    if not path: return None
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES: return None
        data = _bounded_json(raw.decode("utf-8"))
        return data if isinstance(data, Mapping) else None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None


def _changed(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> list[dict[str, str]]:
    prior_controls = previous.get("controls") if isinstance(previous, Mapping) else []
    if not isinstance(prior_controls, list): prior_controls = []
    old = {x["channel_id"]: x for x in prior_controls if _valid_control(x)}
    current_controls = current.get("controls") if isinstance(current.get("controls"), list) else []
    new = {x["channel_id"]: x for x in current_controls if _valid_control(x)}
    rows: list[dict[str, str]] = []
    observed = current.get("observed_at") if isinstance(current.get("observed_at"), str) else ""
    for channel in sorted(set(old) - set(new)):
        rows.append({"channel_id": channel, "status": "REMOVED", "reason_code": "removed", "observed_at": observed})
    for channel in sorted(new):
        item = new[channel]
        old_item = old.get(channel)
        if old_item is None or any(old_item.get(key) != item.get(key) for key in ("status", "reason_code", "control_id", "policy_id")):
            status, reason, at = item.get("status"), item.get("reason_code"), item.get("observed_at")
            if all(isinstance(value, str) for value in (status, reason, at)):
                rows.append({"channel_id": channel, "status": status, "reason_code": reason, "observed_at": at})
    return rows


def _atomic_write(path: str, report: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check anonymous discovery-channel positive controls.")
    parser.add_argument("--config", required=True); parser.add_argument("--scope", required=True)
    parser.add_argument("--output", required=True); parser.add_argument("--previous")
    args = parser.parse_args(list(argv) if argv is not None else None)
    previous = _load_previous(args.previous or args.output)
    try:
        report = run_checks(args.config, args.scope)
        _atomic_write(args.output, report)
        result = {"status": report["status"], "changed": _changed(report, previous)}
        code = 0 if report["status"] == "OK" else 2
    except (OSError, ValueError, PolicyError):
        result = {"status": "FAILED", "changed": []}; code = 2
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True); sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
