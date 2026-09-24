"""Bounded commit-history review for one approved public GitHub repository.

Metadata mode reads only the commit-list endpoint. Patch mode is a separate,
scope-authorized anonymous observation and never reports source text.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import stat
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from .classifiers import MAX_ANALYSIS_BYTES, analyze
from .github_code_search import Broker, CodeError, _repository
from .github_discovery import _normalize_response
from .locators import LocatorStore
from .policy import PolicyError, Scope
from .transport import fetch as transport_fetch

MAX_INPUT = 1_048_576
MAX_BYTES = 8 * 1024 * 1024
MAX_REQUESTS = 20
MAX_PATCH_BYTES = 512 * 1024
MAX_DURATION = 60
_SHA = re.compile(r"[0-9a-f]{40}")
_URL = re.compile(r"https?://[^\s<>\"']{1,2048}")
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@(?: .*)?$")


def _is_reparse(path):
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _no_reparse_chain(path):
    absolute = path.absolute()
    if any(part.exists() and _is_reparse(part) for part in (absolute, *absolute.parents)):
        raise ValueError("unsafe_path")


def _load(path):
    source = Path(path)
    _no_reparse_chain(source)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        raw = os.read(descriptor, MAX_INPUT + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_INPUT:
        raise ValueError("input_too_large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid_manifest")
    return value


def _time(value):
    if not isinstance(value, str):
        raise ValueError("invalid_time")
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("invalid_time")
    return parsed.astimezone(timezone.utc)


def _manifest(value):
    required = {"scope_id", "repository", "branch", "since", "until", "max_commits", "expires_at", "owner_ref"}
    if not isinstance(value, dict) or not required <= set(value):
        raise ValueError("invalid_manifest")
    scope_id = value["scope_id"]
    if not isinstance(scope_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", scope_id):
        raise ValueError("invalid_scope")
    repository = _repository(value["repository"])
    branch = value["branch"]
    if (not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", branch)
            or any(part in {"", ".", ".."} for part in branch.split("/")) or ".." in branch):
        raise ValueError("invalid_branch")
    since, until, expiry = _time(value["since"]), _time(value["until"]), _time(value["expires_at"])
    if since > until or expiry <= datetime.now(timezone.utc):
        raise ValueError("expired_or_invalid_scope")
    maximum = value["max_commits"]
    if type(maximum) is not int or not 1 <= maximum <= 50:
        raise ValueError("invalid_commit_limit")
    if not isinstance(value["owner_ref"], str) or not 1 <= len(value["owner_ref"]) <= 256:
        raise ValueError("invalid_owner_ref")
    return scope_id, repository, branch, since, until, maximum


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        return None
    value = value.replace("\\", "/")
    if value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return value


def _header_path(value, prefix):
    value = value.strip()
    if value == "/dev/null":
        return None
    if value.startswith('"') and "\\" in value:
        return False  # Git C-quoted escapes cannot be decoded by shlex reliably.
    try:
        tokens = shlex.split(value)
    except ValueError:
        return False
    candidate = tokens[0] if value.startswith('"') and len(tokens) == 1 else value
    if not candidate.startswith(prefix):
        return False
    return _path(candidate[len(prefix):]) or False


def _category_hint(path):
    suffix = Path(path).suffix.casefold()
    if suffix in {".csv", ".json", ".jsonl", ".tsv", ".xml", ".yaml", ".yml"}:
        return "structured_data_or_config"
    if suffix in {".sql", ".sqlite", ".db"}:
        return "database_material"
    if suffix in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
        return "document"
    if suffix in {".pem", ".key", ".p12", ".pfx"}:
        return "credential_material_candidate"
    if suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb", ".php"}:
        return "source_code"
    return "other"


def _parse_patch(body, repository, sha, locator_store, scope_id):
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeError:
        return None, "patch_not_utf8_plaintext"
    if "\x00" in text or not text.startswith(f"From {sha} "):
        return None, "patch_provenance_invalid"
    files, changed_lines = [], []
    old_path = new_path = False
    old_remaining = new_remaining = 0
    saw_hunk = saw_binary = saw_diff = False
    for line in text.splitlines():
        in_hunk = old_remaining > 0 or new_remaining > 0
        if not in_hunk and line.startswith("diff --git "):
            saw_diff = True
            old_path = new_path = False
        elif not in_hunk and (line.startswith("GIT binary patch") or line.startswith("Binary files ")):
            saw_binary = True
        elif not in_hunk and line.startswith("--- "):
            old_path = _header_path(line[4:], "a/")
        elif not in_hunk and line.startswith("+++ "):
            new_path = _header_path(line[4:], "b/")
            if old_path is False or new_path is False or (old_path is None and new_path is None):
                return None, "patch_provenance_invalid"
            path = new_path or old_path
            status = "added" if old_path is None else "removed" if new_path is None else "renamed" if old_path != new_path else "modified"
            digest = hashlib.sha256(path.encode()).hexdigest()
            if status == "removed":
                location = f"https://github.com/{repository}/commit/{sha}#diff-{digest}"
            else:
                location = f"https://github.com/{repository}/blob/{sha}/{urllib.parse.quote(path, safe='/')}"
            files.append({"file_locator_ref": locator_store.put(scope_id, location), "path_sha256": digest,
                          "status": status, "category_hint": _category_hint(path),
                          "current_repository_state": "not_measured"})
        elif not in_hunk and line.startswith("@@"):
            match = _HUNK.match(line)
            if not match or not saw_diff or old_path is False or new_path is False:
                return None, "patch_provenance_invalid"
            old_remaining = int(match.group(1) or 1)
            new_remaining = int(match.group(2) or 1)
            saw_hunk = True
        elif in_hunk and line[:1] in {"+", "-"}:
            changed_lines.append(line)
            if line.startswith("+"):
                new_remaining -= 1
            else:
                old_remaining -= 1
        elif in_hunk and line.startswith(" "):
            old_remaining -= 1
            new_remaining -= 1
        elif in_hunk and line == "\\ No newline at end of file":
            pass
        elif in_hunk:
            return None, "patch_provenance_invalid"
        if old_remaining < 0 or new_remaining < 0:
            return None, "patch_provenance_invalid"
    if old_remaining or new_remaining:
        return None, "patch_provenance_invalid"
    if not saw_diff:
        return None, "patch_provenance_invalid"
    if not saw_hunk:
        reason = "binary_patch_not_inspected" if saw_binary else "patch_has_no_text_hunks"
        return {"changed_files": files, "content_review": "not_inspected"}, reason
    changed = "\n".join(changed_lines).encode()
    classification = analyze(changed, "text/plain").report
    js_classification = analyze("\n".join(line[1:] for line in changed_lines).encode(),
                                "application/javascript").report
    signals = sorted({row["code"] for report in (classification, js_classification)
                      for row in report["signals"]})
    if any(report["content"] == "SENSITIVE_CANDIDATE" for report in (classification, js_classification)):
        return {"changed_files": files, "content_review": "stopped_sensitive_candidate",
                "signal_codes": signals}, None
    if saw_binary:
        return {"changed_files": files, "content_review": "not_inspected"}, "binary_patch_not_inspected"
    if len(changed) > MAX_ANALYSIS_BYTES or not all(report["analysis_complete"] for report in (classification, js_classification)):
        return {"changed_files": files, "content_review": "stopped_analysis_limit",
                "signal_codes": signals}, "patch_analysis_limit_reached"
    introduced, removed = set(), set()
    for line in changed_lines:
        target = introduced if line.startswith("+") else removed
        for match in _URL.findall(line[1:]):
            target.add(locator_store.put(scope_id, match.rstrip(".,);]")))
    return {"changed_files": files, "content_review": "value_free_signals_only",
            "literal_url_changes": {"introduced_locator_refs": sorted(introduced),
                                    "removed_locator_refs": sorted(removed)}}, None


def _scope_authorizes_patch(scope, url, owner_ref):
    if not isinstance(scope, Scope):
        raise ValueError("scope_required_for_patch_inspection")
    normalized = scope.authorize(url)
    parts = urllib.parse.urlsplit(normalized)
    origin = f"https://{parts.netloc}"
    decoded_path = urllib.parse.unquote(parts.path)
    matched = [target for target in scope.targets if target.origin == origin and any(
        prefix == "/" or decoded_path == prefix or decoded_path.startswith(prefix.rstrip("/") + "/")
        for prefix in target.path_prefixes)]
    expected_prefix = "/" + "/".join(decoded_path.strip("/").split("/")[:3]) + "/"
    if not matched or not any(target.ownership_evidence == owner_ref and
                              (expected_prefix in target.path_prefixes or decoded_path in target.path_prefixes)
                              for target in matched):
        raise ValueError("owner_reference_mismatch")
    return normalized


def _validate_patch_scope(scope, repository, owner_ref):
    if scope.expires_at <= datetime.now(timezone.utc):
        raise ValueError("expired_patch_scope")
    prefix = f"/{repository}/commit/"
    if not any(target.origin == "https://github.com" and target.ownership_evidence == owner_ref and
               any(path == prefix or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{40}\.patch", path)
                   for path in target.path_prefixes) for target in scope.targets):
        raise ValueError("owner_reference_mismatch")


class HistoryBroker(Broker):
    """Anonymous fixed-host GitHub metadata and scope-bound patch transport."""

    def __init__(self, *, fetcher=None):
        super().__init__("", limit=MAX_REQUESTS, fetcher=fetcher)
        self.deadline = time.monotonic() + MAX_DURATION

    def api(self, path, query=None):
        if not re.fullmatch(r"/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/commits", path):
            raise CodeError("ENDPOINT_INVALID")
        url = "https://api.github.com" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        status, payload = self._request(url, {"Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "open-detective-history/1"})
        if status != 200:
            raise CodeError("HISTORY_REQUEST_FAILED")
        return payload

    def patch(self, url, sha, scope):
        if self.requests >= self.limit:
            raise CodeError("REQUEST_BUDGET")
        remaining_time = self.deadline - time.monotonic()
        if remaining_time <= 0:
            raise CodeError("TIME_BUDGET")
        remaining_bytes = MAX_BYTES - self.bytes
        if remaining_bytes <= 0:
            raise CodeError("BYTE_BUDGET")
        self.requests += 1
        maximum = min(MAX_PATCH_BYTES, remaining_bytes)
        if self.fetcher is not None:
            try:
                response = _normalize_response(self.fetcher(url, {"Accept": "text/plain", "Accept-Encoding": "identity",
                                                               "User-Agent": "open-detective-history/1"}))
                body = response.payload.encode() if isinstance(response.payload, str) else (
                    bytes(response.payload) if isinstance(response.payload, (bytes, bytearray)) else b"")
                observed_size = response.body_bytes or len(body)
                complete = observed_size <= maximum
                body = body[:maximum]
                status, headers = response.status, response.headers
            except Exception:
                raise CodeError("PATCH_REQUEST_FAILED") from None
        else:
            result = transport_fetch(url, scope, follow_redirects=False, max_bytes=maximum,
                                     timeout=min(float(scope.timeout), remaining_time))
            body, headers = result.body, result.headers
            status = result.observation.get("http_status")
            complete = bool(result.observation.get("capture_complete"))
        self.bytes += len(body)
        if self.bytes > MAX_BYTES:
            raise CodeError("BYTE_BUDGET")
        if status != 200:
            return None, "patch_unavailable"
        media = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        encoding = headers.get("content-encoding", "identity").strip().casefold()
        if media not in {"text/plain", "text/x-patch"}:
            return None, "patch_not_plaintext"
        if encoding not in {"", "identity"}:
            return None, "patch_encoding_unsupported"
        if not complete:
            return None, "patch_byte_limit_reached"
        if not body.startswith(f"From {sha} ".encode()):
            return None, "patch_provenance_invalid"
        return body, None


def discover_history(manifest, locator_store, *, inspect_patches=False, scope=None, fetcher=None):
    scope_id, repository, branch, since, until, maximum = _manifest(manifest)
    if inspect_patches and not isinstance(scope, Scope):
        raise ValueError("scope_required_for_patch_inspection")
    if inspect_patches:
        _validate_patch_scope(scope, repository, manifest["owner_ref"])
    broker = HistoryBroker(fetcher=fetcher)
    broker.preflight(repository)
    owner, name = repository.split("/")
    listing = broker.api(f"/repos/{owner}/{name}/commits", {"sha": branch, "since": since.isoformat(),
                         "until": until.isoformat(), "per_page": maximum})
    if not isinstance(listing, list) or len(listing) > maximum:
        raise CodeError("MALFORMED_HISTORY")
    listed_shas = [row.get("sha") if isinstance(row, dict) else None for row in listing]
    if (any(not isinstance(sha, str) or not _SHA.fullmatch(sha) for sha in listed_shas)
            or len(set(listed_shas)) != len(listed_shas)):
        raise CodeError("MALFORMED_HISTORY")
    commits, gaps = [], [{"reason": "history_control_not_measured"}]
    capped = len(listing) == maximum
    if capped:
        gaps.append({"reason": "commit_cap_reached_possible_more"})
    if not listing:
        gaps.append({"reason": "zero_history_result_nonconclusive"})
    stopped = False
    for index, sha in enumerate(listed_shas):
        commit_url = f"https://github.com/{repository}/commit/{sha}"
        commit = {"sha": sha, "commit_locator_ref": locator_store.put(scope_id, commit_url),
                  "patch_inspection": "not_requested"}
        if inspect_patches:
            try:
                patch_url = _scope_authorizes_patch(scope, commit_url + ".patch", manifest["owner_ref"])
                body, stop = broker.patch(patch_url, sha, scope)
            except (CodeError, PolicyError, ValueError) as exc:
                reason = str(exc).casefold() if isinstance(exc, CodeError) else "patch_scope_authorization_failed"
                gaps.append({"sha": sha, "reason": reason})
                commit["patch_inspection"] = "incomplete"
                commits.append(commit)
                stopped = True
                gaps.append({"reason": "remaining_commits_not_inspected", "count": len(listed_shas) - index - 1})
                break
            if stop:
                gaps.append({"sha": sha, "reason": stop})
                commit["patch_inspection"] = "incomplete"
            else:
                commit.update(patch_sha256=hashlib.sha256(body).hexdigest(), captured_bytes=len(body),
                              capture_complete=True)
                summary, stop = _parse_patch(body, repository, sha, locator_store, scope_id)
                if stop:
                    gaps.append({"sha": sha, "reason": stop})
                    commit["patch_inspection"] = "incomplete"
                    if summary:
                        commit.update(**summary)
                else:
                    commit.update(patch_inspection="value_free_summary", **summary)
                    if summary["content_review"] == "stopped_sensitive_candidate":
                        gaps.append({"sha": sha, "reason": "sensitive_candidate_stop"})
                        commits.append(commit)
                        stopped = True
                        gaps.append({"reason": "remaining_commits_not_inspected", "count": len(listed_shas) - index - 1})
                        break
        commits.append(commit)
    return {"schema_version": "1.0", "scope_id": scope_id,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository_locator_ref": locator_store.put(scope_id, "https://github.com/" + repository),
            "branch_sha256": hashlib.sha256(branch.encode()).hexdigest(),
            "window": {"since": manifest["since"], "until": manifest["until"]},
            "inspection_mode": "patch" if inspect_patches else "metadata_only", "history_truncated": capped or stopped,
            "commits": commits, "coverage_gaps": gaps, "requests": broker.requests, "bytes": broker.bytes,
            "public_preflights": broker.public_preflights,
            "limitations": ["selected_public_repository_only", "history_window_and_commit_cap",
                            "history_channel_control_not_measured", "author_identity_redacted",
                            "current_repository_state_not_measured", "patches_not_executed",
                            "discovered_urls_not_requested", "server_state_not_measured"]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--locator-store", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--inspect-patches", action="store_true")
    parser.add_argument("--scope")
    args = parser.parse_args(argv)
    try:
        output = Path(args.output).absolute()
        _no_reparse_chain(output.parent)
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise ValueError("unsafe_output")
        with LocatorStore(args.locator_store) as store:
            loaded_scope = Scope.load(args.scope) if args.inspect_patches and args.scope else None
            result = discover_history(_load(args.manifest), store, inspect_patches=args.inspect_patches, scope=loaded_scope)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print(json.dumps({"error": "github_history_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
