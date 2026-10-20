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
MAX_PATCH_BYTES_HARD = 128 * 1024 * 1024


def patch_requires_material_hold(signal_codes):
    """Labels/UI hints alone do not prove personal data or a usable secret."""
    non_material = {"CONFIDENTIAL_MARKER_CANDIDATE", "HIDDEN_DOM_PRESENT",
                    "LOGIN_FORM_INDICATOR", "RUNTIME_ENDPOINT_UNRESOLVED",
                    "RUNTIME_ENDPOINT_CANDIDATE", "KR_BUSINESS_NUMBER_CANDIDATE"}
    return not signal_codes or bool(set(signal_codes) - non_material)
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
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        return None
    if value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return value


def _git_path_token(value):
    """Decode one Git C-quoted path without shell expansion or lossy escaping."""
    if not isinstance(value, str) or not value:
        return None
    if not value.startswith('"'):
        return value if '"' not in value else None
    if not value.endswith('"'):
        return None
    raw = bytearray()
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11,
               "f": 12, "r": 13, '"': 34, "\\": 92}
    inner = value[1:-1]
    index = 0
    while index < len(inner):
        char = inner[index]
        if char == '"':
            return None
        if char != "\\":
            raw.extend(char.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(inner):
            return None
        char = inner[index]
        if char in escapes:
            raw.append(escapes[char])
            index += 1
        elif index + 3 <= len(inner) and re.fullmatch(r"[0-7]{3}", inner[index:index + 3]):
            decoded = int(inner[index:index + 3], 8)
            if decoded > 255:
                return None
            raw.append(decoded)
            index += 3
        else:
            return None
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeError:
        return None


def _diff_paths(value):
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s"]+', value)
    if len(tokens) == 2 and " ".join(tokens) == value:
        before, after = (_git_path_token(token) for token in tokens)
    elif value.startswith("a/") and '"' not in value and " b/" in value:
        # Match the final Git delimiter, then require ---/+++ path agreement.
        divider = value.rfind(" b/")
        before, after = value[:divider], value[divider + 1:]
    else:
        return None
    if not before or not after or not before.startswith("a/") or not after.startswith("b/"):
        return None
    before, after = _path(before[2:]), _path(after[2:])
    return (before, after) if before and after else None


def _header_path(value, prefix):
    value = value.strip()
    if value == "/dev/null":
        return None
    candidate = _git_path_token(value)
    if candidate is None:
        return False
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


def _patch_url_parts(url):
    """Accept only an exact public GitHub commit patch locator."""
    try:
        parts = urllib.parse.urlsplit(url)
        match = re.fullmatch(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-fA-F]{40})\.patch", parts.path)
        if (parts.scheme != "https" or parts.netloc != "github.com" or parts.query or
                parts.fragment or not match or any(part in {".", ".."} for part in match.groups()[:2])):
            return None
        return match.group(1) + "/" + match.group(2), match.group(3)
    except (TypeError, ValueError):
        return None


def _review_changed_lines(changed_lines):
    """Inspect bounded text chunks across a complete diff, including late lines.

    An overlong line leaves a structure gap after its full text is scanned.
    Truncated projection or incomplete classifier text remains an analysis gap.
    The projection is only analysis text; image pixels stay unreviewed.
    """
    changed = "\n".join(changed_lines).encode("utf-8")
    media_skipped = False
    limit_reached = False
    structure_incomplete = False
    if re.search(br"data:image/", changed, re.I):
        from .media_projection import project_inline_images
        projection = project_inline_images((changed[index:index + 65_536]
            for index in range(0, len(changed), 65_536)),
            max_wire_bytes=len(changed), max_projected_bytes=32 * 1024 * 1024)
        if projection.skipped_images:
            changed = projection.projected
            media_skipped = True
        limit_reached = projection.wire_truncated or projection.projected_truncated
    text = changed.decode("utf-8", "strict")
    chunks, current, current_bytes = [], [], 0
    limit = MAX_ANALYSIS_BYTES - 4096
    for line in text.splitlines():
        row_bytes = len(line.encode("utf-8")) + 1
        if row_bytes > limit:
            structure_incomplete = True
            if current:
                chunks.append("\n".join(current))
                current, current_bytes = [], 0
            # Every position of an oversized source line is scanned. Fragments
            # retain an explicit structure gap even when lexical signals pass.
            marker = line[:1] if line.startswith(("+", "-")) else ""
            segment = line[1:] if marker else line
            for offset in range(0, len(segment), 55_000):
                chunks.append(marker + segment[max(0, offset - 4096):offset + 55_000])
            continue
        if current and current_bytes + row_bytes > limit:
            chunks.append("\n".join(current))
            current, current_bytes = [], 0
        current.append(line)
        current_bytes += row_bytes
    if current:
        chunks.append("\n".join(current))
    signals = set()
    sensitive = False
    for chunk in chunks:
        if not chunk:
            continue
        text_bytes = chunk.encode("utf-8")
        source = "// patch snippet\n" + "\n".join(
            line[1:] if line.startswith(("+", "-")) else line for line in chunk.splitlines())
        reports = (analyze(text_bytes, "text/plain").report,
                   analyze(source.encode("utf-8"), "application/javascript").report)
        for report in reports:
            signals.update(row["code"] for row in report["signals"])
            sensitive |= report["content"] == "SENSITIVE_CANDIDATE"
            limit_reached |= not bool(report["text_analysis_complete"])
            structure_incomplete |= not bool(report["structure_analysis_complete"])
        if sensitive and patch_requires_material_hold(signals):
            break
    return signals, sensitive, limit_reached, structure_incomplete, media_skipped


def _header_only_patch(text, sha):
    """Recognize a commit mail envelope, never infer that its diff is empty."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith(f"From {sha} "):
        return False
    header_end = next((index for index, line in enumerate(lines[1:32], 1) if not line), None)
    if header_end is None:
        return False
    headers = lines[1:header_end]
    if not all(any(line.startswith(name + ": ") and line[len(name) + 2:].strip()
                   for line in headers) for name in ("From", "Date", "Subject")):
        return False
    if any("<html" in line.casefold() for line in lines[header_end + 1:]):
        return False
    return not any(line.startswith(("diff --git ", "@@ ", "--- a/", "+++ b/"))
                   for line in lines[header_end + 1:])


def _parse_patch(body, repository, sha, locator_store, scope_id):
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeError:
        return None, "patch_not_utf8_plaintext"
    if "\x00" in text or not text.startswith(f"From {sha} "):
        return None, "patch_provenance_invalid"
    files, changed_lines = [], []
    old_path = new_path = False
    diff_old = diff_new = None
    current_recorded = False
    status_hint = None
    old_remaining = new_remaining = 0
    saw_hunk = saw_binary = saw_diff = saw_file_marker = False
    file_hunk = file_marker = file_binary = missing_hunk = False

    def record_file():
        nonlocal current_recorded
        if current_recorded:
            return
        before = diff_old if old_path is False else old_path
        after = diff_new if new_path is False else new_path
        if before is False or after is False or (before is None and after is None):
            raise ValueError("patch_provenance_invalid")
        if (before is not None and before != diff_old) or (after is not None and after != diff_new):
            raise ValueError("patch_provenance_invalid")
        path = after or before
        status = ("added" if before is None or status_hint == "added" else
                  "removed" if after is None or status_hint == "removed" else
                  "renamed" if before != after else "modified")
        digest = hashlib.sha256(path.encode()).hexdigest()
        if status == "removed":
            location = f"https://github.com/{repository}/commit/{sha}#diff-{digest}"
        else:
            location = f"https://github.com/{repository}/blob/{sha}/{urllib.parse.quote(path, safe='/')}"
        files.append({"file_locator_ref": locator_store.put(scope_id, location),
                      "status": status, "category_hint": _category_hint(path),
                      "current_repository_state": "not_measured"})
        current_recorded = True

    def finish_file():
        nonlocal missing_hunk
        record_file()
        if file_marker and not file_hunk and not file_binary:
            missing_hunk = True

    for line in text.splitlines():
        in_hunk = old_remaining > 0 or new_remaining > 0
        if not in_hunk and line.startswith("diff --git "):
            if saw_diff:
                try:
                    finish_file()
                except ValueError:
                    return None, "patch_provenance_invalid"
            pair = _diff_paths(line[len("diff --git "):])
            if pair is None:
                return None, "patch_provenance_invalid"
            diff_old, diff_new = pair
            saw_diff = True
            old_path = new_path = False
            current_recorded = False
            status_hint = None
            file_hunk = file_marker = file_binary = False
        elif not in_hunk and line.startswith("new file mode "):
            status_hint = "added"
        elif not in_hunk and line.startswith("deleted file mode "):
            status_hint = "removed"
        elif not in_hunk and line.startswith("rename from "):
            old_path = _path(_git_path_token(line[len("rename from "):])) or False
            if old_path is False:
                return None, "patch_provenance_invalid"
        elif not in_hunk and line.startswith("rename to "):
            new_path = _path(_git_path_token(line[len("rename to "):])) or False
            if new_path is False:
                return None, "patch_provenance_invalid"
        elif not in_hunk and (line.startswith("GIT binary patch") or line.startswith("Binary files ")):
            saw_binary = True
            file_binary = True
        elif not in_hunk and line.startswith("--- "):
            saw_file_marker = True
            file_marker = True
            old_path = _header_path(line[4:], "a/")
        elif not in_hunk and line.startswith("+++ "):
            saw_file_marker = True
            file_marker = True
            new_path = _header_path(line[4:], "b/")
            if old_path is False or new_path is False or (old_path is None and new_path is None):
                return None, "patch_provenance_invalid"
            try:
                record_file()
            except ValueError:
                return None, "patch_provenance_invalid"
        elif not in_hunk and line.startswith("@@"):
            match = _HUNK.match(line)
            if not match or not saw_diff or old_path is False or new_path is False:
                return None, "patch_provenance_invalid"
            old_remaining = int(match.group(1) or 1)
            new_remaining = int(match.group(2) or 1)
            saw_hunk = True
            file_hunk = True
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
        if _header_only_patch(text, sha):
            return {"changed_files": [], "content_review": "header_only_requires_commit_detail"}, "header_only_patch_requires_commit_detail"
        return None, "patch_provenance_invalid"
    try:
        finish_file()
    except ValueError:
        return None, "patch_provenance_invalid"
    if missing_hunk:
        return {"changed_files": files, "content_review": "not_inspected"}, "patch_has_no_text_hunks"
    if not saw_hunk:
        if saw_binary:
            return {"changed_files": files, "content_review": "not_inspected"}, "binary_patch_not_inspected"
        if saw_file_marker:
            return {"changed_files": files, "content_review": "not_inspected"}, "patch_has_no_text_hunks"
        return {"changed_files": files, "content_review": "metadata_only"}, None
    signal_set, sensitive, limit_reached, structure_incomplete, media_skipped = _review_changed_lines(changed_lines)
    signals = sorted(signal_set)
    if sensitive and patch_requires_material_hold(signals):
        return {"changed_files": files, "content_review": "stopped_sensitive_candidate",
                "signal_codes": signals}, None
    if saw_binary:
        return {"changed_files": files, "content_review": "not_inspected"}, "binary_patch_not_inspected"
    if limit_reached:
        return {"changed_files": files, "content_review": "stopped_analysis_limit",
                "signal_codes": signals}, "patch_analysis_limit_reached"
    if structure_incomplete:
        return {"changed_files": files, "content_review": "text_reviewed_structure_pending",
                "signal_codes": signals,
                "pending_reviews": ["inline_image_ocr_unexamined"] if media_skipped else []}, "patch_structure_parse_incomplete"
    if media_skipped:
        return {"changed_files": files, "content_review": "text_reviewed_media_pending",
                "signal_codes": signals}, "inline_image_ocr_unexamined"
    introduced, removed = set(), set()
    for line in changed_lines:
        target = introduced if line.startswith("+") else removed
        for match in _URL.findall(line[1:]):
            target.add(locator_store.put(scope_id, match.rstrip(".,);]")))
    return {"changed_files": files, "content_review": "value_free_signals_only",
            "signal_codes": signals, "sensitivity_candidate": sensitive,
            "literal_url_changes": {"introduced_locator_refs": sorted(introduced),
                                    "removed_locator_refs": sorted(removed)}}, None


def analyze_repository_patch(body, url, locator_store, scope_id, *, max_bytes=MAX_PATCH_BYTES):
    """Analyze captured patch bytes without fetching discovered references."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_PATCH_BYTES_HARD:
        raise ValueError("invalid_patch_byte_limit")
    profile = {"document_type": "repository_patch", "content": "NOT_INSPECTED",
               "analysis_complete": False, "pending_reviews": [],
               "limitations": ["observed_commit_only", "history_lineage_not_exhaustive",
                               "literal_urls_not_requested", "current_repository_state_not_measured"]}
    parsed = _patch_url_parts(url)
    if parsed is None:
        profile["pending_reviews"].append("patch_url_invalid")
        return profile
    if not isinstance(body, bytes) or len(body) > max_bytes:
        profile["pending_reviews"].append("patch_byte_limit_reached")
        return profile
    repository, sha = parsed
    summary, gap = _parse_patch(body, repository, sha, locator_store, scope_id)
    if summary:
        profile.update(summary)
        if summary.get("content_review") in {"value_free_signals_only", "metadata_only",
                                              "text_reviewed_structure_pending",
                                              "text_reviewed_media_pending"}:
            profile["text_analysis_complete"] = True
        if summary.get("sensitivity_candidate"):
            profile["content"] = "SENSITIVE_CANDIDATE"
        if summary.get("content_review") == "stopped_sensitive_candidate":
            profile["content"] = "SENSITIVE_CANDIDATE"
            profile["hold_repository_patch_lineage"] = True
            profile["pending_reviews"].append("sensitive_candidate_stop")
    if gap:
        profile["pending_reviews"].append(gap)
    elif summary and summary.get("content_review") in {"value_free_signals_only", "metadata_only"}:
        profile["analysis_complete"] = True
    return profile


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
