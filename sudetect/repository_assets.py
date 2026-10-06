"""Offline, bounded GitHub repository tree candidate extraction.

The caller fetches a tree under its own scope and request budget, and must put
the returned exact raw URLs into a private locator store before persisting work.
Neither function performs network access or establishes target ownership.
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .github_discovery import _repo_slug
from .inventory import _github_tree_file

_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,100}\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_BLOB_SHA = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}\Z")
_TREE_PATH = re.compile(r"/repos/([^/]+)/([^/]+)/git/trees/([^/]+)\Z")
_MAX_TREE_BYTES = 8 * 1024 * 1024


def _branch_valid(value: object) -> bool:
    return (isinstance(value, str) and _BRANCH.fullmatch(value) is not None
            and ".." not in value and not value.startswith("/")
            and not value.endswith("/") and "//" not in value)


def tree_url(candidate: dict) -> str | None:
    """Build one GitHub tree API URL from observed repository revision metadata."""
    if not isinstance(candidate, Mapping):
        return None
    slug = candidate.get("slug")
    revision = candidate.get("source_revision")
    if not isinstance(slug, str) or not isinstance(revision, Mapping) or slug.count("/") != 1:
        return None
    owner, repo = slug.split("/", 1)
    if _repo_slug(owner, repo) != slug:
        return None
    value, kind = revision.get("value"), revision.get("kind")
    if kind == "commit":
        if not isinstance(value, str) or _SHA.fullmatch(value) is None:
            return None
    elif kind == "branch_mutable":
        if not _branch_valid(value):
            return None
    else:
        return None
    return (f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/"
            f"git/trees/{quote(value, safe='')}?recursive=1")


def _tree_parts(value: str) -> tuple[str, str, str] | None:
    try:
        parsed = urlsplit(value)
        match = _TREE_PATH.fullmatch(parsed.path)
        if (parsed.scheme != "https" or parsed.hostname != "api.github.com"
                or parsed.port not in (None, 443) or parsed.username or parsed.password
                or parsed.fragment or parse_qs(parsed.query) != {"recursive": ["1"]}
                or match is None):
            return None
        owner, repo, encoded_revision = match.groups()
        owner, repo, revision = unquote(owner), unquote(repo), unquote(encoded_revision)
        if _repo_slug(owner, repo) != f"{owner}/{repo}":
            return None
        if not (_SHA.fullmatch(revision) or _branch_valid(revision)):
            return None
        return owner, repo, revision
    except (TypeError, ValueError):
        return None


def analyze_tree(body: bytes, tree_url: str, max_files: int = 1000) -> tuple[dict[str, Any], list[str]]:
    """Return path-free evidence and transient exact raw file URLs.

    Only explicit Git tree blob entries with a valid object SHA are eligible.
    The positional ``file_index`` in the report maps to the returned URL list;
    neither paths nor a reversible unkeyed path digest enter the report.
    """
    if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 10_000:
        raise ValueError("invalid file limit")
    parts = _tree_parts(tree_url)
    report: dict[str, Any] = {"version": 1, "status": "FAILED", "error_code": None,
        "tree_entries": 0, "blob_entries": 0, "files_emitted": 0,
        "rejected_blobs": 0, "unsupported_extensions": 0,
        "provider_truncated": False, "file_limit_reached": False,
        "revision_reference": "unverified", "files": [],
        "limitations": ["public_metadata_only", "ownership_pending", "file_urls_not_fetched"]}
    if parts is None:
        report["error_code"] = "TREE_URL_INVALID"
        return report, []
    owner, repo, revision = parts
    # A SHA-shaped URL alone does not prove its provenance: a branch can also
    # have 40 hex characters. The source candidate carries the authoritative
    # commit-vs-branch distinction.
    report["revision_reference"] = "sha_shaped_unverified" if _SHA.fullmatch(revision) else "branch_mutable"
    if not isinstance(body, bytes) or len(body) > _MAX_TREE_BYTES:
        report["error_code"] = "BYTE_LIMIT_EXCEEDED"
        return report, []
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        report["error_code"] = "BYTE_PARSE_FAILED"
        return report, []
    if (not isinstance(payload, Mapping) or not isinstance(payload.get("tree"), list)
            or not isinstance(payload.get("truncated", False), bool)):
        report["error_code"] = "RESPONSE_SHAPE_MISMATCH"
        return report, []
    report["provider_truncated"] = payload.get("truncated") is True
    seen: set[str] = set()
    exact_urls: list[str] = []
    for entry in payload["tree"]:
        report["tree_entries"] += 1
        if not isinstance(entry, Mapping):
            report["rejected_blobs"] += 1
            continue
        if entry.get("type") != "blob":
            continue
        report["blob_entries"] += 1
        parsed_file = _github_tree_file(entry.get("path"))
        blob_sha = entry.get("sha")
        size = entry.get("size")
        if (parsed_file is None or not isinstance(blob_sha, str)
                or _BLOB_SHA.fullmatch(blob_sha) is None
                or (size is not None and (type(size) is not int or size < 0))):
            report["rejected_blobs"] += 1
            continue
        encoded_path, extension, kind = parsed_file
        if encoded_path in seen:
            report["rejected_blobs"] += 1
            continue
        seen.add(encoded_path)
        if kind == "other":
            report["unsupported_extensions"] += 1
        if len(exact_urls) >= max_files:
            report["file_limit_reached"] = True
            continue
        exact_urls.append(
            f"https://raw.githubusercontent.com/{quote(owner, safe='')}/{quote(repo, safe='')}/"
            f"{quote(revision, safe='')}/{encoded_path}")
        report["files"].append({"file_index": len(exact_urls) - 1,
            "candidate_kind": kind, "extension": extension,
            "byte_size": size, "git_object_sha": blob_sha.lower()})
    report["files_emitted"] = len(exact_urls)
    if report["provider_truncated"]:
        report["error_code"] = "TREE_TRUNCATED"
    elif report["file_limit_reached"]:
        report["error_code"] = "FILE_LIMIT_REACHED"
    elif report["rejected_blobs"]:
        report["error_code"] = "RECORDS_REJECTED"
    report["status"] = "PARTIAL" if report["error_code"] else "COMPLETE"
    return report, exact_urls
