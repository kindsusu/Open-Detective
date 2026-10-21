"""Value-free fallback inventory for an observed GitHub commit.

The commit-detail API can identify changed files when GitHub's .patch endpoint
is unavailable. Its inline patch field is deliberately not treated as a full
diff. All returned file and pagination URLs are constructed or validated here.
"""
from __future__ import annotations

from collections import Counter
import json
import re
from urllib.parse import parse_qs, quote, urlsplit

from .github_discovery import _repo_slug
from .github_history import _patch_url_parts
from .inventory import _github_tree_file

MAX_COMMIT_DETAIL_BYTES = 8 * 1024 * 1024
MAX_COMMIT_DETAIL_BYTES_HARD = 32 * 1024 * 1024
MAX_COMMIT_FILES = 3000
FILES_PER_PAGE = 100
MAX_PAGES = MAX_COMMIT_FILES // FILES_PER_PAGE
_DETAIL_PATH = re.compile(r"/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commits/([0-9a-fA-F]{40})\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_STATUSES = frozenset({"added", "removed", "modified", "renamed", "copied", "changed"})


def _detail_parts(url: str):
    try:
        parts = urlsplit(url)
        match = _DETAIL_PATH.fullmatch(parts.path)
        query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
        if (parts.scheme != "https" or parts.netloc != "api.github.com" or parts.fragment
                or not match or set(query) != {"per_page", "page"}
                or query["per_page"] != [str(FILES_PER_PAGE)] or len(query["page"]) != 1
                or not re.fullmatch(r"(?:[1-9]|[12][0-9]|30)", query["page"][0])):
            return None
        owner, repo, sha = match.groups()
        if _repo_slug(owner, repo) != f"{owner}/{repo}":
            return None
        return f"{owner}/{repo}", sha.lower(), int(query["page"][0])
    except (TypeError, ValueError):
        return None


def commit_detail_url(patch_url: str) -> str | None:
    """Derive the first API page only from an exact observed commit .patch URL."""
    parts = _patch_url_parts(patch_url)
    if parts is None:
        return None
    slug, sha = parts
    owner, repo = slug.split("/", 1)
    if _repo_slug(owner, repo) != slug:
        return None
    return (f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/"
            f"commits/{sha.lower()}?per_page={FILES_PER_PAGE}&page=1")


def _next_detail_url(link_header: str | None, slug: str, sha: str, page: int):
    if not link_header:
        return None, False
    if not isinstance(link_header, str) or len(link_header) > 8192:
        return None, True
    candidates = []
    for item in link_header.split(","):
        match = re.fullmatch(r'\s*<([^<>]+)>\s*;\s*rel="?([A-Za-z]+)"?(?:\s*;[^,]*)?\s*', item)
        if match and match.group(2).casefold() == "next":
            candidates.append(match.group(1))
        elif not match and re.search(r"\bnext\b", item, re.I):
            return None, True
    if not candidates:
        return None, False
    if len(candidates) != 1 or page >= MAX_PAGES:
        return None, True
    target = _detail_parts(candidates[0])
    if target != (slug, sha, page + 1):
        return None, True
    return candidates[0], False


def _raw_url(slug: str, sha: str, path: str) -> str | None:
    parsed = _github_tree_file(path)
    if parsed is None:
        return None
    owner, repo = slug.split("/", 1)
    return (f"https://raw.githubusercontent.com/{quote(owner, safe='')}/{quote(repo, safe='')}/"
            f"{sha}/{parsed[0]}")


def analyze_commit_detail(body: bytes, url: str, *, link_header: str | None = None,
                          max_bytes: int = MAX_COMMIT_DETAIL_BYTES) -> tuple[dict, list[tuple[str, str]]]:
    """Return safe metadata and exact raw-file refs; never assert patch review.

    The caller owns transport scope/budget, commits the report, and queues refs.
    Missing/invalid pagination evidence and inline hunks remain explicit gaps.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_COMMIT_DETAIL_BYTES_HARD:
        raise ValueError("invalid_commit_detail_byte_limit")
    report = {"document_type": "repository_commit_detail", "content": "NOT_INSPECTED",
              "analysis_complete": False, "file_list_page_complete": False,
              "patch_content_review": "not_inspected", "files_observed": 0,
              "empty_diff_verified": False,
              "file_urls_emitted": 0, "status_counts": {}, "parent_count": None,
              "first_parent_observed": False, "inline_patch_missing": 0,
              "pending_reviews": ["commit_patch_hunks_not_reviewed"],
              "limitations": ["commit_detail_file_fallback_only", "observed_commit_only",
                              "historical_lineage_not_exhaustive"]}
    refs: list[tuple[str, str]] = []
    parts = _detail_parts(url)
    if parts is None:
        report["pending_reviews"].append("commit_detail_url_invalid")
        return report, refs
    if not isinstance(body, bytes) or len(body) > max_bytes:
        report["pending_reviews"].append("commit_detail_byte_limit_reached")
        return report, refs
    slug, sha, page = parts
    report["page"] = page
    try:
        payload = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, RecursionError):
        report["pending_reviews"].append("commit_detail_parse_failed")
        return report, refs
    if (not isinstance(payload, dict) or not isinstance(payload.get("sha"), str)
            or payload["sha"].lower() != sha or not isinstance(payload.get("parents"), list)
            or len(payload["parents"]) > 20 or not isinstance(payload.get("files"), list)
            or len(payload["files"]) > FILES_PER_PAGE):
        report["pending_reviews"].append("commit_detail_provenance_invalid")
        return report, refs
    parents = payload["parents"]
    if any(not isinstance(parent, dict) or not isinstance(parent.get("sha"), str)
           or _SHA.fullmatch(parent["sha"]) is None for parent in parents):
        report["pending_reviews"].append("commit_parent_provenance_invalid")
        return report, refs
    parent_sha = parents[0]["sha"].lower() if parents else None
    report["parent_count"] = len(parents)
    report["first_parent_observed"] = bool(parent_sha)
    if len(parents) > 1:
        report["pending_reviews"].append("merge_parent_lineage_unreviewed")
    statuses = Counter()
    seen = set()
    invalid_rows = 0
    for row in payload["files"]:
        if not isinstance(row, dict):
            invalid_rows += 1
            continue
        status, name, previous = row.get("status"), row.get("filename"), row.get("previous_filename")
        if (status not in _STATUSES or _github_tree_file(name) is None
                or (previous is not None and _github_tree_file(previous) is None)
                or (status in {"renamed", "copied"} and previous is None)
                or name in seen):
            invalid_rows += 1
            continue
        seen.add(name)
        statuses[status] += 1
        report["inline_patch_missing"] += not isinstance(row.get("patch"), str)
        if status != "removed":
            current = _raw_url(slug, sha, name)
            if current is not None:
                refs.append(("repository_file", current))
        if status != "added":
            if parent_sha:
                before = _raw_url(slug, parent_sha, previous if status in {"renamed", "copied"} else name)
                if before is not None:
                    refs.append(("repository_file", before))
            else:
                report["pending_reviews"].append("previous_revision_unavailable")
    report["files_observed"] = len(payload["files"])
    report["status_counts"] = dict(sorted(statuses.items()))
    if invalid_rows:
        report["pending_reviews"].append("commit_file_metadata_invalid")
        report["invalid_file_rows"] = invalid_rows
    next_url, invalid_next = _next_detail_url(link_header, slug, sha, page)
    if invalid_next:
        report["pending_reviews"].append("commit_pagination_link_invalid")
    elif next_url:
        refs.append(("repository_commit_detail", next_url))
    elif len(payload["files"]) == FILES_PER_PAGE:
        report["pending_reviews"].append("commit_pagination_unverified")
    report["next_page_observed"] = bool(next_url)
    report["file_list_page_complete"] = not invalid_rows and not invalid_next
    stats = payload.get("stats")
    stats_consistent = (stats is None or isinstance(stats, dict) and
                        all(type(stats.get(key)) is int and stats[key] == 0
                            for key in ("total", "additions", "deletions")))
    if (page == 1 and not payload["files"] and stats_consistent and len(parents) <= 1
            and not next_url and not invalid_next and not invalid_rows):
        report["empty_diff_verified"] = True
        report["patch_content_review"] = "no_changed_files_verified"
        report["analysis_complete"] = True
        report["pending_reviews"].remove("commit_patch_hunks_not_reviewed")
    report["file_urls_emitted"] = sum(kind == "repository_file" for kind, _ in refs)
    report["pending_reviews"] = sorted(set(report["pending_reviews"]))
    return report, refs
