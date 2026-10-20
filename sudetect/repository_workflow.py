"""Operator-bound repository verification over the common audit case.

Bindings are private case inputs. This module never discovers ownership, widens a
scope, or fetches a URL. The existing audit queue performs authorized captures.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote, urlsplit

from .policy import PolicyError, Scope, _normalize_url
from .repository_assets import tree_url
from .repository_history import history_url

_SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,100}\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_BINDINGS = "repository-bindings.json"


def _time(value):
    if not isinstance(value, str):
        raise ValueError("repository_manifest_expiry_required")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("repository_manifest_expiry_invalid") from None
    if instant.tzinfo is None or instant.utcoffset() is None or instant <= datetime.now(timezone.utc):
        raise ValueError("repository_manifest_expired")
    return instant


def _repository(row):
    if not isinstance(row, dict) or set(row) - {"repository", "branch", "owner_ref", "pages", "deployment_urls", "ownership_status"}:
        raise ValueError("repository_manifest_entry_invalid")
    slug, branch, owner_ref = row.get("repository"), row.get("branch"), row.get("owner_ref")
    if not isinstance(slug, str) or not _SLUG.fullmatch(slug) or any(part in {".", ".."} for part in slug.split("/")):
        raise ValueError("repository_slug_invalid")
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch) or any(part in {"", ".", ".."} for part in branch.split("/")) or ".." in branch:
        raise ValueError("repository_branch_invalid")
    if not isinstance(owner_ref, str) or not _REF.fullmatch(owner_ref):
        raise ValueError("repository_owner_evidence_required")
    ownership_status = row.get("ownership_status", "confirmed")
    if ownership_status not in {"confirmed", "investigation"}:
        raise ValueError("repository_ownership_status_invalid")
    pages = row.get("pages", [])
    if not isinstance(pages, list):
        raise ValueError("repository_pages_invalid")
    clean_pages = []
    for association in pages:
        if not isinstance(association, dict) or set(association) != {"page_url", "evidence_ref"}:
            raise ValueError("repository_page_association_invalid")
        page_url, evidence = association["page_url"], association["evidence_ref"]
        if not isinstance(evidence, str) or not _REF.fullmatch(evidence):
            raise ValueError("repository_page_evidence_required")
        try:
            page_url, _ = _normalize_url(page_url)
        except PolicyError:
            raise ValueError("repository_page_url_invalid") from None
        clean_pages.append({"page_url": page_url, "evidence_ref": evidence})
    deployments = row.get("deployment_urls", [])
    if not isinstance(deployments, list):
        raise ValueError("repository_deployments_invalid")
    clean_deployments = []
    for url in deployments:
        try:
            clean_deployments.append(_normalize_url(url)[0])
        except PolicyError:
            raise ValueError("repository_deployment_url_invalid") from None
    if len(set(clean_deployments)) != len(clean_deployments) or len({p["page_url"] for p in clean_pages}) != len(clean_pages):
        raise ValueError("repository_manifest_duplicate_association")
    return {"repository": slug, "branch": branch, "owner_ref": owner_ref,
            "ownership_status": ownership_status, "pages": clean_pages,
            "deployment_urls": clean_deployments}


def _validate_manifest(case, manifest, *, require_current=True):
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "scope_id", "expires_at", "repositories"}:
        raise ValueError("repository_manifest_invalid")
    if manifest["schema_version"] != "1.0" or manifest["scope_id"] != case.scope_id:
        raise ValueError("repository_manifest_case_mismatch")
    if require_current:
        _time(manifest["expires_at"])
    elif not isinstance(manifest["expires_at"], str):
        raise ValueError("repository_manifest_expiry_invalid")
    rows = manifest["repositories"]
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise ValueError("repository_manifest_empty_or_excessive")
    clean = [_repository(row) for row in rows]
    if len({row["repository"] for row in clean}) != len(clean):
        raise ValueError("repository_manifest_duplicate_repository")
    return {"schema_version": "1.0", "scope_id": case.scope_id,
            "expires_at": manifest["expires_at"], "repositories": clean}


def _load(case):
    path = case.root / _BINDINGS
    if not path.exists():
        return None
    from .audit import read_json
    return _validate_manifest(case, read_json(path), require_current=False)


def _required(row):
    slug, branch = row["repository"], row["branch"]
    owner, repo = slug.split("/")
    candidate = {"slug": slug, "source_revision": {"kind": "branch_mutable", "value": branch}}
    return {"inventory": tree_url(candidate), "history": history_url(candidate),
            "content_prefix": f"https://raw.githubusercontent.com/{slug}/",
            "patch_prefix": f"https://github.com/{slug}/commit/",
            "deployments": list(dict.fromkeys(row["deployment_urls"] + [page["page_url"] for page in row["pages"]]))}


def _authorized_prefix(scope, url, owner_ref):
    """Require an exact prefix grant carrying this binding's owner evidence."""
    if not isinstance(scope, Scope) or scope.expires_at <= datetime.now(timezone.utc):
        return False
    parts = urlsplit(url)
    origin, path = f"{parts.scheme}://{parts.netloc}", parts.path
    return any(target.origin == origin and target.ownership_evidence == owner_ref
               and path in target.path_prefixes for target in scope.targets)


def _authorized_url(scope, url, owner_ref):
    if not isinstance(scope, Scope):
        return False
    try:
        scope.authorize(url)
    except PolicyError:
        return False
    parts = urlsplit(url)
    origin, path = f"{parts.scheme}://{parts.netloc}", parts.path
    return any(target.origin == origin and target.ownership_evidence == owner_ref
               and any(prefix == path or path.startswith(prefix.rstrip("/") + "/")
                       for prefix in target.path_prefixes) for target in scope.targets)


def preflight(case, scope):
    """Report exact missing grants before an audit run; never modify scope."""
    manifest = _load(case)
    if manifest is None:
        return {"status": "not_bound", "ready": False, "repositories": [],
                "next_steps": ["bind_operator_repository_manifest"]}
    try:
        expired = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)
    except ValueError:
        expired = True
    rows = []
    for row in manifest["repositories"]:
        needed = _required(row)
        owner_ref = row["owner_ref"]
        checks = {"inventory": _authorized_prefix(scope, f"https://api.github.com/repos/{row['repository']}/git/trees/", owner_ref),
                  "history": _authorized_prefix(scope, f"https://api.github.com/repos/{row['repository']}/commits", owner_ref),
                  "content": _authorized_prefix(scope, needed["content_prefix"], owner_ref),
                  "patch": _authorized_prefix(scope, needed["patch_prefix"], owner_ref),
                  "deployments": all(_authorized_prefix(scope, url.split("?", 1)[0], owner_ref)
                                     and _authorized_url(scope, url, owner_ref)
                                     for url in needed["deployments"])}
        if expired or row["ownership_status"] != "confirmed":
            checks = dict.fromkeys(checks, False)
        missing = [name for name, allowed in checks.items() if not allowed]
        rows.append({"repo_ref": _repo_ref(row["repository"]), "ownership_status": row["ownership_status"],
                     "required_grants": {"inventory": needed["inventory"], "history": needed["history"],
                         "content_prefix": needed["content_prefix"], "patch_prefix": needed["patch_prefix"],
                         "deployment_urls": needed["deployments"]},
                     "authorized": checks, "missing": missing,
                     "next_steps": ["renew_repository_manifest"] if expired else
                         ["confirm_repository_ownership"] if row["ownership_status"] != "confirmed" else
                         [f"grant_exact_{name}_scope" for name in missing]})
    return {"status": "ready" if all(not row["missing"] for row in rows) else "missing_authorization",
            "ready": all(not row["missing"] for row in rows), "repositories": rows,
            "next_steps": sorted({step for row in rows for step in row["next_steps"]})}


def _repo_ref(slug):
    return "repo:" + hashlib.sha256(slug.encode("utf-8")).hexdigest()[:24]


def repository_job_authorized(case, url, scope):
    """Guard an exact bound repository URL. Return None for unrelated URLs.

    This check supplements Scope.authorize in the coordinator's unblock and
    capture paths. A broad host grant cannot replace binding ownership evidence.
    """
    manifest = _load(case)
    if manifest is None:
        return None
    try:
        normalized, _ = _normalize_url(url)
    except PolicyError:
        return False
    applicable = []
    for row in manifest["repositories"]:
        required = _required(row)
        slug = row["repository"]
        prefixes = (
            (f"https://api.github.com/repos/{slug}/git/trees/", "inventory"),
            (f"https://api.github.com/repos/{slug}/commits", "history"),
            (required["content_prefix"], "content"),
            (required["patch_prefix"], "patch"),
        )
        matched = next(((prefix, stage) for prefix, stage in prefixes
                        if normalized == prefix or normalized.startswith(prefix)), None)
        if matched is None:
            matched = next(((target.split("?", 1)[0], "deployment")
                            for target in required["deployments"]
                            if normalized == target or normalized.startswith(target.split("?", 1)[0].rstrip("/") + "/")), None)
        if matched is not None:
            applicable.append((row, matched[0], matched[1]))
    if not applicable:
        return None
    try:
        current = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00")) > datetime.now(timezone.utc)
    except ValueError:
        current = False
    if not current:
        return False
    return all(row["ownership_status"] == "confirmed"
               and _authorized_prefix(scope, prefix, row["owner_ref"])
               and _authorized_url(scope, normalized, row["owner_ref"])
               for row, prefix, _ in applicable)


def bind_repositories(case, manifest, scope=None):
    """Persist one immutable operator selection, then enqueue its explicit work."""
    from .audit import write_json
    clean = _validate_manifest(case, manifest)
    existing = _load(case)
    renewed = False
    if existing is not None and existing != clean:
        previous = {**existing, "expires_at": clean["expires_at"]}
        old_expiry = datetime.fromisoformat(existing["expires_at"].replace("Z", "+00:00"))
        new_expiry = datetime.fromisoformat(clean["expires_at"].replace("Z", "+00:00"))
        if previous != clean or new_expiry <= old_expiry:
            raise ValueError("repository_binding_conflict")
        renewed = True
    if existing is None or renewed:
        write_json(case.root / _BINDINGS, clean)
        if renewed:
            case.ledger._event("AUDIT_REPOSITORY_BINDING_RENEWED", case.meta["case_id"],
                               {"repository_count": len(clean["repositories"]),
                                "previous_expires_at": existing["expires_at"],
                                "expires_at": clean["expires_at"]})
            case.ledger.db.commit()
    for row in clean["repositories"]:
        required = _required(row)
        evidence = row["owner_ref"]
        # Ownership under investigation is visible but cannot authorize capture.
        active_scope = scope if row["ownership_status"] == "confirmed" else None
        for kind, url in (("repository_tree", required["inventory"]),
                          ("repository_history", required["history"]),
                          *(("capture", target) for target in required["deployments"])):
            prefix = (f"https://api.github.com/repos/{row['repository']}/git/trees/"
                      if kind == "repository_tree" else
                      f"https://api.github.com/repos/{row['repository']}/commits"
                      if kind == "repository_history" else url.split("?", 1)[0])
            if _authorized_prefix(active_scope, prefix, evidence) and _authorized_url(active_scope, url, evidence):
                case.enqueue_url(url, scope=active_scope, job_type=kind, evidence=evidence)
            else:
                ref = case.locators.put(case.scope_id, url)
                case.queue.enqueue(kind, ref, scope_id=case.scope_id, state="blocked_input",
                                   origin_evidence_ref=evidence, dedupe_key=f"{kind}:{ref}",
                                   checkpoint={"reason_codes": ["REPOSITORY_OWNERSHIP_UNCONFIRMED" if
                                       row["ownership_status"] != "confirmed" else "EXACT_REPOSITORY_SCOPE_REQUIRED"]})
    return preflight(case, scope)


def _job_result(case, jobs, url):
    ref = case.locators.put(case.scope_id, url)
    relevant = [job for job in jobs if job["asset_ref"] == ref]
    if not relevant:
        return "not_scheduled", None
    job = relevant[-1]
    if job["state"] != "succeeded":
        return job["state"], None
    result = _verified_result(case, job)
    return ("succeeded", result) if result else ("result_missing", None)


def _verified_result(case, job):
    prior = case.prior_result(job)
    if not prior or prior[0] not in job["result_refs"]:
        return None
    report = prior[1]
    return report if report.get("target_id") == job["asset_ref"] else None


def _capture_state(result, *, metadata=False):
    if result is None:
        return "incomplete"
    if not result.get("capture_complete") or not result.get("analysis_complete"):
        return "partial"
    if metadata:
        profile = result.get("status")
        if profile != "COMPLETE" or result.get("gaps"):
            return "partial"
    elif result.get("gaps"):
        return "partial"
    return "evidenced_complete"


def _history_state(result):
    if result is None or not result.get("capture_complete") or not result.get("analysis_complete"):
        return "partial"
    # The five-commit window can be fully reviewed while history as a whole
    # remains explicitly unverified.
    gaps = set(result.get("gaps", []))
    return "evidenced_complete" if gaps <= {"history_window_not_exhaustive"} else "partial"


def repository_status(case):
    """Coverage for selected repositories only, with independent stage evidence."""
    manifest = _load(case)
    if manifest is None:
        return {"status": "not_bound", "complete": False, "repositories": [],
                "next_steps": ["bind_operator_repository_manifest"]}
    jobs = case.queue.status()["jobs"]
    rows = []
    for row in manifest["repositories"]:
        needed = _required(row)
        stages = {}
        state, report = _job_result(case, jobs, needed["inventory"])
        stages["inventory"] = {"state": _capture_state(report, metadata=True) if state == "succeeded" else state,
                               "files_identified": (report or {}).get("files_emitted", 0),
                               "provider_truncated": (report or {}).get("provider_truncated", False)}
        state, report = _job_result(case, jobs, needed["history"])
        stages["history"] = {"state": _history_state(report) if state == "succeeded" else state,
                             "commits_examined": (report or {}).get("commits_examined", 0),
                             "window_exhaustive": False}
        tree_ref = case.locators.put(case.scope_id, needed["inventory"])
        tree_job_ids = {job["job_id"] for job in jobs if job["asset_ref"] == tree_ref}
        file_jobs = [job for job in jobs if job["parent_job_id"] in tree_job_ids and job["job_type"] == "capture"]
        file_states = []
        for job in file_jobs:
            result = _verified_result(case, job) if job["state"] == "succeeded" else None
            file_states.append(_capture_state(result) if result else job["state"])
        expected = stages["inventory"]["files_identified"]
        file_complete = sum(value == "evidenced_complete" for value in file_states)
        inventory_state = stages["inventory"]["state"]
        content_state = ("evidenced_complete" if inventory_state == "evidenced_complete" and file_complete == expected
                         else "partial" if file_jobs else "blocked_or_pending" if inventory_state in
                         {"blocked_scope", "blocked_input", "failed_terminal", "retry_wait"} else "not_scheduled")
        stages["content"] = {"state": content_state,
                             "files_required": expected, "files_captured_complete": file_complete,
                             "files_scheduled": len(file_jobs)}
        history_ref = case.locators.put(case.scope_id, needed["history"])
        history_ids = {candidate["job_id"] for candidate in jobs if candidate["asset_ref"] == history_ref}
        snapshot_jobs = [job for job in jobs if job["job_type"] == "repository_tree" and job["asset_ref"] != tree_ref
                         and job["parent_job_id"] in history_ids]
        patch_jobs = [job for job in jobs if job["job_type"] == "repository_patch" and job["parent_job_id"] in history_ids]
        patch_complete = 0
        for job in patch_jobs:
            if job["state"] == "succeeded":
                result = _verified_result(case, job)
                if result and _capture_state(result) == "evidenced_complete":
                    patch_complete += 1
        expected_patches = stages["history"]["commits_examined"]
        stages["patch"] = {"state": "evidenced_complete" if expected_patches and patch_complete == expected_patches else
                           "partial" if patch_jobs else "blocked_or_pending" if stages["history"]["state"] in
                           {"blocked_scope", "blocked_input", "failed_terminal", "retry_wait"} else "not_inspected",
                           "patches_required": expected_patches, "patches_scheduled": len(patch_jobs),
                           "patches_captured_complete": patch_complete,
                           "snapshots_scheduled": len(snapshot_jobs), "history_window_exhaustive": False}
        deployments = [_job_result(case, jobs, url) for url in needed["deployments"]]
        complete_deployments = sum(state == "succeeded" and _capture_state(report) == "evidenced_complete" for state, report in deployments)
        stages["deployment"] = {"state": "not_evidenced" if not deployments else "evidenced_complete" if complete_deployments == len(deployments) else "partial" if complete_deployments else "blocked_or_pending",
                                "targets_required": len(deployments), "targets_complete": complete_deployments}
        next_steps = []
        if stages["inventory"]["state"] != "evidenced_complete":
            next_steps.append("capture_complete_repository_tree")
        if stages["content"]["state"] != "evidenced_complete":
            next_steps.append("capture_all_emitted_raw_files")
        if stages["history"]["state"] != "evidenced_complete":
            next_steps.append("inspect_bounded_commit_history")
        if stages["patch"]["state"] != "evidenced_complete":
            next_steps.append("inspect_authorized_commit_patches")
        if stages["deployment"]["state"] != "evidenced_complete":
            next_steps.append("declare_and_capture_deployments" if not deployments else "capture_declared_deployments")
        complete = all(stages[name]["state"] == "evidenced_complete" for name in
                       ("inventory", "content", "history", "patch", "deployment"))
        rows.append({"repo_ref": _repo_ref(row["repository"]), "ownership_status": row["ownership_status"],
                     "pages_associated": len(row["pages"]), "stages": stages,
                     "complete": complete, "next_steps": [] if complete else next_steps})
    all_complete = all(row["complete"] for row in rows)
    return {"status": "complete" if all_complete else "incomplete", "complete": all_complete, "repositories": rows,
            "next_steps": sorted({step for row in rows for step in row["next_steps"]}),
            "completion_definition": "selected_repositories_all_stages_evidenced"}
