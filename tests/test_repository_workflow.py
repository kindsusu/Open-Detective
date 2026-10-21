"""Synthetic operator binding and repository coverage checks."""
import json
import tempfile
from pathlib import Path
import unittest
import uuid

from sudetect.audit import Case, init_case
from sudetect.policy import Scope
from sudetect.repository_workflow import (bind_repositories, preflight,
                                          repository_job_authorized, repository_status)


SLUG = "nebula-sales/guide"
OWNER = "operator:confirmed-ownership"


def commit_report(case, job, report, *, state="succeeded", attach=True):
    """Attach synthetic evidence using the same job/result-reference invariant."""
    reference = "fixture:" + uuid.uuid4().hex
    report = {"target_id": job["asset_ref"], **report}
    case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                           (reference, job["job_id"], json.dumps(report)))
    case.ledger.db.execute("UPDATE audit_jobs SET state=?,result_refs=? WHERE job_id=?",
                           (state, json.dumps([reference] if attach else []), job["job_id"]))
    case.ledger.db.commit()
    return reference


def manifest(*, ownership="confirmed", deployments=None):
    return {"schema_version": "1.0", "scope_id": "fixture", "expires_at": "2099-01-01T00:00:00Z",
            "repositories": [{"repository": SLUG, "branch": "main", "owner_ref": OWNER,
                "ownership_status": ownership,
                "pages": [{"page_url": "https://nebula-sales.github.io/guide/", "evidence_ref": "operator:page-link"}],
                "deployment_urls": deployments or []}]}


def scope(*, raw=True, patch=True, owner=OWNER):
    targets = [
        {"origin": "https://api.github.com", "owner": "Nebula", "ownership_evidence": owner,
         "path_prefixes": [f"/repos/{SLUG}/git/trees/", f"/repos/{SLUG}/commits"]},
    ]
    if raw:
        targets.append({"origin": "https://raw.githubusercontent.com", "owner": "Nebula",
                        "ownership_evidence": owner, "path_prefixes": [f"/{SLUG}/"]})
    if patch:
        targets.append({"origin": "https://github.com", "owner": "Nebula",
                        "ownership_evidence": owner, "path_prefixes": [f"/{SLUG}/commit/"]})
    targets.append({"origin": "https://nebula-sales.github.io", "owner": "Nebula",
                    "ownership_evidence": owner, "path_prefixes": ["/guide/"]})
    return Scope.from_dict({"policy_id": "synthetic", "expires_at": "2099-01-01T00:00:00Z", "targets": targets})


class RepositoryWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Nebula", "domains": ["seed.test"]}})

    def tearDown(self):
        self.temp.cleanup()

    def test_binding_requires_operator_owner_and_exact_pages_association(self):
        with Case(self.root) as case:
            incomplete = manifest()
            del incomplete["repositories"][0]["owner_ref"]
            with self.assertRaisesRegex(ValueError, "owner_evidence"):
                bind_repositories(case, incomplete, scope())
            incomplete = manifest()
            incomplete["repositories"][0]["pages"] = [{"page_url": "https://nebula-sales.github.io/guide/"}]
            with self.assertRaisesRegex(ValueError, "page_association"):
                bind_repositories(case, incomplete, scope())
            self.assertEqual(preflight(case, scope())["status"], "not_bound")

    def test_preflight_identifies_missing_raw_and_patch_grants(self):
        with Case(self.root) as case:
            result = bind_repositories(case, manifest(), scope(raw=False, patch=False))
            self.assertEqual(result["repositories"][0]["missing"], ["content", "patch"])
            self.assertFalse(result["ready"])
            self.assertEqual(preflight(case, scope())["status"], "ready")
            jobs = [job for job in case.queue.status()["jobs"] if job["job_type"].startswith("repository_")]
            self.assertEqual(len(jobs), 2)
            self.assertTrue(all(job["state"] == "ready" for job in jobs))
            self.assertEqual(bind_repositories(case, manifest(), scope())["status"], "ready")
            self.assertEqual(len([job for job in case.queue.status()["jobs"] if job["job_type"].startswith("repository_")]), 2)

    def test_investigation_binding_never_queues_as_owned(self):
        with Case(self.root) as case:
            result = bind_repositories(case, manifest(ownership="investigation"), scope())
            self.assertFalse(result["ready"])
            self.assertIn("confirm_repository_ownership", result["next_steps"])
            self.assertTrue(all(job["state"] == "blocked_input" for job in case.queue.status()["jobs"]
                                if job["job_type"].startswith("repository_")))

    def test_metadata_only_never_satisfies_content_or_patch(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            status = repository_status(case)
            row = status["repositories"][0]
            self.assertEqual(row["stages"]["content"]["state"], "not_scheduled")
            self.assertEqual(row["stages"]["patch"]["state"], "not_inspected")
            self.assertFalse(status["complete"])

    def test_one_of_two_required_files_remains_partial(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            tree_job = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "repository_tree")
            file_job = case.enqueue_url(f"https://raw.githubusercontent.com/{SLUG}/main/one.json",
                                        parent=tree_job["job_id"], scope=scope())
            commit_report(case, tree_job, {"status": "COMPLETE", "files_emitted": 2,
                "capture_complete": True, "analysis_complete": True, "gaps": []})
            file = next(job for job in case.queue.status()["jobs"] if job["job_id"] == file_job)
            commit_report(case, file, {"capture_complete": True, "analysis_complete": True, "gaps": []})
            content = repository_status(case)["repositories"][0]["stages"]["content"]
            self.assertEqual(content["files_required"], 2)
            self.assertEqual(content["files_captured_complete"], 1)
            self.assertEqual(content["state"], "partial")

    def test_later_committed_review_improves_file_analysis_without_parent_link(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            tree = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "repository_tree")
            file_id = case.enqueue_url(f"https://raw.githubusercontent.com/{SLUG}/main/one.json",
                                       parent=tree["job_id"], scope=scope())
            file = next(job for job in case.queue.status()["jobs"] if job["job_id"] == file_id)
            commit_report(case, tree, {"status": "COMPLETE", "files_emitted": 1,
                "capture_complete": True, "analysis_complete": True, "gaps": []})
            commit_report(case, file, {"capture_complete": True, "analysis_complete": False,
                "gaps": ["analysis_byte_limit"]})
            content = repository_status(case)["repositories"][0]["stages"]["content"]
            self.assertEqual(1, content["files_body_captured_complete"])
            self.assertEqual(0, content["files_captured_complete"])
            self.assertEqual("partial", content["state"])

            review_id = case.queue.enqueue("content_review", file["asset_ref"], scope_id=case.scope_id,
                                           dedupe_key="fixture:later-review")
            review = next(job for job in case.queue.status()["jobs"] if job["job_id"] == review_id)
            self.assertIsNone(review["parent_job_id"])
            commit_report(case, review, {"capture_complete": True, "analysis_complete": True, "gaps": []})
            content = repository_status(case)["repositories"][0]["stages"]["content"]
            self.assertEqual(1, content["files_body_captured_complete"])
            self.assertEqual(1, content["files_captured_complete"])
            self.assertEqual("evidenced_complete", content["state"])

            failed_id = case.queue.enqueue("content_review", file["asset_ref"], scope_id=case.scope_id,
                                           dedupe_key="fixture:later-failed", state="failed_terminal")
            content = repository_status(case)["repositories"][0]["stages"]["content"]
            self.assertEqual(1, content["files_body_captured_complete"])
            self.assertEqual(1, content["files_captured_complete"])
            self.assertEqual({"failed_terminal": 1}, content["file_job_states"])
            self.assertEqual("partial", content["state"])

    def test_uncommitted_review_cannot_inflate_content_counts(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            tree = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "repository_tree")
            file_id = case.enqueue_url(f"https://raw.githubusercontent.com/{SLUG}/main/one.json",
                                       parent=tree["job_id"], scope=scope())
            file = next(job for job in case.queue.status()["jobs"] if job["job_id"] == file_id)
            commit_report(case, tree, {"status": "COMPLETE", "files_emitted": 1,
                "capture_complete": True, "analysis_complete": True, "gaps": []})
            commit_report(case, file, {"capture_complete": False, "analysis_complete": False,
                "gaps": ["capture_incomplete"]})
            review_id = case.queue.enqueue("content_review", file["asset_ref"], scope_id=case.scope_id,
                                           dedupe_key="fixture:uncommitted")
            review = next(job for job in case.queue.status()["jobs"] if job["job_id"] == review_id)
            commit_report(case, review, {"capture_complete": True, "analysis_complete": True,
                                         "gaps": []}, attach=False)
            content = repository_status(case)["repositories"][0]["stages"]["content"]
            self.assertEqual(0, content["files_body_captured_complete"])
            self.assertEqual(0, content["files_captured_complete"])
            self.assertEqual({"result_missing": 1}, content["file_job_states"])
            self.assertEqual("partial", content["state"])

    def test_latest_blocked_inventory_keeps_earlier_partial_evidence(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            tree = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "repository_tree")
            commit_report(case, tree, {"status": "PARTIAL", "files_emitted": 3,
                "capture_complete": True, "analysis_complete": False, "gaps": ["repository_tree_incomplete"]})
            case.queue.enqueue("content_review", tree["asset_ref"], scope_id=case.scope_id,
                               dedupe_key="fixture:blocked-tree-review", state="blocked_input")
            inventory = repository_status(case)["repositories"][0]["stages"]["inventory"]
            self.assertEqual("blocked_input", inventory["state"])
            self.assertEqual(3, inventory["files_identified"])

    def test_conflicting_rebind_is_rejected(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            altered = manifest()
            altered["repositories"][0]["branch"] = "other"
            with self.assertRaisesRegex(ValueError, "binding_conflict"):
                bind_repositories(case, altered, scope())

    def test_patch_followup_uses_committed_latest_result(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            history = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "repository_history")
            commit_report(case, history, {"capture_complete": True, "analysis_complete": True,
                "commits_examined": 1, "gaps": ["history_window_not_exhaustive"]})
            patch_id = case.enqueue_url(f"https://github.com/{SLUG}/commit/{'a'*40}.patch",
                parent=history["job_id"], scope=scope(), job_type="repository_patch")
            job = next(j for j in case.queue.status()["jobs"] if j["job_id"] == patch_id)
            commit_report(case, job, {"capture_complete": False, "analysis_complete": False,
                                     "gaps": ["capture_incomplete"]})
            review_id = case.queue.enqueue("content_review", job["asset_ref"], scope_id=case.scope_id,
                dedupe_key="fixture:patch-followup")
            review = next(j for j in case.queue.status()["jobs"] if j["job_id"] == review_id)
            commit_report(case, review, {"capture_complete": True, "analysis_complete": True, "gaps": []})
            stage = repository_status(case)["repositories"][0]["stages"]["patch"]
            self.assertEqual(1, stage["patches_captured_complete"])
            self.assertEqual("evidenced_complete", stage["state"])
            case.queue.enqueue("content_review", job["asset_ref"], scope_id=case.scope_id,
                dedupe_key="fixture:patch-failed", state="failed_terminal")
            stage = repository_status(case)["repositories"][0]["stages"]["patch"]
            self.assertEqual("partial", stage["state"])

    def test_empty_review_supersedes_only_older_lineage_hold(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            history = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "repository_history")
            commit_report(case, history, {"capture_complete": True, "analysis_complete": True,
                "commits_examined": 1, "gaps": ["history_window_not_exhaustive"]})
            patch_id = case.enqueue_url(f"https://github.com/{SLUG}/commit/{'a'*40}.patch",
                parent=history["job_id"], scope=scope(), job_type="repository_patch")
            patch = next(j for j in case.queue.status()["jobs"] if j["job_id"] == patch_id)
            review_id = case.queue.enqueue("content_review", patch["asset_ref"], scope_id=case.scope_id,
                dedupe_key="fixture:empty-derived-review")
            blocked_id = case.queue.enqueue("content_review", patch["asset_ref"], scope_id=case.scope_id,
                dedupe_key="fixture:older-lineage-hold", state="blocked_input",
                checkpoint={"reason_codes": ["SENSITIVE_PATCH_LINEAGE_REVIEW"]})
            review = next(j for j in case.queue.status()["jobs"] if j["job_id"] == review_id)
            reference = commit_report(case, review, {"capture_complete": True, "analysis_complete": True,
                "gaps": [], "content_review": "no_changed_files_verified",
                "observation_kind": "derived_review",
                "empty_patch_review_basis": "exact_commit_detail_zero_file_list"})
            with case.ledger.db:
                case.ledger._event("AUDIT_RESULT", review_id, {"result_ref": reference})
            self.assertEqual(blocked_id, [j for j in case.queue.status()["jobs"]
                if j["asset_ref"] == patch["asset_ref"]][-1]["job_id"])
            stage = repository_status(case)["repositories"][0]["stages"]["patch"]
            self.assertEqual(1, stage["patches_captured_complete"])
            self.assertEqual(1, stage["patches_empty_verified"])
            self.assertEqual("evidenced_complete", stage["state"])
            case.queue.enqueue("content_review", patch["asset_ref"], scope_id=case.scope_id,
                dedupe_key="fixture:newer-lineage-hold", state="blocked_input",
                checkpoint={"reason_codes": ["SENSITIVE_PATCH_LINEAGE_REVIEW"]})
            stage = repository_status(case)["repositories"][0]["stages"]["patch"]
            self.assertEqual("partial", stage["state"])

    def test_expiry_renewal_and_bound_url_guard(self):
        with Case(self.root) as case:
            first = manifest()
            first["expires_at"] = "2098-01-01T00:00:00Z"
            bind_repositories(case, first, scope())
            raw = f"https://raw.githubusercontent.com/{SLUG}/main/data.json"
            self.assertTrue(repository_job_authorized(case, raw, scope()))
            self.assertFalse(repository_job_authorized(case, raw, scope(owner="other:owner")))
            self.assertIsNone(repository_job_authorized(case, "https://unrelated.test/", scope()))
            bind_repositories(case, manifest(), scope())
            event_count = case.ledger.db.execute("SELECT COUNT(*) FROM events WHERE event_type='AUDIT_REPOSITORY_BINDING_RENEWED'").fetchone()[0]
            self.assertEqual(event_count, 1)

    def test_all_selected_stages_can_be_evidenced_complete(self):
        with Case(self.root) as case:
            bind_repositories(case, manifest(), scope())
            jobs = case.queue.status()["jobs"]
            tree = next(job for job in jobs if job["job_type"] == "repository_tree")
            history = next(job for job in jobs if job["job_type"] == "repository_history")
            page_ref = case.locators.put(case.scope_id, "https://nebula-sales.github.io/guide/")
            deployment = next(job for job in jobs if job["job_type"] == "capture" and job["asset_ref"] == page_ref)
            file_id = case.enqueue_url(f"https://raw.githubusercontent.com/{SLUG}/main/one.json",
                                       parent=tree["job_id"], scope=scope())
            patch_id = case.enqueue_url(f"https://github.com/{SLUG}/commit/{'a'*40}.patch",
                                        parent=history["job_id"], scope=scope(), job_type="repository_patch")
            ids = (tree["job_id"], history["job_id"], deployment["job_id"], file_id, patch_id)
            for job in (j for j in case.queue.status()["jobs"] if j["job_id"] in ids):
                base = {"capture_complete": True, "analysis_complete": True, "gaps": []}
                if job["job_id"] == tree["job_id"]:
                    base.update(status="COMPLETE", files_emitted=1)
                if job["job_id"] == history["job_id"]:
                    base.update(commits_examined=1, gaps=["history_window_not_exhaustive"])
                commit_report(case, job, base)
            status = repository_status(case)
            self.assertTrue(status["complete"], status)
            self.assertFalse(status["repositories"][0]["stages"]["history"]["window_exhaustive"])


if __name__ == "__main__":
    unittest.main()
