"""Synthetic 503 commit-detail fallback in the common audit queue."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch as mock_patch

from sudetect.audit import Case, init_case, run_case, _verified_empty_detail
from sudetect.policy import Scope
from sudetect.repository_commit import commit_detail_url
from sudetect.repository_workflow import _capture_state, _latest_committed_report
from sudetect.transport import FetchResult

SHA = "a" * 40
PARENT = "b" * 40
PATCH = f"https://github.com/fixture/repo/commit/{SHA}.patch"
DETAIL = commit_detail_url(PATCH)


def scope():
    return Scope.from_dict({"policy_id": "fixture-fallback", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {"origin": "https://github.com", "owner": "fixture", "ownership_evidence": "fixture:owner",
             "path_prefixes": ["/fixture/repo/commit/"]},
            {"origin": "https://api.github.com", "owner": "fixture", "ownership_evidence": "fixture:owner",
             "path_prefixes": ["/repos/fixture/repo/commits/"]},
            {"origin": "https://raw.githubusercontent.com", "owner": "fixture",
             "ownership_evidence": "fixture:owner", "path_prefixes": ["/fixture/repo/"]},
        ], "max_bytes": 2 * 1024 * 1024})


def observed(url, active, *, status, body=b"", headers=None):
    active.authorize(url)
    active.budget.consume()
    return FetchResult({"observation_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat(), "policy_id": active.policy_id,
        "access": "BODY_SERVED" if status == 200 else "HTTP_ERROR", "capture_complete": True,
        "http_status": status, "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(),
        "redirects": []}, body, headers or {"content-type": "application/json"})


class AuditCommitFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {
            "company_en": "Fixture", "domains": []}})

    def tearDown(self):
        self.temp.cleanup()

    def test_503_enqueues_bounded_commit_file_fallback_without_claiming_patch_review(self):
        calls = []
        detail = json.dumps({"sha": SHA, "parents": [{"sha": PARENT}], "files": [
            {"status": "modified", "filename": "data.json", "raw_url": "https://evil.test/ignore"}]}).encode()

        def fetch(url, active, **kwargs):
            calls.append((url, kwargs))
            if url == PATCH:
                return observed(url, active, status=503, headers={"content-type": "text/plain", "retry-after": "60"})
            if url == DETAIL:
                return observed(url, active, status=200, body=detail)
            if url.startswith("https://raw.githubusercontent.com/fixture/repo/"):
                return observed(url, active, status=200, body=b'{"safe":true}')
            raise AssertionError("unexpected fixture request")

        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 5, "max_jobs": 7}, scope=active,
                     fetcher=fetch, inspection_only=True)
            jobs = case.queue.status()["jobs"]
            detail_jobs = [job for job in jobs if job["job_type"] == "repository_commit_detail"]
            self.assertEqual(1, len(detail_jobs))
            self.assertEqual("succeeded", detail_jobs[0]["state"])
            self.assertEqual(2, sum(job["job_type"] == "capture" and job["state"] == "succeeded"
                                    for job in jobs))
            self.assertIn(DETAIL, [url for url, _ in calls])
            reports = [json.loads(row[0]) for row in case.ledger.db.execute(
                "SELECT report_json FROM audit_results")]
            patch = next(row for row in reports if row.get("commit_detail_fallback_queued"))
            self.assertIn("patch_source_unavailable", patch["gaps"])
            fallback = next(row for row in reports if row.get("document_type") == "repository_commit_detail")
            self.assertFalse(fallback["analysis_complete"])
            self.assertIn("commit_patch_hunks_not_reviewed", fallback["gaps"])
            self.assertNotIn("evil.test", json.dumps(reports))

    def test_429_does_not_enqueue_alternate_provider_path(self):
        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 1, "max_jobs": 2}, scope=active,
                     fetcher=lambda url, current, **kwargs: observed(url, current, status=429,
                         headers={"content-type": "text/plain", "retry-after": "60"}),
                     inspection_only=True)
            self.assertFalse(any(job["job_type"] == "repository_commit_detail"
                                 for job in case.queue.status()["jobs"]))

    def test_header_only_patch_links_exact_zero_file_detail_evidence(self):
        patch = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                 "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] empty\n\n").encode()
        detail = json.dumps({"sha": SHA, "parents": [{"sha": PARENT}], "files": [],
                             "stats": {"total": 0, "additions": 0, "deletions": 0}}).encode()
        calls = []

        def fetch(url, active, **kwargs):
            calls.append(url)
            if url == PATCH:
                return observed(url, active, status=200, body=patch, headers={"content-type": "text/plain"})
            if url == DETAIL:
                return observed(url, active, status=200, body=detail)
            raise AssertionError("unexpected fixture request")

        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 3, "max_jobs": 5}, scope=active,
                     fetcher=fetch, inspection_only=True)
            self.assertEqual([PATCH, DETAIL], calls)
            reports = [json.loads(row[0]) for row in case.ledger.db.execute(
                "SELECT report_json FROM audit_results")]
            patch_report = next(row for row in reports if row.get("document_type") == "repository_patch")
            detail_report = next(row for row in reports if row.get("document_type") == "repository_commit_detail")
            self.assertIn("header_only_patch_requires_commit_detail", patch_report["gaps"])
            self.assertTrue(detail_report["empty_diff_verified"])
            self.assertEqual(patch_report["target_id"], detail_report["empty_patch_target_ref"])
            jobs = case.queue.status()["jobs"]
            reconciled_jobs = [job for job in jobs if (job.get("checkpoint") or {}).get("analysis_kind")
                               == "repository_patch_empty_reconcile"]
            self.assertEqual(1, len(reconciled_jobs))
            self.assertEqual("succeeded", reconciled_jobs[0]["state"])
            final = case.prior_result(reconciled_jobs[0])[1]
            self.assertTrue(final["analysis_complete"])
            self.assertEqual([], final["gaps"])
            self.assertEqual("no_changed_files_verified", final["content_review"])
            self.assertEqual(patch_report["observation_id"], final["observation_id"])
            self.assertEqual(patch_report["observed_at"], final["observed_at"])
            self.assertEqual("derived_review", final["observation_kind"])
            related = [job for job in jobs if job["asset_ref"] == patch_report["target_id"]]
            self.assertEqual("evidenced_complete", _capture_state(
                _latest_committed_report(case, related, patch_report["target_id"])))
            self.assertEqual([PATCH, DETAIL], calls)

    def test_mismatched_empty_detail_cannot_complete_patch(self):
        patch = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                 "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] empty\n\n---\n").encode()
        mismatched = json.dumps({"sha": PARENT, "parents": [{"sha": PARENT}], "files": []}).encode()

        def fetch(url, active, **kwargs):
            if url == PATCH:
                return observed(url, active, status=200, body=patch, headers={"content-type": "text/plain"})
            if url == DETAIL:
                return observed(url, active, status=200, body=mismatched)
            raise AssertionError("unexpected fixture request")

        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 3, "max_jobs": 5}, scope=active,
                     fetcher=fetch, inspection_only=True)
            jobs = case.queue.status()["jobs"]
            self.assertFalse(any((job.get("checkpoint") or {}).get("analysis_kind")
                                 == "repository_patch_empty_reconcile" for job in jobs))

    def test_header_only_recheck_content_review_can_link_detail(self):
        patch = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                 "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] empty\n\n---\n").encode()
        detail = json.dumps({"sha": SHA, "parents": [{"sha": PARENT}], "files": []}).encode()
        calls = []

        def fetch(url, active, **kwargs):
            calls.append(url)
            return observed(url, active, status=200, body=patch if url == PATCH else detail,
                            headers={"content-type": "text/plain" if url == PATCH else "application/json"})

        with Case(self.root) as case:
            active = scope()
            ref = case.locators.put(case.scope_id, PATCH)
            case.queue.enqueue("content_review", ref, scope_id=case.scope_id,
                policy_id=active.policy_id, state="ready", priority=2,
                dedupe_key="fixture:patch-recheck", checkpoint={"analysis_kind": "repository_patch"})
            run_case(case, {"max_requests": 3, "max_jobs": 5}, scope=active,
                     fetcher=fetch, inspection_only=True)
            jobs = case.queue.status()["jobs"]
            reconciled = next(job for job in jobs if (job.get("checkpoint") or {}).get("analysis_kind")
                              == "repository_patch_empty_reconcile")
            self.assertEqual("succeeded", reconciled["state"])
            self.assertEqual([PATCH, DETAIL], calls)

    def test_patch_inline_ocr_clears_only_ocr_gap_and_skips_sensitive_hold(self):
        def make_patch(value):
            return (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                    "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] image\n\n---\n"
                    "diff --git a/x.html b/x.html\n--- /dev/null\n+++ b/x.html\n@@ -0,0 +1 @@\n"
                    f"+{value}\n").encode()

        body = make_patch('<img src="data:image/png;base64,' + "A" * 350000 + '">')
        complete = {"inline_images_found": 1, "ocr_completed": 1,
                    "pending_reviews": ["image_visual_and_metadata_review_required"],
                    "content": "NOT_INSPECTED", "signals": []}
        with Case(self.root) as case, mock_patch("sudetect.media_review.analyze_inline_images", return_value=complete) as ocr:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 1, "max_jobs": 2}, scope=active,
                     fetcher=lambda url, current, **kwargs: observed(url, current, status=200,
                         body=body, headers={"content-type": "text/plain"}), inspection_only=True)
            ocr.assert_called_once()
            report = next(json.loads(row[0]) for row in case.ledger.db.execute(
                "SELECT report_json FROM audit_results") if json.loads(row[0]).get("document_type") == "repository_patch")
            self.assertNotIn("inline_image_ocr_unexamined", report["gaps"])
            self.assertIn("image_visual_and_metadata_review_required", report["gaps"])
            self.assertFalse(report["analysis_complete"])

        sensitive = make_patch("ghp_" + "x" * 24 + ' <img src="data:image/png;base64,' + "A" * 100 + '">')
        with Case(self.root) as case, mock_patch("sudetect.media_review.analyze_inline_images") as ocr:
            active = scope()
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 1, "max_jobs": 2}, scope=active,
                     fetcher=lambda url, current, **kwargs: observed(url, current, status=200,
                         body=sensitive, headers={"content-type": "text/plain"}), inspection_only=True)
            ocr.assert_not_called()

    def test_independent_zero_file_detail_releases_only_exact_patch(self):
        other_sha = "c" * 40
        other_url = PATCH.replace(SHA, other_sha)
        sensitive_sha = "d" * 40
        sensitive_url = PATCH.replace(SHA, sensitive_sha)
        empty = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                 "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] empty\n\n").encode()
        sensitive = (f"From {sensitive_sha} Mon Sep 17 00:00:00 2001\nFrom: Fixture <f@example.test>\n"
                     "Date: Tue, 1 Jan 2030 00:00:00 +0000\nSubject: [PATCH] sensitive\n\n---\n"
                     "diff --git a/x.txt b/x.txt\n--- /dev/null\n+++ b/x.txt\n@@ -0,0 +1 @@\n"
                     "+ghp_" + "x" * 24 + "\n").encode()
        detail = json.dumps({"sha": SHA, "parents": [{"sha": PARENT}], "files": []}).encode()
        calls = []

        def fetch(url, active, **kwargs):
            calls.append(url)
            if url == DETAIL:
                return observed(url, active, status=200, body=detail)
            if url == PATCH:
                return observed(url, active, status=200, body=empty,
                                headers={"content-type": "text/plain"})
            if url == sensitive_url:
                return observed(url, active, status=200, body=sensitive,
                                headers={"content-type": "text/plain"})
            raise AssertionError("unapproved fixture request")

        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(DETAIL, scope=active, job_type="repository_commit_detail")
            run_case(case, {"max_requests": 2, "max_jobs": 2}, scope=active,
                     fetcher=fetch, inspection_only=True)
            self.assertIsNotNone(_verified_empty_detail(case, PATCH, active))
            self.assertIsNone(_verified_empty_detail(case, other_url, active))
            denied = Scope.from_dict({"policy_id": "fixture-no-api", "expires_at": "2099-01-01T00:00:00Z",
                "targets": [{"origin": "https://github.com", "owner": "fixture",
                    "ownership_evidence": "fixture:owner", "path_prefixes": ["/fixture/repo/commit/"]}]})
            self.assertIsNone(_verified_empty_detail(case, PATCH, denied))
            case.enqueue_url(sensitive_url, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 2, "max_jobs": 2}, scope=active,
                     fetcher=fetch, inspection_only=True)
            case.enqueue_url(PATCH, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 2, "max_jobs": 3}, scope=active,
                     fetcher=fetch, inspection_only=True)
            case.enqueue_url(other_url, scope=active, job_type="repository_patch")
            run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=active,
                     fetcher=fetch, inspection_only=True)
            self.assertEqual([DETAIL, sensitive_url, PATCH], calls)
            jobs = case.queue.status()["jobs"]
            reconciled = next(job for job in jobs if (job.get("checkpoint") or {}).get("analysis_kind")
                              == "repository_patch_empty_reconcile")
            self.assertEqual("succeeded", reconciled["state"])
            other = next(job for job in jobs if job["job_type"] == "repository_patch" and
                         job["asset_ref"] == case.locators.put(case.scope_id, other_url))
            self.assertEqual("blocked_input", other["state"])

    def test_uncommitted_detail_report_is_not_zero_file_evidence(self):
        with Case(self.root) as case:
            active = scope()
            case.enqueue_url(DETAIL, scope=active, job_type="repository_commit_detail")
            job = next(item for item in case.queue.status()["jobs"]
                       if item["job_type"] == "repository_commit_detail")
            fake = {"target_id": job["asset_ref"], "document_type": "repository_commit_detail",
                    "capture_complete": True, "http_status": 200, "analysis_complete": True,
                    "empty_diff_verified": True, "file_list_page_complete": True,
                    "files_observed": 0, "gaps": []}
            with case.ledger.db:
                case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                                       ("audit:uncommitted-fixture", job["job_id"], json.dumps(fake)))
            self.assertIsNone(_verified_empty_detail(case, PATCH, active))


if __name__ == "__main__":
    unittest.main()
