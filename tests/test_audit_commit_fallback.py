"""Synthetic 503 commit-detail fallback in the common audit queue."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from datetime import datetime, timezone

from sudetect.audit import Case, init_case, run_case
from sudetect.policy import Scope
from sudetect.repository_commit import commit_detail_url
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


if __name__ == "__main__":
    unittest.main()
