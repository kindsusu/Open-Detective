"""Synthetic provider throttling; no external network or organization data."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
from pathlib import Path
import tempfile
import unittest
import uuid

from sudetect.audit import Case, _github_rate_limit_due, _retry_due, init_case, run_case
from sudetect.policy import Scope
from sudetect.transport import FetchResult


def scope():
    return Scope.from_dict({"policy_id": "retry-fixture", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://fixture.test", "owner": "fixture",
                     "ownership_evidence": "fixture-evidence", "path_prefixes": ["/"]}],
        "max_bytes": 1024 * 1024, "max_requests": 10})


class AuditHttpRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "retry-fixture", "identity": {
            "company_en": "Fixture", "domains": ["fixture.test"]}})

    def tearDown(self):
        self.temp.cleanup()

    def test_retry_after_seconds_date_and_invalid_are_bounded(self):
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.assertEqual(now + timedelta(seconds=300),
                         datetime.fromisoformat(_retry_due("300", 1, now=now)))
        date = format_datetime(now + timedelta(minutes=5), usegmt=True)
        self.assertEqual(now + timedelta(minutes=5),
                         datetime.fromisoformat(_retry_due(date, 1, now=now)))
        self.assertEqual(now + timedelta(seconds=30),
                         datetime.fromisoformat(_retry_due("not-a-date", 1, now=now)))
        self.assertEqual(now + timedelta(minutes=15),
                         datetime.fromisoformat(_retry_due(None, 8, now=now)))
        self.assertEqual(now + timedelta(days=14),
                         datetime.fromisoformat(_retry_due(str(14 * 86400), 1, now=now)))

    def test_github_403_requires_confirmed_rate_limit_and_honors_later_delay(self):
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        reset = str(int((now + timedelta(minutes=5)).timestamp()))
        headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}
        api = "https://api.github.com/repos/fixture/example/git/trees/main"
        self.assertEqual(now + timedelta(minutes=5),
                         datetime.fromisoformat(_github_rate_limit_due(api, 403, headers, 1, now=now)))
        self.assertEqual(now + timedelta(minutes=8), datetime.fromisoformat(
            _github_rate_limit_due(api, 403, {**headers, "retry-after": "480"}, 1, now=now)))
        for url, metadata in ((api, {}), (api, {**headers, "x-ratelimit-remaining": "1"}),
                              (api, {**headers, "x-ratelimit-reset": "invalid"}),
                              (api, {**headers, "x-ratelimit-reset": str(int(now.timestamp()) - 1)}),
                              ("https://fixture.test/", headers),
                              ("https://api.github.com.evil.test/", headers)):
            with self.subTest(url=url, metadata=metadata):
                self.assertIsNone(_github_rate_limit_due(url, 403, metadata, 1, now=now))

    def test_github_403_rate_limit_persists_origin_cooldown(self):
        api = "https://api.github.com/repos/fixture/example/git/trees/main"
        github_scope = Scope.from_dict({"policy_id": "retry-fixture", "expires_at": "2099-01-01T00:00:00Z",
            "targets": [{"origin": "https://api.github.com", "owner": "fixture",
                         "ownership_evidence": "fixture-evidence", "path_prefixes": ["/"]}],
            "max_bytes": 1024 * 1024, "max_requests": 10})
        calls = []
        reset = datetime.now(timezone.utc) + timedelta(minutes=6)
        def limited(url, active_scope):
            active_scope.authorize(url)
            active_scope.budget.consume()
            calls.append(url)
            return FetchResult({"observation_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "policy_id": active_scope.policy_id, "access": "ACCESS_DENIED_OBSERVED",
                "capture_complete": True, "http_status": 403, "reason": "access_denied_status",
                "redirects": []}, b"synthetic provider response",
                {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(reset.timestamp()))})
        with Case(self.root) as case:
            first = case.enqueue_url(api, scope=github_scope)
            run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=github_scope,
                     fetcher=limited, inspection_only=True)
            job = next(job for job in case.queue.status()["jobs"] if job["job_id"] == first)
            self.assertEqual("retry_wait", job["state"])
            self.assertGreater(datetime.fromisoformat(job["next_eligible_at"]),
                               datetime.now(timezone.utc) + timedelta(minutes=5))
            saved = case.ledger.db.execute("SELECT report_json FROM audit_results").fetchone()[0]
            self.assertIn("provider_rate_limited", saved)
            self.assertNotIn("synthetic provider response", saved)
            second = case.enqueue_url(api + "-second", scope=github_scope)
            deferred = next(job for job in case.queue.status()["jobs"] if job["job_id"] == second)
            self.assertEqual("retry_wait", deferred["state"])
            self.assertEqual(0, deferred["attempts"])
        with Case(self.root) as case:
            result = run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=github_scope,
                              fetcher=limited, inspection_only=True)
            self.assertEqual(0, result["run"]["requests"])
            self.assertEqual(1, len(calls))

    def test_plain_403_is_not_retried_or_cooldown(self):
        calls = []
        def denied(url, active_scope):
            active_scope.authorize(url)
            active_scope.budget.consume()
            calls.append(url)
            return FetchResult({"observation_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "policy_id": active_scope.policy_id, "access": "ACCESS_DENIED_OBSERVED",
                "capture_complete": True, "http_status": 403, "reason": "access_denied_status",
                "redirects": []}, b"denied", {"content-type": "text/plain"})
        with Case(self.root) as case:
            run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=scope(),
                     fetcher=denied, inspection_only=True)
            capture = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "capture")
            self.assertNotEqual("retry_wait", capture["state"])
            self.assertEqual(0, case.ledger.db.execute(
                "SELECT COUNT(*) FROM audit_origin_cooldown").fetchone()[0])
            self.assertEqual(1, len(calls))

    def test_503_is_retry_without_content_analysis_and_origin_cooldown_persists(self):
        calls = []
        def failing(url, active_scope):
            active_scope.authorize(url)
            active_scope.budget.consume()
            calls.append(url)
            body = b"synthetic upstream error"
            return FetchResult({"observation_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "policy_id": active_scope.policy_id, "access": "INDETERMINATE",
                "capture_complete": True, "http_status": 503, "reason": "response_observed",
                "sha256": hashlib.sha256(body).hexdigest(), "redirects": []},
                body, {"content-type": "text/plain", "retry-after": "300"})
        with Case(self.root) as case:
            run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=scope(),
                     fetcher=failing, inspection_only=True)
            capture = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "capture")
            self.assertEqual("retry_wait", capture["state"])
            self.assertEqual("TRANSPORT_RETRY", capture["last_error_code"])
            self.assertGreater(datetime.fromisoformat(capture["next_eligible_at"]),
                               datetime.now(timezone.utc) + timedelta(minutes=4))
            report = case.prior_result(capture)
            self.assertIsNone(report, "retry response must not become a successful prior result")
            saved = case.ledger.db.execute("SELECT report_json FROM audit_results").fetchone()[0]
            self.assertNotIn("synthetic upstream error", saved)
            second = case.enqueue_url("https://fixture.test/second", scope=scope())
            self.assertIsNotNone(second)
        with Case(self.root) as case:
            second_run = run_case(case, {"max_requests": 1, "max_jobs": 1}, scope=scope(),
                                  fetcher=failing, inspection_only=True)
            deferred = next(job for job in case.queue.status()["jobs"] if job["job_id"] == second)
            self.assertEqual("retry_wait", deferred["state"])
            self.assertEqual(0, deferred["attempts"])
            self.assertEqual([], deferred["result_refs"])
            self.assertEqual(0, second_run["run"]["requests"])
            self.assertEqual(1, len(calls), "origin cooldown must not send another request")


if __name__ == "__main__": unittest.main()
