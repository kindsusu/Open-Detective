"""Inspection-only waiting ignores retry work it cannot claim."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from sudetect.audit import Case, init_case, run_case
from sudetect.policy import Scope
from sudetect.transport import FetchResult


URL = "https://fixture.test/data.json"


def scope():
    return Scope.from_dict({"policy_id": "fixture-inspection", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://fixture.test", "owner": "fixture",
                     "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}]})


class InspectionRetryWaitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})

    def tearDown(self):
        self.temp.cleanup()

    def defer(self, case, job_id, seconds):
        due = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
        case.ledger.db.execute("UPDATE audit_jobs SET state='retry_wait',next_eligible_at=? WHERE job_id=?",
                               (due, job_id))
        case.ledger.db.commit()

    def test_discovery_retry_alone_does_not_sleep(self):
        with Case(self.root) as case:
            discovery = case.queue.enqueue("discovery", "discovery", scope_id=case.scope_id)
            self.defer(case, discovery, 4)
            with patch("sudetect.audit.time.sleep", side_effect=AssertionError("unexpected discovery wait")):
                run_case(case, {"max_seconds": 10}, scope=scope(),
                         wait_for_retry=True, inspection_only=True)
            states = {job["job_id"]: job["state"] for job in case.queue.status()["jobs"]}
            self.assertEqual("retry_wait", states[discovery])

    def test_inspection_retry_is_waited_then_claimed(self):
        with Case(self.root) as case:
            discovery = case.queue.enqueue("discovery", "discovery", scope_id=case.scope_id)
            self.defer(case, discovery, 2)
            capture = case.enqueue_url(URL, scope=scope())
            self.defer(case, capture, 4)
            calls = []
            sleeps = []

            def fake_sleep(seconds):
                sleeps.append(seconds)
                case.ledger.db.execute("UPDATE audit_jobs SET next_eligible_at=? WHERE job_id=?",
                    ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), capture))
                case.ledger.db.commit()

            def fetch(url, active):
                active.authorize(url)
                active.budget.consume()
                calls.append(url)
                body = b'{"safe":true}'
                return FetchResult({"observation_id": str(uuid.uuid4()),
                    "observed_at": datetime.now(timezone.utc).isoformat(), "policy_id": active.policy_id,
                    "access": "BODY_SERVED", "capture_complete": True, "http_status": 200,
                    "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(),
                    "redirects": []}, body, {"content-type": "application/json"})

            with patch("sudetect.audit.time.sleep", side_effect=fake_sleep):
                run_case(case, {"max_seconds": 10, "max_requests": 1, "max_jobs": 1},
                         scope=scope(), fetcher=fetch, wait_for_retry=True, inspection_only=True)
            self.assertEqual(1, len(sleeps))
            self.assertGreater(sleeps[0], 3)
            self.assertEqual([URL], calls)
            states = {job["job_id"]: job["state"] for job in case.queue.status()["jobs"]}
            self.assertEqual("succeeded", states[capture])
            self.assertEqual("retry_wait", states[discovery])


if __name__ == "__main__":
    unittest.main()
