"""An unresolved engine upgrade is not requeued in an unchanged context."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from sudetect.audit import Case, init_case, run_case
from sudetect.policy import Scope
from sudetect.transport import FetchResult


URL = "https://fixture.test/data.json"


def scope():
    return Scope.from_dict({"policy_id": "fixture-upgrade", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://fixture.test", "owner": "fixture",
                     "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}]})


class EngineUpgradeRetryTests(unittest.TestCase):
    def test_partial_upgrade_does_not_resume_on_same_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "case"
            init_case(root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})
            calls = []
            active = scope()
            with Case(root) as case:
                original = case.enqueue_url(URL, scope=active)
                original_ref = next(job["asset_ref"] for job in case.queue.status()["jobs"]
                                    if job["job_id"] == original)
                case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)", (
                    "audit:oldengine", original, json.dumps({"target_id": original_ref,
                        "policy_id": active.policy_id, "engine_review_version": 2,
                        "capture_complete": True, "analysis_complete": True, "gaps": []})))
                case.ledger.db.execute("UPDATE audit_jobs SET state='succeeded',result_refs=? WHERE job_id=?",
                                       (json.dumps(["audit:oldengine"]), original))
                case.ledger.db.commit()

                def fetch(url, current):
                    current.authorize(url)
                    current.budget.consume()
                    calls.append(url)
                    body = b'{"safe":true}'
                    return FetchResult({"observation_id": str(uuid.uuid4()),
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "policy_id": current.policy_id, "access": "BODY_SERVED",
                        "capture_complete": True, "http_status": 200,
                        "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(),
                        "redirects": []}, body,
                        {"content-type": "application/json", "content-encoding": "gzip"})

                budget = {"max_jobs": 2, "max_requests": 2}
                run_case(case, budget, scope=active, fetcher=fetch, inspection_only=True)
                child = next(job for job in case.queue.status()["jobs"]
                             if job["job_type"] == "content_review")
                self.assertEqual("blocked_input", child["state"])
                self.assertEqual(1, child["attempts"])
                self.assertEqual([URL], calls)

                run_case(case, budget, scope=active, fetcher=fetch, inspection_only=True)
                child_after = next(job for job in case.queue.status()["jobs"]
                                   if job["job_id"] == child["job_id"])
                self.assertEqual("blocked_input", child_after["state"])
                self.assertEqual(1, child_after["attempts"])
                self.assertEqual([URL], calls)


if __name__ == "__main__":
    unittest.main()
