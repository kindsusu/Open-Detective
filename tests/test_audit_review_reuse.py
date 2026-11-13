"""A direct child review can satisfy an uncaptured duplicate without a second fetch."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from sudetect.audit import Case, _review_context, init_case, run_case
from sudetect.policy import Scope
from sudetect.scheduler import LIMITS
from sudetect.transport import FetchResult


URL = "https://fixture.test/file.json"


def scope():
    return Scope.from_dict({"policy_id": "reuse-fixture", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://fixture.test", "owner": "fixture",
                     "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}]})


class AuditReviewReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})

    def tearDown(self):
        self.temp.cleanup()

    def exercise(self, *, partial=False, context_mismatch=False, old_observation=False,
                 original_result=False, seeded_latest=None, excluded=False):
        calls = []
        active = scope()
        budget = {"max_requests": 3, "max_jobs": 3}
        with Case(self.root) as case:
            class NoTransientCache(dict):
                def __setitem__(self, key, value):
                    pass

            case.transient_responses = NoTransientCache()
            original_id = case.enqueue_url(URL, scope=active)
            original = next(job for job in case.queue.status()["jobs"] if job["job_id"] == original_id)
            context = _review_context(active, None, {**LIMITS, **budget})
            child_id = case.queue.enqueue("content_review", original["asset_ref"],
                scope_id=case.scope_id, policy_id=active.policy_id, parent_job_id=original_id,
                state="blocked_input" if seeded_latest else "ready", priority=40,
                checkpoint={"analysis_kind": "capture", "depth": 0,
                    "context_digest": context})
            if seeded_latest:
                successful = {"observation_id": str(uuid.uuid4()), "observed_at": "2090-01-01T00:00:00Z",
                    "target_id": original["asset_ref"], "policy_id": active.policy_id,
                    "engine_review_version": 3, "capture_complete": True, "retry_required": False}
                case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                                       ("audit:oldercomplete", child_id, json.dumps(successful)))
                refs = ["audit:oldercomplete"]
                if seeded_latest != "success":
                    latest = {**successful, "observation_id": str(uuid.uuid4()),
                              "capture_complete": False, "retry_required": True}
                    case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                                           ("audit:newerfailure", child_id, json.dumps(latest)))
                    if seeded_latest == "committed_failure":
                        refs.append("audit:newerfailure")
                case.ledger.db.execute("UPDATE audit_jobs SET result_refs=? WHERE job_id=?",
                                       (json.dumps(refs), child_id))
                case.ledger.db.commit()
            if excluded:
                case.meta["intake"]["excluded_urls"] = [{"url": URL, "evidence_ref": "fixture:excluded"}]
            if original_result:
                case.ledger.db.execute("INSERT INTO audit_results VALUES(?,?,?)",
                    ("audit:priorfailure", original_id, json.dumps({"retry_required": True})))
                case.ledger.db.commit()

            def fetch(url, current):
                current.authorize(url)
                current.budget.consume()
                calls.append(url)
                body = b'{"safe":true}'
                return FetchResult({"observation_id": str(uuid.uuid4()),
                    "observed_at": ("2000-01-01T00:00:00Z" if old_observation
                                    else datetime.now(timezone.utc).isoformat()),
                    "policy_id": current.policy_id, "access": "BODY_SERVED", "capture_complete": True,
                    "http_status": 200, "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(),
                    "redirects": []}, body,
                    {"content-type": "application/json", **({"content-encoding": "gzip"} if partial else {})})

            if context_mismatch:
                with patch("sudetect.audit._review_context", side_effect=[context, "different-context"]):
                    run_case(case, budget, scope=active, fetcher=fetch, inspection_only=True)
            else:
                run_case(case, budget, scope=active, fetcher=fetch, inspection_only=True)
            jobs = {job["job_id"]: job for job in case.queue.status()["jobs"]}
            reports = {job_id: [(ref, json.loads(report)) for ref, report in
                case.ledger.db.execute("SELECT result_ref,report_json FROM audit_results WHERE job_id=? ORDER BY rowid",
                                       (job_id,))] for job_id in (original_id, child_id)}
            return calls, jobs, reports, original_id, child_id

    def test_complete_review_reuses_exact_observation(self):
        calls, jobs, reports, original, child = self.exercise()
        self.assertEqual([URL], calls)
        self.assertEqual("succeeded", jobs[original]["state"])
        source_ref, source = reports[child][-1]
        reused = reports[original][-1][1]
        self.assertEqual(source_ref, reused["reused_result_ref"])
        self.assertEqual(source["observation_id"], reused["observation_id"])
        self.assertEqual(source["observed_at"], reused["observed_at"])

    def test_partial_review_preserves_gaps_and_flags(self):
        calls, jobs, reports, original, child = self.exercise(partial=True)
        self.assertEqual([URL], calls)
        self.assertEqual("blocked_input", jobs[child]["state"])
        source = reports[child][-1][1]
        reused = reports[original][-1][1]
        self.assertEqual(source["gaps"], reused["gaps"])
        self.assertFalse(reused["analysis_complete"])
        self.assertFalse(reused["review_complete"])

    def test_mismatched_context_fetches(self):
        calls, _, reports, original, _ = self.exercise(context_mismatch=True)
        self.assertEqual([URL, URL], calls)
        self.assertNotIn("reused_result_ref", reports[original][-1][1])

    def test_old_observation_fetches(self):
        calls, _, reports, original, _ = self.exercise(old_observation=True)
        self.assertEqual([URL, URL], calls)
        self.assertNotIn("reused_result_ref", reports[original][-1][1])

    def test_original_with_prior_failed_result_fetches(self):
        calls, _, reports, original, _ = self.exercise(original_result=True)
        self.assertEqual([URL, URL], calls)
        self.assertNotIn("reused_result_ref", reports[original][-1][1])

    def test_newer_child_failure_does_not_resurrect_older_success(self):
        calls, _, reports, original, _ = self.exercise(seeded_latest="committed_failure")
        self.assertEqual([URL], calls)
        self.assertNotIn("reused_result_ref", reports[original][-1][1])

    def test_uncommitted_newer_child_result_does_not_resurrect_older_success(self):
        calls, _, reports, original, _ = self.exercise(seeded_latest="uncommitted_failure")
        self.assertEqual([URL], calls)
        self.assertNotIn("reused_result_ref", reports[original][-1][1])

    def test_excluded_url_cannot_reuse_existing_child_result(self):
        calls, jobs, reports, original, _ = self.exercise(seeded_latest="success", excluded=True)
        self.assertEqual([], calls)
        self.assertEqual("blocked_scope", jobs[original]["state"])
        self.assertEqual([], reports[original])


if __name__ == "__main__":
    unittest.main()
