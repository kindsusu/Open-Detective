"""Synthetic provider reports exercise case handoff; no public service is called."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.audit import Case, import_channel, init_case, read_json, run_case
from sudetect.channel_health import run_checks
from sudetect.discovery_channels import run_discovery
from sudetect.policy import Scope
from sudetect.transport import FetchResult


class AuditChannelImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {
            "company_en": "Nebula", "domains": ["seed.test"]}})

    def tearDown(self):
        self.temp.cleanup()

    def report(self, case):
        now = datetime.now(timezone.utc) - timedelta(seconds=5)
        scope = Scope.from_dict({"policy_id": "fixture", "expires_at": "2099-01-01T00:00:00Z",
            "targets": [{"origin": "https://api.certspotter.com", "owner": "fixture",
                "ownership_evidence": "fixture", "path_prefixes": ["/v1/issuances"]}],
            "exclude_urls": [], "max_requests": 10})
        health = run_checks({"controls": [{"channel_id": "certificate_transparency", "control_id": "ctl",
            "url": "https://api.certspotter.com/v1/issuances",
            "expect": {"kind": "json_pointer", "pointer": "/ok", "equals": "yes"}}]},
            scope, fetcher=lambda *a, **k: FetchResult({"observation_id": "12345678-1234-4234-9234-123456789abc",
                "http_status": 200, "capture_complete": True}, b'{"ok":"yes"}'), now=now)
        health["synthetic"] = False  # Only emulate the import contract inside this fixture.
        job = next(j for j in read_json(self.root / "search-plan.json")["jobs"]
                   if j["channel"] == "certificate_transparency")
        responses = iter([[{"id": "1", "dns_names": ["new.seed.test"]}], []])
        report = run_discovery({"version": 1, "scope_id": "fixture", "provider": "certspotter",
            "channel_id": "certificate_transparency", "source_id": "fixture-ct", "expected_control_ids": ["ctl"],
            "query": {"work_id": job["work_id"], "value": job["value"]},
            "endpoint": {"url": "https://api.certspotter.com/v1/issuances", "include_subdomains": True},
            "limits": {"max_requests": 3}}, scope=scope, channel_health=health, locator_store=case.locators,
            fetcher=lambda *a, **k: FetchResult({"http_status": 200, "capture_complete": True},
                json.dumps(next(responses)).encode(), {}), now=now)
        return report, health

    def test_import_reconciles_channel_and_queues_candidates_without_scope_grant(self):
        with Case(self.root) as case:
            report, health = self.report(case)
            report["synthetic"] = False
            result = import_channel(case, report, health)
            again = import_channel(case, report, health)
            self.assertEqual(result, again)
            plan = read_json(self.root / "search-plan.json")
            job = next(j for j in plan["jobs"] if j["work_id"] == report["query_work_id"])
            self.assertEqual("completed", job["state"])
            self.assertEqual(1, len(job["attempts"]))
            self.assertEqual(1, case.ledger.db.execute("SELECT COUNT(*) FROM events WHERE event_type='AUDIT_CHANNEL_IMPORTED'").fetchone()[0])
            status = run_case(case, {"max_requests": 5})
            channel = next(j for j in status["jobs"] if j["job_type"] == "channel_review")
            self.assertEqual("succeeded", channel["state"])
            candidate = next(j for j in status["jobs"] if j["asset_ref"] == report["candidates"][0]["locator_ref"])
            self.assertEqual("blocked_scope", candidate["state"])
            self.assertNotIn("new.seed.test", json.dumps(result))

    def test_synthetic_or_unknown_locator_does_not_mutate_plan_or_jobs(self):
        with Case(self.root) as case:
            report, health = self.report(case)
            before = read_json(self.root / "search-plan.json")
            jobs = case.queue.status()["jobs"]
            with self.assertRaises(ValueError):
                import_channel(case, report, health)
            report["synthetic"] = False
            report["candidates"][0]["locator_ref"] = "opaque:" + "0" * 32
            with self.assertRaises(ValueError):
                import_channel(case, report, health)
            self.assertEqual(before, read_json(self.root / "search-plan.json"))
            self.assertEqual(jobs, case.queue.status()["jobs"])

    def test_interrupted_import_replays_without_duplicate_queue_or_attempts(self):
        with Case(self.root) as case:
            report, health = self.report(case)
            report["synthetic"] = False
            with patch("sudetect.audit.write_json", side_effect=OSError("synthetic interruption")):
                with self.assertRaises(OSError):
                    import_channel(case, report, health)
            count = len(case.queue.status()["jobs"])
            import_channel(case, report, health)
            self.assertEqual(count, len(case.queue.status()["jobs"]))
            job = next(j for j in read_json(self.root / "search-plan.json")["jobs"] if j["work_id"] == report["query_work_id"])
            self.assertEqual(1, len(job["attempts"]))

    def test_partial_channel_keeps_review_blocked_but_preserves_candidate(self):
        with Case(self.root) as case:
            report, health = self.report(case)
            report.update(synthetic=False, status="PARTIAL")
            report["coverage"].update(error_code="BODY_TRUNCATED", end_condition=None)
            import_channel(case, report, health)
            status = run_case(case, {"max_requests": 5})
            channel = next(j for j in status["jobs"] if j["job_type"] == "channel_review")
            self.assertEqual("blocked_input", channel["state"])
            self.assertFalse(status["complete"])

    def test_older_partial_report_cannot_overwrite_newer_complete_observation(self):
        with Case(self.root) as case:
            old, health = self.report(case)
            old["synthetic"] = False
            newer = json.loads(json.dumps(old))
            stamp = datetime.fromisoformat(newer["observed_at"].replace("Z", "+00:00")) + timedelta(seconds=1)
            newer["observed_at"] = stamp.isoformat()
            imported = import_channel(case, newer, health)
            self.assertEqual("operator_supplied_not_independently_verified", imported["execution_attestation"])
            old.update(status="PARTIAL")
            old["coverage"].update(error_code="BODY_TRUNCATED", end_condition=None)
            with self.assertRaisesRegex(ValueError, "stale_channel_observation"):
                import_channel(case, old, health)
            job = next(j for j in read_json(self.root / "search-plan.json")["jobs"] if j["work_id"] == old["query_work_id"])
            self.assertEqual("completed", job["state"])


if __name__ == "__main__":
    unittest.main()
