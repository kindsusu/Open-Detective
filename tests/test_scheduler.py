"""Persistent scheduler regressions, including T05/T20/T21 handoff behavior."""

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from sudetect.ledger import Ledger, LedgerError
from sudetect.scheduler import Scheduler


class SchedulerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.sqlite"
        self.ledger = Ledger(self.path)
        self.queue = Scheduler(self.ledger)

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def test_t05_reclaim_fences_stale_worker_and_preserves_checkpoint(self):
        job = self.queue.enqueue("capture", "loc:one", scope_id="scope", checkpoint={"stage": "captured"})
        run = self.queue.start_run({"max_requests": 2})
        first = self.queue.claim(run, lease_seconds=1)
        self.assertTrue(self.queue.reserve(run, requests=1))
        self.ledger.db.execute("UPDATE audit_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id=?", (job,))
        self.ledger.db.commit()
        self.ledger.close()
        self.ledger = Ledger(self.path)
        self.queue = Scheduler(self.ledger)
        second = self.queue.claim(run)
        self.assertEqual(job, second["job_id"])
        self.assertNotEqual(first["lease_owner"], second["lease_owner"])
        self.assertEqual({"stage": "captured"}, second["checkpoint"])
        self.assertFalse(self.queue.finish(job, first["lease_owner"], result_refs=("obs:old",)))
        self.assertTrue(self.queue.finish(job, second["lease_owner"], result_refs=("obs:new",), checkpoint={"stage": "committed"}))
        self.assertFalse(self.queue.finish(job, second["lease_owner"], result_refs=("obs:new",)))
        self.assertEqual(1, self.queue.get_run(run)["requests"])
        self.assertEqual(["obs:new"], self.queue.status()["jobs"][0]["result_refs"])

    def test_independent_affordability_and_run_reasons(self):
        costly = self.queue.enqueue("search", "asset:a", scope_id="scope", estimated_cost=2, priority=10)
        cheap = self.queue.enqueue("lookup", "asset:b", scope_id="scope", estimated_cost=1)
        run = self.queue.start_run({"max_requests": 1})
        self.assertEqual(cheap, self.queue.claim(run)["job_id"])
        self.assertEqual(0, self.queue.get_run(run)["requests"])
        self.assertTrue(self.queue.reserve(run, requests=1))
        self.queue.end_run(run, "no_ready_work")
        self.assertEqual("budget_exhausted", self.queue.get_run(run)["reason"])
        self.assertEqual("running", self.queue.status()["jobs"][1]["state"] if self.queue.status()["jobs"][1]["job_id"] == cheap else self.queue.status()["jobs"][0]["state"])
        self.assertEqual(costly, self.queue.enqueue("search", "asset:a", scope_id="scope", estimated_cost=2))

    def test_t20_blocked_resume_and_cross_session_usage(self):
        job = self.queue.enqueue("capture", "loc:one", scope_id="scope", state="blocked_scope", checkpoint={"offset": 7})
        self.assertTrue(self.queue.unblock(job, policy_id="policy"))
        first_run = self.queue.start_run({"max_requests": 1})
        claim = self.queue.claim(first_run)
        self.assertEqual("policy", claim["policy_id"])
        self.assertEqual({"offset": 7}, claim["checkpoint"])
        self.assertTrue(self.queue.reserve(first_run, requests=1))
        self.assertTrue(self.queue.finish(job, claim["lease_owner"], state="blocked_input", checkpoint={"offset": 8}, error_code="INPUT_REQUIRED"))
        self.queue.end_run(first_run, "input_required")
        self.assertTrue(self.queue.unblock(job))
        next_run = self.queue.start_run({"max_requests": 1})
        claim = self.queue.claim(next_run)
        self.assertEqual({"offset": 8}, claim["checkpoint"])
        self.assertEqual(0, self.queue.get_run(next_run)["requests"])
        self.assertEqual(1, self.queue.status()["all_runs_usage"]["requests"])

    def test_t21_counts_and_event_history(self):
        first = self.queue.enqueue("capture", "loc:one", scope_id="scope")
        self.queue.enqueue("capture", "loc:two", scope_id="scope", state="blocked_input")
        run = self.queue.start_run({})
        claim = self.queue.claim(run)
        self.assertEqual(first, claim["job_id"])
        self.assertTrue(self.queue.finish(first, claim["lease_owner"], result_refs=("obs:1",)))
        status = self.queue.status()
        self.assertEqual(1, status["counts"]["succeeded"])
        self.assertEqual(1, status["unresolved"])
        self.assertFalse(status["complete"])
        events = list(self.ledger.db.execute("SELECT event_type FROM events WHERE entity_id=?", (first,)))
        self.assertEqual(["AUDIT_JOB_ENQUEUED", "AUDIT_JOB_CLAIMED", "AUDIT_JOB_FINISHED"], [x[0] for x in events])
        with self.assertRaises(sqlite3.DatabaseError):
            self.ledger.db.execute("DELETE FROM events")

    def test_parent_is_provenance_and_failed_terminal_remains_gap(self):
        parent = self.queue.enqueue("discovery", "seed", scope_id="scope", state="retry_wait")
        self.ledger.db.execute("UPDATE audit_jobs SET next_eligible_at='2099-01-01T00:00:00Z' WHERE job_id=?", (parent,))
        self.ledger.db.commit()
        child = self.queue.enqueue("capture", "loc:child", scope_id="scope", parent_job_id=parent)
        run = self.queue.start_run({})
        claim = self.queue.claim(run)
        self.assertEqual(child, claim["job_id"])
        self.assertTrue(self.queue.finish(child, claim["lease_owner"], state="failed_terminal", error_code="CAPTURE_FAILED"))
        status = self.queue.status()
        self.assertFalse(status["complete"])
        self.assertEqual(2, status["unresolved"])

    def test_byte_limit_sets_budget_exhausted_reason(self):
        self.queue.enqueue("capture", "loc:one", scope_id="scope")
        run = self.queue.start_run({"max_download_bytes": 1})
        self.assertTrue(self.queue.reserve(run, download_bytes=1))
        self.queue.end_run(run, "no_ready_work")
        self.assertEqual("budget_exhausted", self.queue.get_run(run)["reason"])

    def test_max_attempts_after_expired_lease_keeps_failure_visible(self):
        job = self.queue.enqueue("capture", "loc:one", scope_id="scope")
        run = self.queue.start_run({"max_attempts": 2})
        first = self.queue.claim(run)
        self.ledger.db.execute("UPDATE audit_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id=?", (job,))
        self.ledger.db.commit()
        second = self.queue.claim(run)
        self.assertNotEqual(first["lease_owner"], second["lease_owner"])
        self.ledger.db.execute("UPDATE audit_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id=?", (job,))
        self.ledger.db.commit()
        self.assertIsNone(self.queue.claim(run))
        current = self.queue.status()
        self.assertEqual("failed_terminal", current["jobs"][0]["state"])
        self.assertEqual("LEASE_EXPIRED", current["jobs"][0]["last_error_code"])
        self.assertEqual(1, current["unresolved"])
        self.assertFalse(current["complete"])

    def test_thousand_jobs_skip_unaffordable_without_starving_tail(self):
        for index in range(1000):
            self.queue.enqueue("search", f"asset:{index}", scope_id="scope", priority=100,
                               estimated_cost=2)
        tail = self.queue.enqueue("lookup", "asset:tail", scope_id="scope", estimated_cost=1)
        run = self.queue.start_run({"max_requests": 1, "max_jobs": 1})
        claimed = self.queue.claim(run)
        self.assertEqual(tail, claimed["job_id"])
        self.assertEqual(0, self.queue.get_run(run)["requests"])
        self.assertTrue(self.queue.reserve(run, requests=1))
        self.queue.end_run(run, "no_ready_work")
        self.assertEqual("jobs_exhausted", self.queue.get_run(run)["reason"])

    def test_concurrent_reservation_is_atomic(self):
        run = self.queue.start_run({"max_requests": 1})
        outcomes = []
        barrier = threading.Barrier(2)

        def reserve():
            with Ledger(self.path) as ledger:
                scheduler = Scheduler(ledger)
                barrier.wait()
                outcomes.append(scheduler.reserve(run, requests=1))

        threads = [threading.Thread(target=reserve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([False, True], sorted(outcomes))
        self.assertEqual(1, self.queue.get_run(run)["requests"])

    def test_invalid_limits_and_finite_checkpoint(self):
        for budget in ({"max_requests": 0}, {"max_seconds": float("inf")}, {"max_jobs": True}, {"unknown": 1}):
            with self.assertRaises(LedgerError):
                self.queue.start_run(budget)
        with self.assertRaises(LedgerError):
            self.queue.enqueue("x", "a", scope_id="s", checkpoint={"x": float("nan")})


if __name__ == "__main__":
    unittest.main()
