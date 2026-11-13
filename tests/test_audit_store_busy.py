"""Only SQLite BUSY/LOCKED handler errors are resumable state-store failures."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sudetect.audit import Case, init_case, run_case
from sudetect.policy import Scope


URL = "https://fixture.test/data.json"


def scope():
    return Scope.from_dict({"policy_id": "fixture-store", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://fixture.test", "owner": "fixture",
                     "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}]})


class AuditStoreBusyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})

    def tearDown(self):
        self.temp.cleanup()

    def run_with_read_error(self, error):
        with Case(self.root) as case:
            case.enqueue_url(URL, scope=scope())
            with patch.object(case, "reusable_child_review", side_effect=error):
                run_case(case, {"max_jobs": 1, "max_requests": 1}, scope=scope(),
                         fetcher=lambda *_: self.fail("busy read must not fetch"), inspection_only=True)
            job = next(job for job in case.queue.status()["jobs"] if job["job_type"] == "capture")
            count = case.ledger.db.execute("SELECT COUNT(*) FROM audit_results").fetchone()[0]
            return job, count

    def test_actual_sqlite_read_lock_is_retry_without_fake_observation(self):
        path = Path(self.temp.name) / "locked.sqlite"
        owner = sqlite3.connect(path)
        reader = sqlite3.connect(path, timeout=0)
        try:
            owner.execute("CREATE TABLE item(value INTEGER)")
            owner.commit()
            owner.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(sqlite3.OperationalError) as caught:
                reader.execute("SELECT value FROM item").fetchall()
            self.assertEqual(sqlite3.SQLITE_BUSY, caught.exception.sqlite_errorcode & 0xff)
        finally:
            owner.rollback()
            reader.close()
            owner.close()
        job, count = self.run_with_read_error(caught.exception)
        self.assertEqual("retry_wait", job["state"])
        self.assertEqual("STATE_STORE_BUSY", job["last_error_code"])
        self.assertEqual(0, count)
        seconds = (datetime.fromisoformat(job["next_eligible_at"].replace("Z", "+00:00"))
                   - datetime.now(timezone.utc)).total_seconds()
        self.assertGreater(seconds, 0)
        self.assertLessEqual(seconds, 60)

    def test_extended_locked_code_is_retry(self):
        error = sqlite3.OperationalError("locked")
        error.sqlite_errorcode = sqlite3.SQLITE_LOCKED | (1 << 8)
        job, count = self.run_with_read_error(error)
        self.assertEqual("retry_wait", job["state"])
        self.assertEqual("STATE_STORE_BUSY", job["last_error_code"])
        self.assertEqual(0, count)

    def test_other_sqlite_error_is_explicit_terminal(self):
        error = sqlite3.OperationalError("I/O failure")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        job, count = self.run_with_read_error(error)
        self.assertEqual("failed_terminal", job["state"])
        self.assertEqual("STATE_STORE_ERROR", job["last_error_code"])
        self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
