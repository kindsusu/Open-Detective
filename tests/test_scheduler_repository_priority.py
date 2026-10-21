"""Queue priority regressions for resumed repository inventory work."""
import tempfile
import unittest
from pathlib import Path

from sudetect.ledger import Ledger
from sudetect.scheduler import Scheduler


class RepositoryPriorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.temporary.name) / "ledger.sqlite")
        self.queue = Scheduler(self.ledger)

    def tearDown(self):
        self.ledger.close()
        self.temporary.cleanup()

    def test_resumed_tree_review_and_inventory_beat_500_media_captures(self):
        for index in range(500):
            self.queue.enqueue("capture", f"image:{index}", scope_id="fixture", priority=20)
        review = self.queue.enqueue("content_review", "tree:review", scope_id="fixture", priority=0,
                                    checkpoint={"analysis_kind": "repository_tree"})
        tree = self.queue.enqueue("repository_tree", "tree:next", scope_id="fixture", priority=20)
        unrelated = self.queue.enqueue("search", "search:urgent", scope_id="fixture", priority=50)
        pending = self.queue.enqueue("repository_tree", "tree:pending", scope_id="fixture",
                                     priority=100, state="pending")
        run = self.queue.start_run({"max_requests": 5, "max_jobs": 5})
        self.assertEqual([unrelated, review, tree],
                         [self.queue.claim(run)["job_id"] for _ in range(3)])
        self.assertEqual("capture", self.queue.claim(run)["job_type"])
        stored = {job["job_id"]: job for job in self.queue.status()["jobs"]}
        self.assertEqual(0, stored[review]["priority"])
        self.assertEqual(20, stored[tree]["priority"])
        self.assertEqual("pending", stored[pending]["state"])

    def test_history_and_patch_reviews_stay_ahead_of_low_priority_media(self):
        image = self.queue.enqueue("capture", "image:one", scope_id="fixture", priority=1)
        patch = self.queue.enqueue("content_review", "patch:review", scope_id="fixture", priority=0,
                                   checkpoint={"analysis_kind": "repository_patch"})
        history = self.queue.enqueue("content_review", "history:review", scope_id="fixture", priority=0,
                                     checkpoint={"analysis_kind": "repository_history"})
        run = self.queue.start_run({"max_requests": 3, "max_jobs": 3})
        self.assertEqual([history, patch, image],
                         [self.queue.claim(run)["job_id"] for _ in range(3)])

    def test_current_tree_then_history_patch_then_historical_snapshot(self):
        image = self.queue.enqueue("capture", "image:one", scope_id="fixture", priority=1)
        snapshot = self.queue.enqueue("repository_tree", "tree:snapshot", scope_id="fixture",
                                      priority=20, checkpoint={"depth": 1})
        snapshot_review = self.queue.enqueue("content_review", "tree:snapshot-review", scope_id="fixture",
                                             priority=20, checkpoint={"analysis_kind": "repository_tree", "depth": 1})
        patch = self.queue.enqueue("repository_patch", "patch:one", scope_id="fixture", priority=4)
        history = self.queue.enqueue("repository_history", "history:one", scope_id="fixture", priority=5)
        current = self.queue.enqueue("repository_tree", "tree:current", scope_id="fixture",
                                     priority=0, checkpoint={"depth": 0})
        current_review = self.queue.enqueue("content_review", "tree:current-review", scope_id="fixture",
                                            priority=0, checkpoint={"analysis_kind": "repository_tree", "depth": 0})
        run = self.queue.start_run({"max_requests": 7, "max_jobs": 7})
        self.assertEqual([current, current_review, history, patch, snapshot, snapshot_review, image],
                         [self.queue.claim(run)["job_id"] for _ in range(7)])
        stored = {job["job_id"]: job for job in self.queue.status()["jobs"]}
        self.assertEqual(20, stored[snapshot]["priority"])
        self.assertEqual(20, stored[snapshot_review]["priority"])

    def test_inspection_filter_and_existing_age_bonus_remain_effective(self):
        aged = self.queue.enqueue("capture", "capture:aged", scope_id="fixture", priority=20)
        self.ledger.db.execute("UPDATE audit_jobs SET created_at='2000-01-01T00:00:00Z' WHERE job_id=?", (aged,))
        self.ledger.db.commit()
        tree = self.queue.enqueue("repository_tree", "tree:ready", scope_id="fixture", priority=0)
        future = self.queue.enqueue("repository_tree", "tree:future", scope_id="fixture", priority=100,
                                    state="retry_wait")
        self.ledger.db.execute("UPDATE audit_jobs SET next_eligible_at='2099-01-01T00:00:00Z' WHERE job_id=?", (future,))
        self.ledger.db.commit()
        run = self.queue.start_run({"max_requests": 3, "max_jobs": 3})
        self.assertEqual(aged, self.queue.claim(run)["job_id"])
        self.assertEqual(tree, self.queue.claim(run, job_types=frozenset({"repository_tree", "content_review"}))["job_id"])
        self.assertIsNone(self.queue.claim(run, job_types=frozenset({"repository_tree", "content_review"})))


if __name__ == "__main__":
    unittest.main()
