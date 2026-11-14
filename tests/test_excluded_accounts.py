import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from sudetect import search_plan
from sudetect.search_plan import create_plan, exclude_accounts, run_plan
from tests.test_github_discovery import repo


def account_job(plan, login):
    return next((job for job in plan["jobs"] if job["kind"] == "account_candidate"
                 and job["value"].casefold() == login.casefold()), None)


class ExcludedAccountTests(unittest.TestCase):
    def test_exclusion_marks_pending_job_not_applicable_and_keeps_history(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent", query_budget=1, account_budget=1)
        done = account_job(plan, "melodyrent")
        done.update(state="completed", attempts=[{"state": "completed"}])
        out = exclude_accounts(plan, ["melody-rent", "MelodyRent"], "unrelated music app")
        self.assertEqual("not_applicable", account_job(out, "melody-rent")["state"])
        self.assertEqual("operator_excluded", account_job(out, "melody-rent")["not_applicable_reason"])
        self.assertEqual("completed", account_job(out, "melodyrent")["state"])
        self.assertEqual(["melody-rent", "MelodyRent"],
                         [row["login"] for row in out["excluded_accounts"]])
        again = exclude_accounts(out, ["melody-rent"], "duplicate")
        self.assertEqual(2, len(again["excluded_accounts"]))

    def test_invalid_input_is_rejected(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent")
        with self.assertRaises(ValueError):
            exclude_accounts(plan, ["bad/login"], "x")
        with self.assertRaises(ValueError):
            exclude_accounts(plan, ["ok-login"], " ")

    def test_run_drops_excluded_owner_candidates_and_does_not_expand_them(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent", query_budget=1, account_budget=1)
        for job in plan["jobs"]:
            if job["kind"] == "account_candidate":
                job["state"] = "not_applicable"; job["not_applicable_reason"] = "fixture"
        plan = exclude_accounts(plan, ["unrelated-shop"], "event rental, different company")
        calls = []

        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            calls.append(path)
            if path == "/search/repositories":
                return 200, {"items": [repo("unrelated-shop", "melody-site"), repo("melody-rent", "portal")],
                             "total_count": 2}, {}
            if path == "/search/users":
                return 200, {"items": [{"login": "unrelated-shop"}], "total_count": 1}, {}
            return 200, [], {}

        out = run_plan(plan, fetch=fetch, request_budget=6, max_batches=1)
        slugs = [c["slug"] for run in out["runs"] for batch in run.get("batches", [run])
                 for c in batch.get("result", {}).get("candidates", [])]
        self.assertIn("melody-rent/portal", slugs)
        self.assertNotIn("unrelated-shop/melody-site", slugs)
        self.assertNotIn("/users/unrelated-shop/repos", calls)
        self.assertIsNone(next((job for job in out["jobs"] if job["kind"] == "account_candidate"
                                and job["value"] == "unrelated-shop"
                                and job["state"] in {"planned", "deferred"}), None))

    def test_cli_exclude_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            path.write_text(json.dumps(create_plan(scope_id="fixture", company_en="Melody Rent")), encoding="utf-8")
            code = search_plan.main(["exclude", "--plan", str(path), "--account", "melody-rent",
                                     "--reason", "unrelated"])
            self.assertEqual(0, code)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("melody-rent", saved["excluded_accounts"][0]["login"])


if __name__ == "__main__":
    unittest.main()
