import unittest
import urllib.parse

from sudetect.github_discovery import discover
from sudetect.search_plan import create_plan, run_plan, MAX_DISCOVERED_ACCOUNT_JOBS
from tests.test_github_discovery import repo


class DiscoveryRelevanceTests(unittest.TestCase):
    def test_ambiguous_search_keeps_candidates_without_listing_owners(self):
        calls = []

        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            calls.append(path)
            if path == "/search/repositories":
                return 200, {"items": [repo("unrelated-shop", "harmony-theme")],
                             "total_count": 1}, {}
            if path == "/search/users":
                return 200, {"items": [{"login": "unrelated-shop"}],
                             "total_count": 1}, {}
            self.fail(url)

        result = discover("relevance", seeds=["harmony"], fetch=fetch,
                          search_account_context=["harmony-rent"])
        self.assertEqual(["/search/repositories", "/search/users"], calls)
        self.assertEqual(["unrelated-shop/harmony-theme"],
                         [item["slug"] for item in result["candidates"]])
        self.assertEqual([], result["accounts"])
        self.assertTrue(any(item["reason"] == "operator_review_required"
                            for item in result["deferred"]))

    def test_plan_caps_review_jobs_and_does_not_auto_resume_them(self):
        plan = create_plan(scope_id="harmony-review", company_en="Harmony Rent",
                           aliases=["HarmonyRent"], query_budget=1, account_budget=1)
        for job in plan["jobs"]:
            if job["channel"] == "github" and job["kind"] == "account_candidate":
                job["state"] = "not_applicable"
                job["not_applicable_reason"] = "fixture"
        calls = []

        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            calls.append(path)
            if path == "/search/repositories":
                return 200, {"items": [repo(f"thirdparty-{i}", "harmony")
                                       for i in range(80)], "total_count": 80}, {}
            if path == "/search/users":
                return 200, {"items": [], "total_count": 0}, {}
            self.fail(url)

        result = run_plan(plan, fetch=fetch, request_budget=3, max_batches=2,
                          resume_all_deferred=True)
        self.assertEqual(["/search/repositories", "/search/users"], calls)
        self.assertEqual(80, len(result["runs"][-1]["result"]["candidates"]))
        review_jobs = [job for job in result["jobs"]
                       if job.get("deferred_reason") == "operator_review_required"]
        self.assertEqual(MAX_DISCOVERED_ACCOUNT_JOBS, len(review_jobs))
        self.assertTrue(result["discovered_account_job_limit_reached"])
        self.assertTrue(all("attempts" not in job for job in review_jobs))


if __name__ == "__main__":
    unittest.main()
