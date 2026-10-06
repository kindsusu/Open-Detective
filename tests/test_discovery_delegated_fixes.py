"""Held-out synthetic organizations for bounded planning and retry behavior."""
from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from sudetect.github_discovery import discover
from sudetect.identifiers import generate_identifiers, generate_search_queries
from sudetect.search_plan import create_plan, plan_status, reconcile_generated_jobs, run_plan
from tests.test_github_discovery import repo


class DiscoveryDelegatedFixes(unittest.TestCase):
    def test_persisted_seed_plan_gains_prefix_jobs_once_without_replaying_completed(self):
        old = create_plan(scope_id="migration-fixture",
                          company_en="Silver Orchard Research Collective",
                          functions=["records"], query_budget=1, account_budget=1)
        old.pop("generation_version")
        old["jobs"] = [job for job in old["jobs"]
                       if "proper-prefix" not in job["generation_rationale"]]
        completed = next(job for job in old["jobs"] if job["channel"] == "github"
                         and job["kind"] == "search_query")
        completed.update(state="completed", result_count=0, pages=2,
                         end_condition="page_exhausted", observed_at="2026-01-01T00:00:00Z",
                         source_ref="fixture:original", attempts=[{"state": "completed"}])
        old["runs"] = [{"run_id": "historical", "status": "COMPLETE"}]
        original_ids = {job["work_id"] for job in old["jobs"]}
        migrated = reconcile_generated_jobs(old)
        self.assertEqual(2, migrated["generation_version"])
        self.assertGreater(migrated["generation_migration_added"], 0)
        self.assertEqual(original_ids, original_ids & {job["work_id"] for job in migrated["jobs"]})
        retained = next(job for job in migrated["jobs"] if job["work_id"] == completed["work_id"])
        self.assertEqual(completed, retained)
        self.assertEqual(old["runs"], migrated["runs"])
        self.assertEqual(migrated, reconcile_generated_jobs(migrated))
        self.assertTrue(any(job["channel"] == "github" and job["state"] == "deferred"
                            and "proper-prefix" in job["generation_rationale"]
                            for job in migrated["jobs"]))

    def test_resume_persists_generation_before_any_request(self):
        old = create_plan(scope_id="migration-save",
                          company_en="Silver Orchard Research Collective",
                          query_budget=1, account_budget=1)
        old.pop("generation_version")
        old["jobs"] = [job for job in old["jobs"]
                       if "proper-prefix" not in job["generation_rationale"]]
        for job in old["jobs"]:
            job["state"] = "not_applicable"
            job["not_applicable_reason"] = "fixture"
        snapshots = []
        out = run_plan(old, fetch=lambda *_: self.fail("unexpected network"),
                       persist=lambda value: snapshots.append(value.copy()))
        self.assertEqual(2, snapshots[0]["generation_version"])
        self.assertEqual(2, out["generation_version"])
        self.assertGreater(out["generation_migration_added"], 0)

    def test_unreconstructable_old_identity_stays_partial(self):
        old = create_plan(scope_id="migration-gap", company_en="Silver Orchard Research Collective")
        old.pop("generation_version")
        old.pop("identity")
        migrated = reconcile_generated_jobs(old)
        self.assertEqual("identity_or_budget_unavailable", migrated["generation_migration_gap"])
        self.assertEqual("PARTIAL", plan_status(migrated)["status"])

    def test_multiword_proper_prefixes_have_source_and_bounded_roles(self):
        rows = generate_identifiers(en="Silver Orchard Research Collective",
                                    aliases=["Copper Willow Analytics Guild"],
                                    functions=["records"])
        values = {str(row["identifier"]): str(row["rationale"]) for row in rows}
        self.assertEqual("english-proper-prefix:2", values["silverorchard"])
        self.assertEqual("english-proper-prefix:2", values["silver-orchard"])
        self.assertEqual("operator-alias-proper-prefix:2", values["copper-willow"])
        self.assertEqual("english-proper-prefix+role:2:records", values["silverorchardrecords"])
        self.assertEqual("english-proper-prefix+role:2:sales", values["silver-orchard-sales"])
        self.assertLessEqual(sum("proper-prefix" in value for value in values.values()), 120)
        self.assertNotIn("silverorc", values)

        queries = {row["query"]: row["rationale"] for row in generate_search_queries(
            en="Silver Orchard Research Collective", functions=["records"])}
        self.assertEqual("full-name:official-english-proper-prefix:2", queries["Silver Orchard"])
        self.assertIn("Silver-Orchard", queries)
        self.assertEqual("narrow:proper-prefix+function", queries["Silver Orchard records"])

    def test_smaller_page_is_persisted_and_used_on_retry(self):
        plan = create_plan(scope_id="page-fixture", company_en="Paper Lantern Studio",
                           query_budget=1, account_budget=1)
        target = next(job for job in plan["jobs"] if job["channel"] == "github"
                      and job["kind"] == "account_candidate" and job["state"] == "planned")
        for job in plan["jobs"]:
            if job is not target:
                job["state"] = "not_applicable"
                job["not_applicable_reason"] = "fixture"
        sizes = []

        def fetch(url, _headers):
            sizes.append(int(parse_qs(urlsplit(url).query)["per_page"][0]))
            if sizes[-1] == 100:
                return 200, [], {}, 2 * 1024 * 1024 + 1
            return 200, [], {}, 100

        failed = run_plan(plan, fetch=fetch, max_batches=1)
        failed_job = next(job for job in failed["jobs"] if job["work_id"] == target["work_id"])
        self.assertEqual("BODY_LIMIT_EXCEEDED", failed_job["error_code"])
        self.assertEqual(50, failed_job["page_size"])
        recovered = run_plan(failed, fetch=fetch, retry_failed=True, max_batches=1)
        job = next(job for job in recovered["jobs"] if job["work_id"] == target["work_id"])
        self.assertEqual([100, 50], sizes)
        self.assertEqual("completed", job["state"])
        self.assertEqual(2, len(job["attempts"]))

    def test_one_item_and_detail_body_limits_do_not_retry_unchanged(self):
        plan = create_plan(scope_id="body-stop", company_en="Paper Lantern Studio",
                           query_budget=1, account_budget=1)
        target = next(job for job in plan["jobs"] if job["channel"] == "github"
                      and job["kind"] == "account_candidate" and job["state"] == "planned")
        target["page_size"] = 1
        for job in plan["jobs"]:
            if job is not target:
                job["state"] = "not_applicable"
                job["not_applicable_reason"] = "fixture"
        calls = []
        def fetch(url, _headers):
            calls.append(url)
            return 200, [], {}, 2 * 1024 * 1024 + 1
        failed = run_plan(plan, fetch=fetch, max_batches=1)
        retried = run_plan(failed, fetch=fetch, retry_failed=True, max_batches=1)
        self.assertEqual(1, len(calls))
        self.assertEqual("failed", next(job for job in retried["jobs"]
                                        if job["work_id"] == target["work_id"])["state"])

    def test_final_single_item_page_is_attempted_before_exhaustion(self):
        plan = create_plan(scope_id="last-page-size", company_en="Paper Lantern Studio")
        target = next(j for j in plan['jobs'] if j['kind'] == 'account_candidate')
        target['page_size'] = 2
        for job in plan['jobs']:
            if job is not target:
                job.update(state='not_applicable', not_applicable_reason='fixture')
        sizes = []
        def fetch(url, headers):
            size = int(parse_qs(urlsplit(url).query)['per_page'][0])
            sizes.append(size)
            return 200, [], {}, 2_097_153 if size == 2 else 100
        failed = run_plan(plan, fetch=fetch, max_batches=1)
        recovered = run_plan(failed, fetch=fetch, retry_failed=True, max_batches=1)
        self.assertEqual([2, 1], sizes)
        self.assertEqual('completed', next(j for j in recovered['jobs'] if j['work_id'] == target['work_id'])['state'])

    def test_rate_limit_due_survives_and_deferred_work_runs(self):
        plan = create_plan(scope_id="due-fixture", company_en="Paper Lantern Studio",
                           query_budget=1, account_budget=1)
        query = next(job for job in plan["jobs"] if job["channel"] == "github"
                     and job["kind"] == "search_query" and job["state"] == "planned")
        account = next(job for job in plan["jobs"] if job["channel"] == "github"
                       and job["kind"] == "account_candidate" and job["state"] == "planned")
        for job in plan["jobs"]:
            if job is account:
                job["state"] = "deferred"
            elif job is not query:
                job["state"] = "not_applicable"
                job["not_applicable_reason"] = "fixture"
        calls = []
        def fetch(url, _headers):
            calls.append(urlsplit(url).path)
            if urlsplit(url).path.startswith("/search/"):
                return 429, {}, {"Retry-After": "120"}
            return 200, [], {}
        failed = run_plan(plan, fetch=fetch, max_batches=1)
        due = next(job for job in failed["jobs"] if job["work_id"] == query["work_id"])["next_eligible_at"]
        resumed = run_plan(failed, fetch=fetch, retry_failed=True,
                           resume_all_deferred=True, max_batches=1)
        self.assertEqual(due, next(job for job in resumed["jobs"]
                                   if job["work_id"] == query["work_id"])["next_eligible_at"])
        self.assertEqual(1, sum(path.startswith("/search/") for path in calls))
        self.assertIn(f"/users/{account['value']}/repos", calls)

    def test_due_failed_query_does_not_starve_deferred_account(self):
        plan = create_plan(scope_id="fair-fixture", company_en="Paper Lantern Studio",
                           query_budget=1, account_budget=1)
        query = next(job for job in plan["jobs"] if job["channel"] == "github"
                     and job["kind"] == "search_query" and job["state"] == "planned")
        account = next(job for job in plan["jobs"] if job["channel"] == "github"
                       and job["kind"] == "account_candidate" and job["state"] == "planned")
        query.update(state="failed", error_code="REQUEST_FAILED",
                     next_eligible_at="2020-01-01T00:00:00Z")
        account["state"] = "deferred"
        for job in plan["jobs"]:
            if job not in (query, account):
                job["state"] = "not_applicable"
                job["not_applicable_reason"] = "fixture"
        seen = []
        def fetch(url, _headers):
            seen.append(urlsplit(url).path)
            return 200, [], {}
        result = run_plan(plan, fetch=fetch, retry_failed=True,
                          resume_all_deferred=True, max_batches=1)
        self.assertEqual([f"/users/{account['value']}/repos"], seen)
        self.assertEqual("planned", next(job for job in result["jobs"]
                                         if job["work_id"] == query["work_id"])["state"])

    def test_account_page_size_and_next_cursor_are_validated(self):
        seen = []
        def fetch(url, _headers):
            parsed = urlsplit(url)
            page = int(parse_qs(parsed.query)["page"][0])
            size = int(parse_qs(parsed.query)["per_page"][0])
            seen.append((page, size))
            if page == 1:
                next_url = url.replace("page=1", "page=2")
                return 200, [repo("paper-lantern", "inert")] * size, {"Link": f'<{next_url}>; rel="next"'}
            return 200, [], {}
        report = discover("pagination-fixture", accounts=["paper-lantern"],
                          fetch=fetch, page_size=25, max_requests=2)
        self.assertEqual([(1, 25), (2, 25)], seen)
        self.assertEqual("COMPLETE", report["coverage"]["list_public_repositories:paper-lantern"]["state"])


if __name__ == "__main__":
    unittest.main()
