import contextlib, io, json, tempfile, unittest, urllib.parse
from pathlib import Path
from sudetect.search_plan import create_plan, import_results, main, plan_status, run_plan
from tests.test_github_discovery import repo

class SearchPlanTests(unittest.TestCase):
    def test_plan_separates_queries_accounts_and_preserves_deferred(self):
        plan=create_plan(scope_id="synthetic",company_ko="별빛 연구소",company_en="Starlight Research Lab",
                         aliases=["Star Light"],industry=["research"],functions=["docs"],query_budget=2,account_budget=2)
        queries=[j for j in plan["jobs"] if j["kind"]=="search_query"]
        accounts=[j for j in plan["jobs"] if j["kind"]=="account_candidate"]
        self.assertTrue(any(j["value"]=="별빛 연구소" for j in queries))
        self.assertTrue(any(j["value"]=="StarLight" for j in queries))
        self.assertTrue(any(j["state"]=="deferred" for j in queries+accounts))
        self.assertTrue(all(j["state"] in {"deferred","not_applicable"} for j in plan["jobs"] if j["channel"]!="github"))
        self.assertTrue(any(j["kind"]=="search_query" and j["value"]=="별빛 연구소" for j in plan["jobs"] if j["channel"]=="web"))
        self.assertTrue(any(j["channel"]=="certificate_transparency" and j["state"]=="not_applicable" for j in plan["jobs"]))

    def test_ct_uses_only_explicit_domain_seed(self):
        plan=create_plan(scope_id="ct-fixture",company_en="Starlight Lab",domains=["starlight.example"])
        ct=[j for j in plan["jobs"] if j["channel"]=="certificate_transparency"]
        self.assertEqual(["starlight.example"],[j["value"] for j in ct]); self.assertEqual(["domain_seed"],[j["kind"] for j in ct])

    def test_plan_id_includes_known_urls_and_domains(self):
        base=dict(scope_id="plan-identity",company_en="Starlight Lab")
        plain=create_plan(**base)
        known=create_plan(**base,known_urls=["https://github.com/starlight/site"])
        domain=create_plan(**base,domains=["starlight.example"])
        self.assertEqual(3,len({plain["plan_id"],known["plan_id"],domain["plan_id"]}))

    def test_import_rejects_complete_with_error_or_incomplete_provenance(self):
        plan=create_plan(scope_id="import-fixture",company_en="Starlight Lab",query_budget=1,account_budget=1)
        job=next(j for j in plan["jobs"] if j["channel"]=="web")
        imported=import_results(plan,{"jobs":[{"work_id":job["work_id"],"state":"completed","result_count":0,"pages":1,
            "end_condition":"provider_empty","observed_at":"2026-01-01T00:00:00Z","source_ref":"fixture:web","error_code":"RATE_LIMITED"}]})
        changed=next(j for j in imported["jobs"] if j["work_id"]==job["work_id"])
        self.assertEqual("failed",changed["state"]); self.assertEqual("PROVENANCE_INCOMPLETE",changed["error_code"])

    def test_failed_import_also_requires_counts_source_and_observation_time(self):
        plan=create_plan(scope_id="failed-import",company_en="Starlight Lab",query_budget=1,account_budget=1)
        job=next(j for j in plan["jobs"] if j["channel"]=="documents")
        imported=import_results(plan,{"jobs":[{"work_id":job["work_id"],"state":"failed","error_code":"RATE_LIMITED"}]})
        changed=next(j for j in imported["jobs"] if j["work_id"]==job["work_id"])
        self.assertEqual("PROVENANCE_INCOMPLETE",changed["error_code"])

    def test_resume_only_promotes_deferred_and_keeps_completed(self):
        plan=create_plan(scope_id="resume-fixture",company_en="Starlight Research",query_budget=1,account_budget=1)
        completed=next(j for j in plan["jobs"] if j["kind"]=="search_query" and j["state"]=="planned")
        completed.update(state="completed",result_count=0,pages=1,end_condition="provider_empty",observed_at="2026-01-01T00:00:00Z",source_ref="fixture:old")
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path.startswith("/search/"): return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        resumed=run_plan(plan,fetch=fetch,resume_query_budget=1)
        old=next(j for j in resumed["jobs"] if j["work_id"]==completed["work_id"])
        self.assertEqual("fixture:old",old["source_ref"])
        newly=[j for j in resumed["jobs"] if j["kind"]=="search_query" and j["channel"]=="github" and j.get("source_ref")=="github_api:anonymous"]
        self.assertEqual(1,len(newly))

    def test_locator_store_masks_pages_candidate_and_preserves_ref(self):
        from sudetect.locators import LocatorStore
        plan=create_plan(scope_id="locator-fixture",company_en="Starlight",query_budget=1,account_budget=1)
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/search/users": return 200,{"items":[{"login":"starlight-ops"}],"total_count":1,"incomplete_results":False},{}
            if path=="/search/repositories": return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path=="/users/starlight-ops/repos": return 200,[repo("starlight-ops","private-path",pages=True)],{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"locators.db") as store:
            result=run_plan(plan,fetch=fetch,locator_store=store); candidate=result["runs"][0]["result"]["candidates"][0]
            self.assertEqual("ready",candidate["handoff_state"]); self.assertEqual("https://starlight-ops.github.io",candidate["pages_url_candidate"])
            self.assertEqual("https://starlight-ops.github.io/private-path/",store.get("locator-fixture",candidate["locator_ref"]))

    def test_name_only_run_finds_hidden_account_repo_and_pages(self):
        plan=create_plan(scope_id="synthetic-e2e",company_en="Starlight Research",query_budget=2,account_budget=2)
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/search/users": return 200,{"items":[{"login":"starlight-ops"}],"total_count":1,"incomplete_results":False},{}
            if path=="/search/repositories": return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path=="/users/starlight-ops/repos": return 200,[repo("starlight-ops","hidden-docs",pages=True)],{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch)
        github=result["runs"][0]["result"]
        self.assertIn("starlight-ops/hidden-docs",[c["slug"] for c in github["candidates"]])
        self.assertIn("https://starlight-ops.github.io/hidden-docs/",[c["pages_url_candidate"] for c in github["candidates"]])
        self.assertEqual("PARTIAL",result["status"])

    def test_account_failure_does_not_poison_successful_query_jobs(self):
        plan=create_plan(scope_id="per-job",company_en="Starlight Research",query_budget=1,account_budget=1)
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path.startswith("/search/"): return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path.startswith("/users/"): return 403,{"message":"limited"},{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch)
        query=next(j for j in result["jobs"] if j["channel"]=="github" and j["kind"]=="search_query" and j["state"]!="deferred")
        account=next(j for j in result["jobs"] if j["channel"]=="github" and j["kind"]=="account_candidate" and j["state"]!="deferred")
        self.assertEqual("completed",query["state"]); self.assertIsNone(query["error_code"])
        self.assertEqual("failed",account["state"]); self.assertEqual("RATE_LIMITED",account["error_code"])

    def test_partial_github_run_prevents_complete_even_if_jobs_later_imported(self):
        plan=create_plan(scope_id="run-status",company_en="Starlight Lab",query_budget=1,account_budget=1)
        plan["runs"]=[{"run_id":"run-1","channel":"github","status":"PARTIAL"}]
        for job in plan["jobs"]:
            job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
        self.assertEqual("PARTIAL",plan_status(plan)["status"])

    def test_known_url_is_selected_before_broad_jobs_at_run_cap(self):
        plan=create_plan(scope_id="strong-first",company_en="Starlight Research Lab",
                         known_urls=["https://strong-owner.github.io/known-site/"],query_budget=10,account_budget=10)
        # Inflate weak planned work so selection must defer some work at the
        # per-run cap; the exact URL must still reach repository detail.
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/repos/strong-owner/known-site": return 200,repo("strong-owner","known-site",pages=True),{}
            if path.startswith("/search/"): return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch)
        known=next(j for j in result["jobs"] if j["kind"]=="known_url")
        self.assertNotEqual("deferred",known["state"])
        self.assertIn("strong-owner/known-site",[c["slug"] for c in result["runs"][0]["result"]["candidates"]])

    def test_cli_stdout_has_summary_without_raw_queries(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"plan.json"; stdout=io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code=main(["plan","--output",str(path),"--scope-id","fixture","--company-ko","비밀 별빛"])
            self.assertEqual(0,code); self.assertNotIn("비밀 별빛",stdout.getvalue()); self.assertIn("비밀 별빛",path.read_text(encoding="utf-8"))

if __name__=="__main__": unittest.main()
