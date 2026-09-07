import contextlib, io, json, tempfile, unittest, urllib.parse
from datetime import datetime
from pathlib import Path
from sudetect.search_plan import _health_requirements, create_plan, import_results, main, plan_status, run_plan
from tests.test_github_discovery import repo
from tests.health_fixtures import health_report

class SearchPlanTests(unittest.TestCase):
    def test_health_requirements_are_channel_specific_and_fail_closed(self):
        self.assertEqual(["github-repositories"], _health_requirements({"channel":"github", "kind":"known_url"}))
        self.assertEqual(["github-user-search", "github-repository-search", "github-repositories"],
                         _health_requirements({"channel":"github", "kind":"search_query"}))
        self.assertEqual(["web"], _health_requirements({"channel":"web", "kind":"search_query"}))
        self.assertEqual(["documents"], _health_requirements({"channel":"documents", "kind":"search_query"}))
        self.assertEqual(["certificate_transparency"], _health_requirements({"channel":"certificate_transparency", "kind":"domain_seed"}))
        self.assertEqual(["invalid-channel"], _health_requirements({"channel":"untrusted", "kind":"search_query"}))

    def test_external_import_requires_its_own_health_at_observation_time(self):
        plan=create_plan(scope_id="external-health",company_en="Starlight Lab",query_budget=1,account_budget=1)
        job=next(job for job in plan["jobs"] if job["channel"]=="web")
        observed="2026-01-01T00:00:00Z"
        row={"work_id":job["work_id"],"state":"completed","result_count":0,"pages":1,
             "end_condition":"provider_empty","observed_at":observed,"source_ref":"fixture:web"}
        current=datetime.fromisoformat(observed.replace("Z","+00:00"))
        valid=import_results(plan,{"jobs":[row],"channel_health":health_report("web",now=current)})
        self.assertEqual("completed",next(job for job in valid["jobs"] if job["work_id"]==row["work_id"])["state"])
        wrong=import_results(plan,{"jobs":[row],"channel_health":health_report("documents",now=current)})
        changed=next(job for job in wrong["jobs"] if job["work_id"]==row["work_id"])
        self.assertEqual("failed",changed["state"]); self.assertEqual("CHANNEL_HEALTH_MISSING",changed["error_code"])
    def test_live_plan_requires_health_without_mutating_checkpoint(self):
        plan=create_plan(scope_id="health-gate",company_en="Starlight",query_budget=1,account_budget=1)
        before=json.loads(json.dumps(plan))
        with self.assertRaisesRegex(ValueError,"CHANNEL_HEALTH_REQUIRED"):
            run_plan(plan)
        self.assertEqual(before,plan)

    def test_expired_second_batch_preserves_history_and_deferred_state(self):
        from unittest.mock import patch
        plan=create_plan(scope_id="expiry-history",company_en="Starlight",query_budget=1,account_budget=1)
        query=next(job for job in plan["jobs"] if job["kind"]=="search_query" and job["state"]=="planned")
        account=next(job for job in plan["jobs"] if job["kind"]=="account_candidate" and job["state"]=="planned")
        account.update(state="deferred", deferred_reason="fixture-deferred")
        # Keep only query then deferred account runnable in run-until-budget.
        for job in plan["jobs"]:
            if job not in (query, account):
                job.update(state="not_applicable", not_applicable_reason="fixture")
        old_attempt={"attempted_at":"2026-01-01T00:00:00Z", "state":"completed", "method":"import"}
        query["attempts"]=[old_attempt]
        result={"schema_version":"1.0","provider":"github_public","scope_id":"expiry-history",
                "status":"COMPLETE","observed_at":"2026-09-07T00:00:00Z","candidates":[],"accounts":[],
                "edges":[],"errors":[],"coverage":{"search_users:1":{"state":"COMPLETE","pages":1,"items":0,
                "end_condition":"page_exhausted","error_code":None},"search_repositories:1":{"state":"COMPLETE","pages":1,
                "items":0,"end_condition":"page_exhausted","error_code":None},"totals":{"requests":2}},"methods_executed":[]}
        checks=iter(([], [], ["CHANNEL_HEALTH_STALE"]))
        with patch("sudetect.search_plan._validate_channel_health", side_effect=lambda *_args, **_kwargs: next(checks)), \
             patch("sudetect.search_plan.github_discover", return_value=result) as discovered:
            out=run_plan(plan, request_budget=5, max_batches=5, resume_all_deferred=True,
                         channel_health={"controls":[]})
        self.assertEqual(1,discovered.call_count)
        unchanged=next(job for job in out["jobs"] if job["work_id"]==account["work_id"])
        self.assertEqual("deferred",unchanged["state"]); self.assertEqual("fixture-deferred",unchanged["deferred_reason"])
        retained=next(job for job in out["jobs"] if job["work_id"]==query["work_id"])
        self.assertEqual(old_attempt,retained["attempts"][0])
        self.assertEqual("channel_health_failed",out["last_execution"]["stop_reason"])

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

    def test_function_narrow_query_runs_in_first_three_query_turns(self):
        plan=create_plan(scope_id="round-robin",company_en="Atlas Systems",
                         aliases=["Atlas Cloud", "Atlas Data"], industry=["hosting", "analytics"],
                         functions=["dashboard", "portal"], query_budget=3, account_budget=1)
        observed_queries=[]
        def fetch(url,_headers):
            parsed=urllib.parse.urlsplit(url)
            if parsed.path.startswith("/search/"):
                query=urllib.parse.parse_qs(parsed.query)["q"][0]
                observed_queries.append(query)
                if parsed.path=="/search/repositories":
                    rows=[repo("atlas-org","dashboard-repo")] if query.startswith("Atlas dashboard ") else []
                    return 200,{"items":rows,"total_count":len(rows),"incomplete_results":False},{}
                return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if parsed.path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch,request_budget=10,max_batches=4)
        query_turns=[]
        for value in observed_queries:
            seed=value.split(" in:",1)[0]
            if seed not in query_turns: query_turns.append(seed)
        self.assertIn("Atlas dashboard",query_turns[:3])
        candidates=[candidate["slug"] for run in result["runs"] for candidate in run["result"]["candidates"]]
        self.assertIn("atlas-org/dashboard-repo",candidates)

    def test_legacy_query_order_is_reselected_without_mutating_history_or_ids(self):
        plan=create_plan(scope_id="legacy-query-order",company_en="Atlas Systems",
                         aliases=["Atlas Cloud", "Atlas Data"], industry=["hosting", "analytics"],
                         functions=["dashboard", "portal"], query_budget=1, account_budget=1)
        github_queries=[job for job in plan["jobs"] if job["channel"]=="github" and job["kind"]=="search_query"]
        completed=github_queries[0]
        completed.update(state="completed", result_count=0, pages=2, end_condition="page_exhausted",
                         observed_at="2026-01-01T00:00:00Z", source_ref="fixture:historic",
                         attempts=[{"attempted_at":"2026-01-01T00:00:00Z", "state":"completed"}])
        for job in github_queries[1:]:
            job.update(state="deferred", deferred_reason="legacy-order")
        for job in plan["jobs"]:
            if job["channel"]=="github" and job["kind"]=="account_candidate":
                job.update(state="not_applicable", not_applicable_reason="fixture")
        # Simulate a persisted legacy order where all industry rows precede functions.
        plan["jobs"]=[job for job in plan["jobs"] if job not in github_queries] + [completed] + sorted(
            github_queries[1:], key=lambda job: "function" in job["generation_rationale"])
        before_ids={job["work_id"] for job in plan["jobs"]}
        seen=[]
        def fetch(url,_headers):
            parsed=urllib.parse.urlsplit(url)
            if parsed.path.startswith("/search/"):
                query=urllib.parse.parse_qs(parsed.query)["q"][0]; seen.append(query)
                rows=[repo("atlas-org","dashboard-repo")] if query.startswith("Atlas dashboard ") and parsed.path=="/search/repositories" else []
                return 200,{"items":rows,"total_count":len(rows),"incomplete_results":False},{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch,resume_all_deferred=True,request_budget=6,max_batches=3)
        query_turns=[]
        for value in seen:
            seed=value.split(" in:",1)[0]
            if seed not in query_turns: query_turns.append(seed)
        self.assertIn("Atlas dashboard",query_turns[:3])
        current=next(job for job in result["jobs"] if job["work_id"]==completed["work_id"])
        self.assertEqual("fixture:historic",current["source_ref"])
        self.assertEqual([{"attempted_at":"2026-01-01T00:00:00Z", "state":"completed"}],current["attempts"])
        self.assertTrue(before_ids.issubset({job["work_id"] for job in result["jobs"]}))

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
            result=run_plan(plan,fetch=fetch,locator_store=store)
            candidate=next(c for run in result["runs"] for c in run["result"]["candidates"] if c["slug"]=="starlight-ops/private-path")
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
        candidates=[c for run in result["runs"] for c in run["result"]["candidates"]]
        self.assertIn("starlight-ops/hidden-docs",[c["slug"] for c in candidates])
        self.assertIn("https://starlight-ops.github.io/hidden-docs/",[c["pages_url_candidate"] for c in candidates])
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
        self.assertEqual("failed",account["state"]); self.assertEqual("ACCESS_DENIED",account["error_code"])

    def test_historical_partial_recovers_only_with_current_job_provenance(self):
        plan=create_plan(scope_id="run-status",company_en="Starlight Lab",query_budget=1,account_budget=1)
        plan["runs"]=[{"run_id":"run-1","channel":"github","status":"PARTIAL"}]
        for job in plan["jobs"]:
            job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
            job["attempts"]=[{"attempted_at":"2026-01-01T00:00:00Z","state":"not_applicable","method":"import"}]
        plan["coverage_version"]=2; plan["legacy_coverage_gap"]=False
        self.assertEqual("COMPLETE",plan_status(plan)["status"])
        plan["jobs"][0].pop("not_applicable_reason")
        self.assertEqual("PARTIAL",plan_status(plan)["status"])

    def test_legacy_partial_run_with_unmigrated_completed_job_stays_partial(self):
        plan=create_plan(scope_id="legacy-partial",company_en="Starlight",query_budget=1,account_budget=1)
        plan.pop("coverage_version"); plan.pop("legacy_coverage_gap")
        plan["runs"]=[{"run_id":"old","status":"PARTIAL"}]
        for job in plan["jobs"]:
            job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
        plan["jobs"][0].update(state="completed",result_count=0,pages=1,end_condition="provider_empty",
                               observed_at="2026-01-01T00:00:00Z",source_ref="legacy")
        self.assertEqual("PARTIAL",plan_status(plan)["status"])

    def test_failed_job_retries_and_preserves_attempt_history(self):
        plan=create_plan(scope_id="retry-history",company_en="Starlight",query_budget=1,account_budget=1)
        account=next(j for j in plan["jobs"] if j["channel"]=="github" and j["kind"]=="account_candidate" and j["state"]=="planned")
        for job in plan["jobs"]:
            if job["channel"]=="github" and job["kind"]=="search_query" and job["state"]=="planned":
                job["state"]="completed"; job.update(result_count=0,pages=2,end_condition="page_exhausted",
                    observed_at="2026-01-01T00:00:00Z",source_ref="fixture")
        calls=0
        def fetch(url,_headers):
            nonlocal calls
            calls+=1
            if calls==1: return 429,{"message":"limited"},{}
            return 200,[],{}
        failed=run_plan(plan,fetch=fetch,max_batches=1)
        first=next(j for j in failed["jobs"] if j["work_id"]==account["work_id"])
        self.assertEqual("failed",first["state"]); self.assertEqual(1,len(first["attempts"]))
        recovered=run_plan(failed,fetch=fetch,retry_failed=True,max_batches=1)
        current=next(j for j in recovered["jobs"] if j["work_id"]==account["work_id"])
        self.assertEqual("completed",current["state"]); self.assertEqual(2,len(current["attempts"]))
        self.assertEqual("RATE_LIMITED",current["attempts"][0]["error_code"])

    def test_rate_limit_stops_following_batches(self):
        plan=create_plan(scope_id="rate-stop",company_en="Starlight Research",query_budget=2,account_budget=2)
        calls=[]
        def fetch(url,_headers):
            calls.append(url); return 429,{"message":"limited"},{}
        result=run_plan(plan,fetch=fetch,request_budget=20,max_batches=10)
        self.assertEqual(1,len(calls))
        self.assertEqual("provider_rate_limited",result["last_execution"]["stop_reason"])
        self.assertEqual(1,result["last_execution"]["batches"])

    def test_request_budget_is_strict_and_next_work_is_explained(self):
        plan=create_plan(scope_id="strict-budget",company_en="Starlight Research",query_budget=2,account_budget=2)
        calls=[]
        def fetch(url,_headers):
            calls.append(url); return 200,[],{}
        result=run_plan(plan,fetch=fetch,request_budget=2,max_batches=10)
        self.assertEqual(2,len(calls)); self.assertEqual(2,result["last_execution"]["requests_used"])
        self.assertEqual("request_budget_exhausted",result["last_execution"]["stop_reason"])
        self.assertGreater(result["last_execution"]["next_work"]["remaining"],0)

    def test_search_discovered_unexpanded_account_becomes_durable_job(self):
        plan=create_plan(scope_id="durable-expansion",company_en="Starlight",query_budget=1,account_budget=1)
        # Mark initial account out of the way so this batch exercises the query.
        for job in plan["jobs"]:
            if job["channel"]=="github" and job["kind"]=="account_candidate" and job["state"]=="planned":
                job["state"]="completed"; job.update(result_count=0,pages=1,end_condition="provider_empty",
                    observed_at="2026-01-01T00:00:00Z",source_ref="fixture")
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/search/repositories": return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path=="/search/users": return 200,{"items":[{"login":"new-account"}],"total_count":1,"incomplete_results":False},{}
            if path=="/users/new-account/repos": return 403,{"message":"limited"},{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch,request_budget=2,max_batches=1)
        expansion=next(j for j in result["jobs"] if j["kind"]=="account_candidate" and j["value"]=="new-account")
        self.assertEqual("failed",expansion["state"])
        self.assertEqual("REQUEST_LIMIT_EXCEEDED",expansion["error_code"])

    def test_cli_run_until_budget_requires_total_budget(self):
        with self.assertRaises(SystemExit):
            main(["run-until-budget","--plan","unused.json"])

    def test_run_until_budget_promotes_multiple_deferred_batches(self):
        plan=create_plan(scope_id="auto-resume",company_en="Starlight Research",query_budget=1,account_budget=1)
        checkpoints=[]
        def fetch(_url,_headers): return 200,[],{}
        result=run_plan(plan,fetch=fetch,request_budget=3,max_batches=3,resume_all_deferred=True,
                        persist=lambda value:checkpoints.append(json.loads(json.dumps(value))))
        completed=[j for j in result["jobs"] if j["channel"]=="github" and j["state"]=="completed"]
        self.assertEqual(3,result["last_execution"]["requests_used"])
        self.assertGreaterEqual(len(completed),2)
        self.assertGreaterEqual(len(checkpoints),3)
        self.assertTrue(all("last_execution" in snapshot for snapshot in checkpoints))

    def test_not_found_end_condition_is_preserved(self):
        plan=create_plan(scope_id="not-found",company_en="Starlight",query_budget=1,account_budget=1)
        for job in plan["jobs"]:
            if job["channel"]=="github" and job["kind"]=="search_query" and job["state"]=="planned":
                job["state"]="completed"; job.update(result_count=0,pages=2,end_condition="page_exhausted",
                    observed_at="2026-01-01T00:00:00Z",source_ref="fixture")
        def fetch(_url,_headers): return 404,{"message":"missing"},{}
        result=run_plan(plan,fetch=fetch,max_batches=1)
        account=next(j for j in result["jobs"] if j["channel"]=="github" and j["kind"]=="account_candidate" and j["state"]=="completed")
        self.assertEqual("not_found_observed",account["end_condition"])

    def test_per_job_cap_preserves_budget_for_identity_account(self):
        plan=create_plan(scope_id="fair-budget",company_en="Starlight Research",query_budget=1,account_budget=1)
        paths=[]
        def fetch(url,_headers):
            parsed=urllib.parse.urlsplit(url); paths.append(parsed.path)
            if parsed.path.startswith("/search/"):
                page=int(urllib.parse.parse_qs(parsed.query)["page"][0])
                rows=[] if page==4 else [repo("unrelated","repo"+str(page))]*100
                headers={} if page==4 else {"link":url.replace("page="+str(page),"page="+str(page+1))+"; rel=\"next\""}
                return 200,{"items":rows,"total_count":300,"incomplete_results":False},headers
            if parsed.path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch,request_budget=8,per_job_request_budget=6,max_batches=2)
        self.assertIn("/users/starlightresearch/repos",[path.lower() for path in paths])
        self.assertLessEqual(result["last_execution"]["requests_used"],8)

    def test_aggregate_matches_raw_batches_and_qualified_coverage(self):
        plan=create_plan(scope_id="aggregate",company_en="Starlight",query_budget=1,account_budget=1)
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path.startswith("/search/"): return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=run_plan(plan,fetch=fetch,request_budget=3,max_batches=2)
        run=result["runs"][0]; aggregate=run["result"]
        self.assertEqual(2,len(run["batches"])); self.assertTrue(all("result" in row for row in run["batches"]))
        self.assertEqual(sum(row["requests_used"] for row in run["batches"]),aggregate["totals"]["requests"])
        self.assertTrue(all(key.startswith(tuple(run["work_ids"])) for key in aggregate["coverage"]))

    def test_legacy_all_not_applicable_does_not_erase_partial_run(self):
        plan=create_plan(scope_id="legacy-na",company_en="Starlight",query_budget=1,account_budget=1)
        plan.pop("coverage_version"); plan.pop("legacy_coverage_gap")
        plan["runs"]=[{"run_id":"old","status":"PARTIAL"}]
        for job in plan["jobs"]:
            job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
        self.assertEqual("PARTIAL",plan_status(plan)["status"])

    def test_noop_run_and_empty_import_preserve_legacy_partial_gap(self):
        plan=create_plan(scope_id="legacy-noop",company_en="Starlight",query_budget=1,account_budget=1)
        plan.pop("coverage_version"); plan.pop("legacy_coverage_gap")
        plan["runs"]=[{"run_id":"old","status":"PARTIAL"}]
        for job in plan["jobs"]:
            job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
        after_run=run_plan(plan,fetch=lambda *_:self.fail("no request expected"),max_batches=1)
        self.assertEqual("PARTIAL",plan_status(after_run)["status"])
        self.assertNotEqual(False,after_run.get("legacy_coverage_gap"))
        after_import=import_results(plan,{"jobs":[]})
        self.assertEqual("PARTIAL",plan_status(after_import)["status"])
        self.assertNotEqual(False,after_import.get("legacy_coverage_gap"))

    def test_unrelated_run_and_import_cannot_clear_legacy_gap(self):
        plan=create_plan(scope_id="legacy-unrelated",company_en="Starlight",query_budget=1,account_budget=1)
        plan.pop("coverage_version"); plan.pop("legacy_coverage_gap")
        plan["runs"]=[{"run_id":"old","status":"PARTIAL"}]
        after_run=run_plan(plan,fetch=lambda *_:(200,[],{}),max_batches=1)
        self.assertTrue(after_run["legacy_coverage_gap"]); self.assertEqual("PARTIAL",plan_status(after_run)["status"])
        imported_job=next(j for j in plan["jobs"] if j["channel"]=="web")
        after_import=import_results(plan,{"jobs":[{"work_id":imported_job["work_id"],"state":"not_applicable",
            "not_applicable_reason":"unrelated fixture"}]})
        self.assertTrue(after_import["legacy_coverage_gap"]); self.assertEqual("PARTIAL",plan_status(after_import)["status"])

    def test_new_v2_plan_can_recover_failed_job_without_legacy_gap(self):
        plan=create_plan(scope_id="v2-recovery",company_en="Starlight",query_budget=1,account_budget=1)
        self.assertEqual(2,plan["coverage_version"]); self.assertFalse(plan["legacy_coverage_gap"])
        account=next(j for j in plan["jobs"] if j["channel"]=="github" and j["kind"]=="account_candidate" and j["state"]=="planned")
        for job in plan["jobs"]:
            if job is not account:
                job["state"]="not_applicable"; job["not_applicable_reason"]="fixture"
        failed=run_plan(plan,fetch=lambda *_:(429,{"message":"limited"},{}),max_batches=1)
        recovered=run_plan(failed,fetch=lambda *_:(200,[],{}),retry_failed=True,max_batches=1)
        self.assertEqual("COMPLETE",plan_status(recovered)["status"])
        self.assertEqual(2,len(account_attempts:=next(j for j in recovered["jobs"] if j["work_id"]==account["work_id"])["attempts"]))

    def test_discovered_account_case_does_not_duplicate_existing_job(self):
        plan=create_plan(scope_id="casefold-account",company_en="Starlight",query_budget=1,account_budget=1)
        existing=next(j for j in plan["jobs"] if j["channel"]=="github" and j["kind"]=="account_candidate")
        existing["value"]="starlight"
        before=len([j for j in plan["jobs"] if j["kind"]=="account_candidate"])
        from sudetect.search_plan import _record_discovered_accounts
        _record_discovered_accounts(plan,{"observed_at":"2026-01-01T00:00:00Z",
            "accounts":[{"login":"StarLight"}],"coverage":{"list_public_repositories:STARLIGHT":{
            "state":"COMPLETE","pages":1,"items":0,"end_condition":"page_exhausted","error_code":None}}})
        accounts=[j for j in plan["jobs"] if j["kind"]=="account_candidate"]
        self.assertEqual(before,len(accounts)); self.assertEqual("completed",existing["state"])

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
