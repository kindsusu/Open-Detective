"""Synthetic regression cases for bounded discovery and independent work."""
import unittest
from unittest.mock import patch
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sudetect.asset_graph import build_asset_graph, compare_mirror_observations
from sudetect.github_discovery import discover
from sudetect.identifiers import generate_identifiers, generate_search_queries
from sudetect.search_plan import create_plan, run_plan
from sudetect.locators import LocatorStore
from tests.test_asset_graph import row
from tests.test_github_discovery import repo


class DiscoveryImprovements(unittest.TestCase):
    def test_t01_default_role_survives_operator_function(self):
        rows = generate_identifiers(en="Fictional Beacon", functions=["finance"])
        by_value = {item["identifier"]: item["rationale"] for item in rows}
        self.assertEqual("stem+operator-function:finance", by_value["fictionalbeaconfinance"])
        self.assertEqual("stem+default-function:sales", by_value["fictionalbeaconsales"])
        queries = generate_search_queries(en="Fictional Beacon", functions=["finance"])
        self.assertIn("Fictional sales", {item["query"] for item in queries})

    def test_t02_seed_finds_role_account_repo_and_domain(self):
        plan = create_plan(scope_id="fictional", company_en="Fictional Beacon",
                           functions=["finance"], query_budget=1, account_budget=4)
        self.assertTrue(any(j["value"] == "fictionalbeaconsales" for j in plan["jobs"]))
        calls = []
        def fetch(url, _headers):
            parsed = urlsplit(url); calls.append(parsed.path)
            if parsed.path == "/search/repositories":
                return 200, {"items":[repo("fictional-beacon-2", "portal", pages=True,
                         homepage="https://dev.fictional.example/work")], "total_count":1,
                         "incomplete_results":False}, {}
            if parsed.path == "/search/users":
                return 200, {"items":[], "total_count":0, "incomplete_results":False}, {}
            if parsed.path.startswith("/users/"):
                return 200, [], {}
            raise AssertionError(parsed.path)
        result = discover("fictional", seeds=["Fictional Beacon"], fetch=fetch)
        self.assertIn("fictional-beacon-2/portal", [x["slug"] for x in result["candidates"]])
        item = result["candidates"][0]
        self.assertEqual("pending", item["ownership"])
        self.assertEqual("unknown", item["publication_approval"])
        self.assertTrue(any(x["kind"] == "repository_homepage" for x in item["deployment_candidates"]))
        self.assertIn("domain:dev.fictional.example", {x["target"] for x in result["edges"]})

    def test_t03_affordable_account_after_expensive_query(self):
        plan=create_plan(scope_id="budget",company_en="Fictional Beacon",query_budget=2,account_budget=1)
        calls=[]
        def fetch(url,_headers):
            calls.append(urlsplit(url).path)
            if urlsplit(url).path.startswith("/search/"):
                return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            return 200,[],{}
        out=run_plan(plan,fetch=fetch,request_budget=3,max_batches=5)
        self.assertEqual(3,out["last_execution"]["requests_used"])
        self.assertTrue(any(path.startswith("/users/") for path in calls))

    def test_connected_domain_is_deferred_with_source(self):
        plan=create_plan(scope_id="domain-link",company_en="Fictional Beacon",query_budget=1,account_budget=1)
        def fetch(url,_headers):
            path=urlsplit(url).path
            if path=="/search/repositories":
                return 200,{"items":[repo("fictional-beacon","portal",homepage="https://dev.fictional.example/page")],
                            "total_count":1,"incomplete_results":False},{}
            if path=="/search/users":
                return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            return 200,[],{}
        out=run_plan(plan,fetch=fetch,request_budget=4,max_batches=3)
        queued=[j for j in out["jobs"] if j["kind"]=="domain_seed" and j["value"]=="dev.fictional.example"]
        self.assertEqual(1,len(queued))
        self.assertEqual("deferred",queued[0]["state"])
        self.assertEqual("fictional-beacon/portal",queued[0]["origin_evidence_ref"])

    def test_t04_search_cooldown_allows_core_and_retry_time(self):
        plan=create_plan(scope_id="cooldown",company_en="Fictional Beacon",query_budget=1,account_budget=1)
        calls=[]
        def fetch(url,_headers):
            path=urlsplit(url).path; calls.append(path)
            if path.startswith("/search/"):
                return 429,{}, {"Retry-After":"120"}
            return 200,[],{}
        out=run_plan(plan,fetch=fetch,request_budget=4,max_batches=4)
        self.assertEqual(2,len(calls))
        self.assertTrue(any(x.startswith("/users/") for x in calls))
        failed=next(j for j in out["jobs"] if j["kind"]=="search_query" and j["state"]=="failed")
        self.assertGreater(datetime.fromisoformat(failed["next_eligible_at"].replace("Z","+00:00")), datetime.now(timezone.utc))

    def test_t04_unhealthy_search_control_keeps_core_eligible(self):
        plan=create_plan(scope_id="health-independent",company_en="Fictional Beacon",query_budget=1,account_budget=1)
        def health(_report,required,**_kwargs):
            return ["CHANNEL_HEALTH_STALE"] if "github-user-search" in required else []
        observed=[]
        def result(_scope,**kwargs):
            observed.append(kwargs)
            account=kwargs["accounts"][0]
            return {"status":"COMPLETE","observed_at":"2026-01-01T00:00:00Z",
                    "candidates":[],"accounts":[],"errors":[],
                    "coverage":{f"list_public_repositories:{account}":{"state":"COMPLETE","pages":1,
                        "items":0,"end_condition":"page_exhausted","error_code":None},
                        "totals":{"requests":1}}}
        with patch("sudetect.search_plan._validate_channel_health",side_effect=health), \
             patch("sudetect.search_plan.github_discover",side_effect=result):
            out=run_plan(plan,channel_health={"controls":[]},request_budget=3)
        self.assertEqual(1,len(observed))
        self.assertEqual("channel_health_failed",out["last_execution"]["stop_reason"])

    def test_metered_live_fetch_checks_health_at_request_boundary(self):
        calls=[]
        with patch("sudetect.github_discovery._validate_channel_health",
                   side_effect=[[],["CHANNEL_HEALTH_STALE"]]):
            result=discover("metered",accounts=["fictional-beacon"],
                fetch=lambda *_: calls.append(1),channel_health={"controls":[]},
                validate_fetch_health=True)
        self.assertEqual([],calls)
        self.assertIn("CHANNEL_HEALTH_STALE",result["errors"])

    def test_t18_complete_representation_only_and_independent_states(self):
        digest="a"*64
        complete={"capture_complete":True,"sha256":digest,"representation":"identity"}
        self.assertEqual("same_at_observation",compare_mirror_observations(complete,dict(complete)))
        self.assertEqual("comparison_pending",compare_mirror_observations(
            {"capture_complete":False,"prefix_sha256":digest,"representation":"identity"},complete))
        candidate=row(); candidate.update(existence_state="observed",business_relevance="low",publication_approval="unknown")
        node=build_asset_graph([candidate])["nodes"][0]
        self.assertEqual("ownership_pending",node["ownership_state"])
        self.assertEqual("low",node["business_relevance"])

    def test_repository_revision_mirror_does_not_treat_branch_as_commit(self):
        branch=repo("fictional-beacon", "portal")
        branch["default_branch"]="main"
        pinned=repo("fictional-beacon", "archive")
        pinned["commit_sha"]="a"*40
        def fetch(url,_headers):
            path=urlsplit(url).path
            if path=="/search/repositories":
                return 200,{"items":[branch,pinned],"total_count":2,"incomplete_results":False},{}
            if path=="/search/users":
                return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            return 200,[],{}
        result=discover("revision",seeds=["fictional"],fetch=fetch)
        mirrors=[deployment for candidate in result["candidates"]
                 for deployment in candidate["deployment_candidates"] if deployment["kind"]=="cdn_mirror"]
        self.assertEqual({"branch_mutable","commit"},{item["revision"]["kind"] for item in mirrors})
        self.assertTrue(all(item["status"]=="candidate_not_confirmed" for item in mirrors))

    def test_deployment_locators_keep_exact_paths_out_of_plan(self):
        plan=create_plan(scope_id="deployment-refs",company_en="Fictional Beacon",query_budget=1,account_budget=1)
        item=repo("fictional-beacon","portal",pages=True,
                  homepage="https://dev.fictional.example/private/workspace")
        item["default_branch"]="main"
        def fetch(url,_headers):
            path=urlsplit(url).path
            if path=="/search/repositories":
                return 200,{"items":[item],"total_count":1,"incomplete_results":False},{}
            if path=="/search/users":
                return 200,{"items":[],"total_count":0,"incomplete_results":False},{}
            return 200,[],{}
        with tempfile.TemporaryDirectory() as tmp, LocatorStore(Path(tmp)/"locators.db") as store:
            result=run_plan(plan,fetch=fetch,locator_store=store,request_budget=4,max_batches=3)
            candidate=next(c for run in result["runs"] for c in run["result"]["candidates"])
            deployments=candidate["deployment_candidates"]
            self.assertEqual({"pages","repository_homepage","cdn_mirror"},{d["kind"] for d in deployments})
            self.assertTrue(all(d["handoff_state"]=="ready" and d["locator_ref"].startswith("opaque:")
                                for d in deployments))
            homepage=next(d for d in deployments if d["kind"]=="repository_homepage")
            self.assertEqual("https://dev.fictional.example/private/workspace",
                             store.get("deployment-refs",homepage["locator_ref"]))
            serialized=json.dumps(result)
            self.assertNotIn("private/workspace",serialized)
            self.assertNotIn("@main",serialized)
            self.assertNotIn("/portal/",serialized)

    def test_no_store_blocks_deployments_without_exposing_exact_path(self):
        item=repo("fictional-beacon","portal",homepage="https://dev.fictional.example/private/workspace")
        result=discover("blocked-deployments",accounts=["fictional-beacon"],
                        fetch=lambda *_:(200,[item],{}))
        candidate=result["candidates"][0]
        self.assertTrue(all(d["handoff_state"]=="blocked" for d in candidate["deployment_candidates"]))
        self.assertNotIn("private/workspace",json.dumps(candidate))


if __name__ == "__main__":
    unittest.main()
