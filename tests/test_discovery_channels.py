import tempfile
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sudetect.channel_health import run_checks
from sudetect.discovery_channels import load_channel_config, make_plan_import, run_discovery
from sudetect.search_plan import create_plan, import_results
from sudetect.locators import LocatorStore
from sudetect.policy import Scope
from sudetect.transport import FetchResult

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def scope():
    return Scope.from_dict({"policy_id": "p", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://api.certspotter.com", "owner": "o", "ownership_evidence": "e", "path_prefixes": ["/v1/issuances"]},
                    {"origin": "https://search.example", "owner": "o", "ownership_evidence": "e", "path_prefixes": ["/export"]}],
        "exclude_urls": [], "max_requests": 20})


def health(channel):
    config = {"controls": [{"channel_id": channel, "control_id": "ctl", "url": "https://search.example/export",
        "expect": {"kind": "json_pointer", "pointer": "/ok", "equals": "yes"}}]}
    report = run_checks(config, scope(), fetcher=lambda *a, **k: FetchResult(
        {"observation_id": "12345678-1234-4234-9234-123456789abc", "http_status": 200, "capture_complete": True}, b'{"ok":"yes"}'), now=NOW)
    report["synthetic"] = False
    return report


def cert_config():
    return {"version": 1, "scope_id": "team", "provider": "certspotter", "channel_id": "certificate_transparency",
        "source_id": "certspotter-v1", "expected_control_ids":["ctl"], "query": {"work_id": "work-1", "value": "Example.COM"},
        "endpoint": {"url": "https://api.certspotter.com/v1/issuances", "include_subdomains": True},
        "limits": {"max_requests": 3, "max_pages": 3, "max_body_bytes": 4096, "max_candidates": 10}}


def response(body, complete=True):
    import json
    return FetchResult({"http_status": 200, "capture_complete": complete}, json.dumps(body).encode(), {"content-encoding": "identity"})


class DiscoveryChannelTests(unittest.TestCase):
    def test_certspotter_paginates_normalizes_and_keeps_exact_urls_private(self):
        requested = []
        def fake(url, _scope, **kwargs):
            requested.append(url); query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if "after" not in query:
                return response([{"id": "10", "dns_names": ["WWW.Example.com", "*.example.com", "evil-example.com"]}])
            return response([])
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"loc.sqlite") as store:
            report = run_discovery(cert_config(), scope=scope(), channel_health=health("certificate_transparency"), locator_store=store, fetcher=fake, now=NOW)
            self.assertEqual("COMPLETE", report["status"])
            self.assertEqual("10", urllib.parse.parse_qs(urllib.parse.urlsplit(requested[1]).query)["after"][0])
            encoded = str(report)
            self.assertNotIn("www.example.com", encoded.lower())
            self.assertEqual("https://www.example.com/", store.get("team", report["candidates"][0]["locator_ref"]))
            self.assertNotIn("search_plan_import", report)

    def test_certspotter_repeated_cursor_and_truncation_are_partial(self):
        for fake, code in ((lambda *a, **k: response([{"id":"1","dns_names":["a.example.com"]}]), "CURSOR_NOT_ADVANCING"),
                           (lambda *a, **k: response([], complete=False), "BODY_TRUNCATED")):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
                out = run_discovery(cert_config(), scope=scope(), channel_health=health("certificate_transparency"), locator_store=store, fetcher=fake, now=NOW)
                self.assertEqual("PARTIAL", out["status"]); self.assertEqual(code, out["coverage"]["error_code"])

    def test_certspotter_accepts_bounded_numeric_issuance_id(self):
        calls=0
        def fake(*args,**kwargs):
            nonlocal calls; calls+=1
            return response([{"id":7,"dns_names":["a.example.com"]}]) if calls==1 else response([])
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            out=run_discovery(cert_config(),scope=scope(),channel_health=health("certificate_transparency"),locator_store=store,fetcher=fake,now=NOW)
            self.assertEqual("COMPLETE",out["status"])

    def test_generic_empty_has_more_and_malformed_rows_cannot_claim_complete(self):
        cfg = {"version":1,"scope_id":"team","provider":"generic_json_export","channel_id":"web","source_id":"public-export","expected_control_ids":["ctl"],
               "query":{"work_id":"work-2","value":"declared query"},"endpoint":{"url":"https://search.example/export","query_param":"q",
               "page_param":"page","results_pointer":"/rows","url_pointer":"/url","has_more_pointer":"/more"},"limits":{}}
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            out = run_discovery(cfg, scope=scope(), channel_health=health("web"), locator_store=store,
                                fetcher=lambda *a, **k: response({"rows":[],"more":True}), now=NOW)
            self.assertEqual("REQUEST_LIMIT_EXCEEDED", out["coverage"]["error_code"])
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            out = run_discovery(cfg, scope=scope(), channel_health=health("web"), locator_store=store,
                                fetcher=lambda *a, **k: response({"rows":[{"url":"http://bad host"}],"more":False}), now=NOW)
            self.assertEqual("RECORDS_REJECTED", out["coverage"]["error_code"])

    def test_endpoint_family_scope_and_health_fail_before_fetch(self):
        calls=[]
        with self.assertRaises(ValueError):
            load_channel_config({**cert_config(), "endpoint":{"url":"https://elsewhere.example/v1/issuances"}})
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            with self.assertRaises(ValueError):
                run_discovery(cert_config(), scope=scope(), channel_health=health("web"), locator_store=store,
                              fetcher=lambda *a, **k:calls.append(1), now=NOW)
        self.assertEqual([], calls)

    def test_scope_budget_smaller_than_config_stops_before_extra_fixture_call(self):
        narrow=Scope.from_dict({"policy_id":"p","expires_at":"2099-01-01T00:00:00Z","targets":[
            {"origin":"https://api.certspotter.com","owner":"o","ownership_evidence":"e","path_prefixes":["/v1/issuances"]},
            {"origin":"https://search.example","owner":"o","ownership_evidence":"e","path_prefixes":["/export"]}],"exclude_urls":[],"max_requests":1})
        calls=[]
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            out=run_discovery(cert_config(),scope=narrow,channel_health=health("certificate_transparency"),locator_store=store,
                fetcher=lambda *a,**k:(calls.append(1) or response([{"id":"1","dns_names":["a.example.com"]}])),now=NOW)
        self.assertEqual(1,len(calls)); self.assertEqual("REQUEST_LIMIT_EXCEEDED",out["coverage"]["error_code"])

    def test_plan_projection_binds_query_and_imports_end_to_end(self):
        plan=create_plan(scope_id="team",company_en="Example Lab",domains=["example.com"],query_budget=1,account_budget=1)
        job=next(x for x in plan["jobs"] if x["channel"]=="certificate_transparency" and x["kind"]=="domain_seed")
        cfg=cert_config(); cfg["query"]={"work_id":job["work_id"],"value":job["value"]}; healthy=health("certificate_transparency")
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"l") as store:
            report=run_discovery(cfg,scope=scope(),channel_health=healthy,locator_store=store,fetcher=lambda *a,**k:response([]),now=NOW)
        with self.assertRaises(ValueError): make_plan_import(report,plan,healthy)
        report["synthetic"]=False
        imported=import_results(plan,make_plan_import(report,plan,healthy))
        self.assertEqual("completed",next(x for x in imported["jobs"] if x["work_id"]==job["work_id"])["state"])
        report["query_sha256"]="sha256:"+"0"*64
        with self.assertRaises(ValueError): make_plan_import(report,plan,healthy)


if __name__ == "__main__": unittest.main()
