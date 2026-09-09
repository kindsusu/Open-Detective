import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from sudetect.github_code_search import Broker, CodeError, _file, enable_code_search, export_report, run_code
from sudetect.locators import LocatorStore
from sudetect.search_plan import create_plan, import_results, main, run_plan

ENV = "OD_TEST_SEARCH_TOKEN"
CONTROL = {"control_id": "synthetic-public-file", "query": "known-marker", "repository": "fixture/control",
           "path": "README.md", "expires_at": "2099-01-01T00:00:00Z"}


def item(path="data/pricing.json", *, repo="unrelated/app", rid=91, sha="a" * 40, private=False):
    owner, name = repo.split("/")
    return {"path": path, "sha": sha, "html_url": f"https://github.com/{repo}/blob/{'b' * 40}/{path}",
            "repository": {"id": rid, "name": name, "full_name": repo, "owner": {"login": owner}, "private": private}}


def payload(items=(), *, total=None, incomplete=False):
    return {"total_count": len(items) if total is None else total, "incomplete_results": incomplete, "items": list(items)}


class Fake:
    def __init__(self, pages=None, control=None):
        self.calls = []
        self.pages = pages or {}
        self.control = payload([item("README.md", repo="fixture/control")]) if control is None else control

    def __call__(self, url, headers):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        self.calls.append((parsed, query, headers))
        if "repo:fixture/control" in query["q"][0]:
            return self.control
        return self.pages.get(int(query["page"][0]), payload([item()]))


def plan():
    result = create_plan(scope_id="team", company_en="Fixture Motors", query_budget=1, account_budget=1, github_code=True)
    return result


class CodeSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = LocatorStore(self.root / "locations.db")
        self.env = patch.dict(os.environ, {ENV: "synthetic-token-not-real"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.store.close()
        self.temp.cleanup()

    def run_code(self, source=None, fake=None, **kwargs):
        return run_code(source or plan(), token_env=ENV, control=CONTROL, locator_store=self.store,
                        fetcher=fake or Fake(), **kwargs)

    def test_opt_in_upgrade_is_idempotent_and_preserves_existing_work(self):
        old = create_plan(scope_id="team", company_en="Fixture Motors", domains=["fixture.example"])
        self.assertNotIn("github_code", old["required_channels"])
        upgraded = enable_code_search(old)
        self.assertEqual(old["jobs"], upgraded["jobs"][:len(old["jobs"])])
        self.assertEqual(upgraded, enable_code_search(upgraded))
        jobs = [j for j in upgraded["jobs"] if j["channel"] == "github_code"]
        self.assertEqual('"fixture.example" in:file is:public', jobs[0]["value"])

    def test_only_fixed_search_endpoint_explicit_auth_no_snippets(self):
        fake = Fake()
        result = self.run_code(fake=fake)
        self.assertEqual(2, len(fake.calls))
        for parsed, query, headers in fake.calls:
            self.assertEqual("api.github.com", parsed.netloc)
            self.assertEqual("/search/code", parsed.path)
            self.assertEqual("Bearer synthetic-token-not-real", headers["Authorization"])
            self.assertNotIn("text-match", headers["Accept"])
            self.assertFalse({"Cookie", "Origin", "Referer"} & set(headers))
            self.assertTrue(query["q"][0].endswith("is:public"))
        report = export_report(result)
        encoded = json.dumps(report)
        for secret in ("synthetic-token-not-real", "pricing.json", "unrelated/app", "Fixture Motors"):
            self.assertNotIn(secret, encoded)
        asset = report["assets"][0]
        self.assertEqual("ownership_pending", asset["ownership"])
        self.assertEqual("not_measured", asset["public_exposure"])
        self.assertEqual("NOT_INSPECTED", asset["content"])
        self.assertEqual(item()["html_url"], self.store.get("team", asset["locator_ref"]))

    def test_missing_explicit_token_never_uses_ambient_github_token(self):
        fake = Fake()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ambient", "GH_TOKEN": "ambient"}):
            result = run_code(plan(), token_env="MISSING_TEST_OD_TOKEN", control=CONTROL,
                              locator_store=self.store, fetcher=fake)
        self.assertEqual([], fake.calls)
        self.assertIn("EXPLICIT_TOKEN_REQUIRED", result["code_runs"][-1]["errors"])
        self.assertTrue(any(j["state"] == "deferred" for j in result["jobs"] if j["channel"] == "github_code"))

    def test_bad_control_prevents_search_and_zero_result_confirmation(self):
        for control in (payload(), payload([item("README.md", repo="fixture/control")], incomplete=True), (401, {}, {})):
            fake = Fake(control=control)
            result = self.run_code(fake=fake)
            self.assertEqual(1, len(fake.calls))
            self.assertEqual([], result["code_assets"])
            self.assertIn("CODE_CONTROL_FAILED", result["code_runs"][-1]["errors"])

    def test_incomplete_results_preserve_candidates_but_never_complete(self):
        result = self.run_code(fake=Fake({1: payload([item()], incomplete=True)}))
        self.assertEqual(1, len(result["code_assets"]))
        self.assertIn("SEARCH_INCOMPLETE", result["code_runs"][-1]["errors"])
        self.assertEqual("partial", export_report(result)["coverage"])

    def test_zero_only_completes_bounded_query_after_positive_control(self):
        result = self.run_code(fake=Fake({1: payload()}))
        job = next(j for j in result["jobs"] if j["channel"] == "github_code" and j["state"] == "completed")
        self.assertEqual(0, job["result_count"])
        self.assertEqual("page_exhausted", job["end_condition"])
        self.assertEqual("PARTIAL", result["status"])

    def test_pages_resume_without_replaying_first_page(self):
        pages = {1: payload([item(f"file-{i}.json") for i in range(100)], total=101),
                 2: payload([item("last.json")], total=101)}
        first = self.run_code(fake=Fake(pages), request_budget=2)
        job = next(j for j in first["jobs"] if j["channel"] == "github_code" and "code_cursor" in j)
        self.assertEqual(2, job["code_cursor"]["next_page"])
        second_fake = Fake(pages)
        second = self.run_code(first, second_fake, request_budget=2)
        self.assertEqual([1, 2], [int(q["page"][0]) for _, q, _ in second_fake.calls])
        self.assertEqual(101, len(second["code_assets"]))

    def test_same_file_multiple_queries_deduplicates_and_preserves_evidence(self):
        result = self.run_code(resume_query_budget=2)
        self.assertEqual(1, len(result["code_assets"]))
        self.assertGreater(len(result["code_assets"][0]["evidence_refs"]), 1)
        self.assertEqual([], result["runs"])

    def test_distinct_paths_same_blob_do_not_collapse(self):
        result = self.run_code(fake=Fake({1: payload([item("a.json"), item("b.json")])}))
        self.assertEqual(2, len({a["asset_id"] for a in result["code_assets"]}))

    def test_nonpublic_malformed_and_foreign_urls_are_rejected(self):
        bad = item()
        bad["html_url"] = "https://evil.example/blob/main/data/pricing.json"
        variants = [item(private=True), bad, {**item(), "path": "../private.json"}, {**item(), "sha": "fake"}]
        for value in variants:
            result = self.run_code(fake=Fake({1: payload([value])}))
            self.assertEqual([], result["code_assets"])
            self.assertIn("INVALID_OR_NONPUBLIC_ITEMS", result["code_runs"][-1]["errors"])

    def test_rate_and_redirect_failures_do_not_retry_or_follow(self):
        for response, code in (((429, {}, {"x-ratelimit-reset": "2000000000"}), "RATE_LIMITED"),
                               ((302, {}, {"location": "https://evil.example"}), "REDIRECT_BLOCKED")):
            fake = Fake({1: response})
            result = self.run_code(fake=fake)
            self.assertEqual(2, len(fake.calls))
            self.assertIn(code, result["code_runs"][-1]["errors"])

    def test_report_resolves_existing_private_export(self):
        from sudetect.asset_locations import export_locations
        result = self.run_code()
        path = self.root / "report.json"
        path.write_text(json.dumps(export_report(result)), encoding="utf-8")
        self.assertEqual("RESOLVED", export_locations(path, self.root / "locations.db", "team")["assets"][0]["location_state"])
        with self.assertRaises(ValueError):
            export_locations(path, self.root / "locations.db", "wrong")

    def test_generic_import_cannot_mark_code_job_completed(self):
        source = plan()
        job = next(j for j in source["jobs"] if j["channel"] == "github_code")
        with self.assertRaises(ValueError):
            import_results(source, {"jobs": [{"work_id": job["work_id"], "state": "completed"}]})

    def test_query_qualifiers_cannot_be_injected(self):
        for query in ('"abc" in:file is:private is:public', 'abc is:public', '"abc" repo:other/repo is:public'):
            fake = Fake()
            with self.assertRaises(CodeError):
                Broker("fixture", fetcher=fake).get(query, 1)
            self.assertEqual([], fake.calls)

    def test_cli_upgrade_and_code_run(self):
        source = create_plan(scope_id="team", company_en="Fixture Motors", query_budget=1)
        plan_path, control_path, report_path = [self.root / f"{name}.json" for name in ("plan", "control", "report")]
        plan_path.write_text(json.dumps(source), encoding="utf-8")
        control_path.write_text(json.dumps(CONTROL), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(["enable-code", "--plan", str(plan_path)]))
        # Network is deliberately not invoked by this CLI test: missing explicit token.
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0, main(["run-code", "--plan", str(plan_path), "--token-env", "OD_MISSING_TEST_TOKEN",
                                     "--control", str(control_path), "--locator-store", str(self.root / "cli.db"), "--output", str(report_path)]))
        self.assertNotIn("Fixture Motors", output.getvalue())
        self.assertIn("EXPLICIT_TOKEN_REQUIRED", json.loads(report_path.read_text())["runs"][-1]["errors"])

    def test_changed_index_and_duplicate_pages_remain_partial(self):
        first_page = [item(f"file-{i}.json") for i in range(100)]
        for second in (payload(first_page, total=200), payload([item("last.json")], total=201)):
            result = self.run_code(fake=Fake({1: payload(first_page, total=200), 2: second}))
            codes = result["code_runs"][-1]["errors"]
            self.assertTrue({"SEARCH_RESULTS_OVERLAP", "SEARCH_INDEX_CHANGED"} & set(codes))
            self.assertEqual("partial", export_report(result)["coverage"])

    def test_provider_result_cap_never_claims_full_coverage(self):
        source = plan()
        job = next(j for j in source["jobs"] if j["channel"] == "github_code" and j["state"] == "planned")
        import hashlib
        job["code_cursor"] = {"query_sha256": hashlib.sha256(job["value"].encode()).hexdigest(),
                              "next_page": 10, "items": 900, "pages": 9, "total_count": 1001}
        fake = Fake({10: payload([item(f"last-{i}.json") for i in range(100)], total=1001)})
        result = self.run_code(source, fake)
        self.assertIn("PROVIDER_RESULT_CAP", result["code_runs"][-1]["errors"])
        self.assertEqual(2, len(fake.calls))

    def test_private_repositories_do_not_become_assets_even_with_text_match(self):
        value = item(private=True)
        value["text_matches"] = [{"fragment": "DO_NOT_EXPORT_SYNTHETIC_VALUE"}]
        result = self.run_code(fake=Fake({1: payload([value])}))
        self.assertNotIn("DO_NOT_EXPORT_SYNTHETIC_VALUE", json.dumps(result))
        self.assertFalse(result["code_assets"])

    def test_new_sha_same_file_preserves_revision_history(self):
        first = self.run_code()
        first_job = next(j for j in first["jobs"] if j["channel"] == "github_code" and j["state"] == "completed")
        first_job.update(state="failed", error_code="SEARCH_INDEX_CHANGED")
        second = self.run_code(first, Fake({1: payload([item(sha="c" * 40)])}), retry_failed=True)
        self.assertEqual(1, len(second["code_assets"]))
        self.assertEqual(2, len(second["code_assets"][0]["revisions"]))
        self.assertEqual(first["code_assets"][0]["asset_id"], second["code_assets"][0]["asset_id"])

    def test_real_path_broker_disables_proxy_redirects_and_bounds_errors(self):
        import urllib.error
        seen = []
        class Opener:
            def open(self, request, timeout):
                seen.append(request)
                raise urllib.error.HTTPError(request.full_url, 302, "ignored-secret", {"Location": "https://outside.example"}, None)
        with patch("sudetect.github_code_search.urllib.request.build_opener", return_value=Opener()) as builder:
            with self.assertRaisesRegex(CodeError, "REDIRECT_BLOCKED"):
                Broker("only-explicit-token").get('"fixture" in:file is:public', 1)
        handlers = builder.call_args.args
        self.assertEqual({}, handlers[0].proxies)
        self.assertEqual("_NoRedirect", type(handlers[1]).__name__)
        self.assertEqual(1, len(seen))
        self.assertEqual("GET", seen[0].get_method())

    def test_live_window_exhaustion_prevents_network_even_for_control(self):
        import time
        source = plan()
        source["code_rate_window"] = {"started": time.time(), "used": 10}
        with patch("sudetect.github_code_search.urllib.request.build_opener") as opener:
            result = run_code(source, token_env=ENV, control=CONTROL, locator_store=self.store)
        opener.assert_not_called()
        self.assertIn("RATE_WINDOW_EXHAUSTED", result["code_runs"][-1]["errors"])

    def test_existing_anonymous_runner_never_executes_code_jobs(self):
        source = plan()
        for job in source["jobs"]:
            if job["channel"] == "github":
                job.update(state="not_applicable", not_applicable_reason="fixture-only")
        fake = Fake()
        result = run_plan(source, fetch=fake)
        self.assertEqual([], fake.calls)
        self.assertTrue(any(j["state"] == "planned" for j in result["jobs"] if j["channel"] == "github_code"))


if __name__ == "__main__":
    unittest.main()
