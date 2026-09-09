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
    def __init__(self, pages=None, control=None, repositories=None):
        self.calls = []
        self.pages = pages or {}
        self.control = payload([item("README.md", repo="fixture/control")]) if control is None else control
        self.repositories = repositories or {}

    def __call__(self, url, headers):
        parsed = urlsplit(url)
        self.calls.append((parsed, parse_qs(parsed.query), headers))
        if parsed.path.startswith("/repos/"):
            slug = parsed.path.removeprefix("/repos/")
            return self.repositories.get(slug, {"full_name": slug, "private": False, "visibility": "public"})
        query = parse_qs(parsed.query)
        if "repo:fixture/control" in query["q"][0]:
            return self.control
        return self.pages.get(int(query["page"][0]), payload([item()]))


def plan():
    result = create_plan(scope_id="team", company_en="Fixture Motors", query_budget=1, account_budget=1,
                         github_code=True, repositories=["unrelated/app"])
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
        upgraded = enable_code_search(old, ["unrelated/app"])
        self.assertEqual(old["jobs"], upgraded["jobs"][:len(old["jobs"])])
        self.assertEqual(upgraded, enable_code_search(upgraded, ["unrelated/app"]))
        jobs = [j for j in upgraded["jobs"] if j["channel"] == "github_code"]
        self.assertEqual('"fixture.example" repo:unrelated/app in:file', jobs[0]["value"])

    def test_only_fixed_search_endpoint_explicit_auth_no_snippets(self):
        fake = Fake()
        result = self.run_code(fake=fake)
        self.assertEqual(4, len(fake.calls))
        for parsed, query, headers in fake.calls:
            self.assertEqual("api.github.com", parsed.netloc)
            if parsed.path.startswith("/repos/"):
                self.assertNotIn("Authorization", headers)
                continue
            self.assertEqual("/search/code", parsed.path)
            self.assertEqual("Bearer synthetic-token-not-real", headers["Authorization"])
            self.assertNotIn("text-match", headers["Accept"])
            self.assertFalse({"Cookie", "Origin", "Referer"} & set(headers))
            self.assertRegex(query["q"][0], r'^".+" repo:[^ ]+/[^ ]+ in:file$')
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
        resumed = self.run_code(result, Fake())
        self.assertTrue(any(job["state"] == "completed" for job in resumed["jobs"] if job["channel"] == "github_code"))

    def test_bad_control_prevents_search_and_zero_result_confirmation(self):
        for control in (payload(), payload([item("README.md", repo="fixture/control")], incomplete=True), (401, {}, {})):
            fake = Fake(control=control)
            result = self.run_code(fake=fake)
            self.assertEqual(2, len(fake.calls))
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
        first = self.run_code(fake=Fake(pages), request_budget=4)
        job = next(j for j in first["jobs"] if j["channel"] == "github_code" and "code_cursor" in j)
        self.assertEqual(2, job["code_cursor"]["next_page"])
        second_fake = Fake(pages)
        second = self.run_code(first, second_fake, request_budget=4)
        self.assertEqual([1, 2], [int(q["page"][0]) for parsed, q, _ in second_fake.calls if parsed.path == "/search/code"])
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
            self.assertEqual(4, len(fake.calls))
            self.assertIn(code, result["code_runs"][-1]["errors"])

    def test_explicit_retry_recovers_auth_and_transient_request_failures_only(self):
        for failure in ("AUTH_FAILED", "REQUEST_FAILED"):
            def failing_fetch(url, headers, *, _failure=failure):
                parsed = urlsplit(url)
                query = parse_qs(parsed.query).get("q", [""])[0]
                if parsed.path == "/search/code" and "repo:fixture/control" not in query:
                    if _failure == "AUTH_FAILED":
                        return (401, {}, {})
                    raise OSError("synthetic transient failure")
                return Fake()(url, headers)

            first = self.run_code(fake=failing_fetch)
            first_job = next(job for job in first["jobs"] if job["channel"] == "github_code" and
                             job.get("error_code") == failure)
            self.assertEqual("failed", first_job["state"])
            not_retried = self.run_code(first, Fake())
            self.assertEqual([], not_retried["code_runs"][-1]["errors"])
            self.assertEqual("failed", next(job for job in not_retried["jobs"] if job["work_id"] == first_job["work_id"])["state"])
            recovered = self.run_code(first, Fake(), retry_failed=True)
            self.assertEqual("completed", next(job for job in recovered["jobs"] if job["work_id"] == first_job["work_id"])["state"])

        first = self.run_code(fake=Fake({1: payload([item()], incomplete=True)}))
        incomplete = next(job for job in first["jobs"] if job["channel"] == "github_code" and
                          job.get("error_code") == "SEARCH_INCOMPLETE")
        blocked = self.run_code(first, Fake(), retry_failed=True)
        self.assertEqual("failed", next(job for job in blocked["jobs"] if job["work_id"] == incomplete["work_id"])["state"])
        self.assertEqual(0, blocked["code_runs"][-1]["requests"])

    def test_report_resolves_existing_private_export(self):
        from sudetect.asset_locations import export_locations
        result = self.run_code()
        path = self.root / "report.json"
        path.write_text(json.dumps(export_report(result)), encoding="utf-8")
        mapping = export_locations(path, self.root / "locations.db", "team")["assets"][0]
        self.assertEqual("RESOLVED", mapping["location_state"])
        self.assertTrue(mapping["private_location"].endswith("data/pricing.json"))
        with self.assertRaises(ValueError):
            export_locations(path, self.root / "locations.db", "wrong")

    def test_generic_import_cannot_mark_code_job_completed(self):
        source = plan()
        job = next(j for j in source["jobs"] if j["channel"] == "github_code")
        with self.assertRaises(ValueError):
            import_results(source, {"jobs": [{"work_id": job["work_id"], "state": "completed"}]})

    def test_query_qualifiers_cannot_be_injected(self):
        for query in ('"abc" in:file', 'abc repo:other/repo in:file', '"abc" repo:other/repo in:file is:public'):
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
            self.assertEqual(0, main(["enable-code", "--plan", str(plan_path), "--repository", "unrelated/app"]))
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
        self.assertEqual(4, len(fake.calls))

    def test_invalid_or_mismatched_scoped_job_never_reaches_control(self):
        source = plan()
        job = next(job for job in source["jobs"] if job["channel"] == "github_code")
        work_id = job["work_id"]
        job["value"] = '"Fixture Motors" repo:other/repository in:file'
        fake = Fake()
        result = self.run_code(source, fake)
        self.assertEqual([], fake.calls)
        current = next(item for item in result["jobs"] if item["work_id"] == job["work_id"])
        self.assertEqual("deferred", current["state"])
        self.assertEqual("repository_scope_required", current["deferred_reason"])
        self.assertIn("REPOSITORY_SCOPE_REQUIRED", result["code_runs"][-1]["errors"])

    def test_legacy_unscoped_job_stays_deferred_without_control(self):
        source = plan()
        legacy = next(job for job in source["jobs"] if job["channel"] == "github_code")
        legacy.pop("repository")
        legacy["value"] = '"Fixture Motors" in:file is:public'
        source["code_repositories"] = []
        fake = Fake()
        result = self.run_code(source, fake)
        self.assertEqual([], fake.calls)
        self.assertEqual("NO_RUNNABLE_WORK", result["code_runs"][-1]["status"])
        self.assertIn("REPOSITORY_SCOPE_REQUIRED", result["code_runs"][-1]["errors"])

    def test_completed_scope_rerun_and_unknown_deferred_work_do_not_make_requests(self):
        complete = self.run_code(fake=Fake())
        rerun_fake = Fake()
        rerun = self.run_code(complete, rerun_fake)
        self.assertEqual([], rerun_fake.calls)
        self.assertEqual("NO_RUNNABLE_WORK", rerun["code_runs"][-1]["status"])
        self.assertEqual([], rerun["code_runs"][-1]["errors"])
        expired = dict(CONTROL, expires_at="2000-01-01T00:00:00Z")
        no_token = run_code(complete, token_env="MISSING_NOOP_TOKEN", control=expired,
                            locator_store=self.store, fetcher=Fake())
        self.assertEqual([], no_token["code_runs"][-1]["errors"])
        deferred = plan()
        job = next(job for job in deferred["jobs"] if job["channel"] == "github_code")
        job.update(state="deferred", deferred_reason="fixture_non_target_deferred")
        result = self.run_code(deferred, Fake())
        self.assertEqual([], result["code_runs"][-1]["errors"])

    def test_budget_deferred_job_requires_explicit_resume_budget(self):
        source = plan()
        job = next(job for job in source["jobs"] if job["channel"] == "github_code")
        work_id = job["work_id"]
        job.update(state="deferred", deferred_reason="query_budget_exceeded")
        blocked = self.run_code(source, Fake())
        self.assertEqual([], blocked["code_runs"][-1]["errors"])
        resumed = self.run_code(source, Fake(), resume_query_budget=1)
        self.assertEqual("completed", next(job for job in resumed["jobs"] if job["work_id"] == work_id)["state"])

    def test_scoped_report_excludes_repository_and_query_text_but_keeps_scope_contract(self):
        result = self.run_code(fake=Fake())
        report = export_report(result)
        encoded = json.dumps(report)
        self.assertNotIn("unrelated/app", encoded)
        self.assertNotIn("Fixture Motors", encoded)
        self.assertFalse(report["global_search_performed"])
        self.assertEqual(1, report["selected_repository_scope"]["repository_count"])
        self.assertEqual(1, len(report["selected_repository_scope"]["repository_locator_refs"]))
        self.assertEqual(1, report["job_counts"]["completed"])
        self.assertEqual("partial", report["coverage"])

    def test_scoped_report_uses_configured_scope_and_keeps_invalid_jobs_as_gaps(self):
        source = plan()
        invalid = next(job for job in source["jobs"] if job["channel"] == "github_code" and job["state"] == "planned")
        invalid.update(repository="other/repository", value='"Fixture Motors" repo:other/repository in:file')
        source["code_repository_locator_refs"] = {
            "unrelated/app": self.store.put("team", "https://github.com/unrelated/app"),
            "other/repository": self.store.put("team", "https://github.com/other/repository"),
        }
        result = self.run_code(source, Fake())
        report = export_report(result)
        self.assertEqual(1, report["selected_repository_scope"]["repository_count"])
        self.assertEqual(1, len(report["selected_repository_scope"]["repository_locator_refs"]))
        self.assertEqual(0, report["selected_repository_scope"]["attempted_repository_count"])
        self.assertEqual(1, report["job_counts"]["scope_gap"])
        self.assertEqual("partial", report["coverage"])

    def test_selected_repository_without_a_matching_job_stays_partial(self):
        source = plan()
        source["code_repositories"].append("other/repository")
        report = export_report(source)
        self.assertEqual(2, report["selected_repository_scope"]["repository_count"])
        self.assertEqual("partial", report["coverage"])

    def test_missing_repository_job_is_a_scope_gap_and_refs_must_be_opaque(self):
        source = plan()
        missing = next(job for job in source["jobs"] if job["channel"] == "github_code" and job["state"] == "planned")
        missing.pop("repository")
        missing.update(state="deferred", deferred_reason="repository_scope_required")
        source["code_repository_locator_refs"] = {"unrelated/app": "https://not-an-opaque-reference.example"}
        report = export_report(source)
        self.assertEqual(1, report["job_counts"]["scope_gap"])
        self.assertEqual([], report["selected_repository_scope"]["repository_locator_refs"])
        self.assertEqual("partial", report["coverage"])

    def test_legacy_superseded_job_is_not_a_scope_gap(self):
        source = plan()
        legacy = next(job for job in source["jobs"] if job["channel"] == "github_code")
        legacy.pop("repository")
        legacy.update(state="deferred", deferred_reason="superseded_by_repository_scoped_jobs")
        report = export_report(source)
        self.assertEqual(1, report["job_counts"]["legacy_superseded"])
        self.assertEqual(0, report["job_counts"]["scope_gap"])

    def test_case_variant_repository_reenable_is_idempotent(self):
        source = create_plan(scope_id="team", company_en="Fixture Motors", query_budget=1)
        first = enable_code_search(source, ["Owner/Repository"])
        second = enable_code_search(first, ["owner/repository"])
        self.assertEqual(1, len(second["code_repositories"]))
        self.assertEqual(len([job for job in first["jobs"] if job["channel"] == "github_code"]),
                         len([job for job in second["jobs"] if job["channel"] == "github_code"]))

    def test_preflight_failure_counts_the_attempt_and_blocks_authenticated_search(self):
        source = plan()
        fake = Fake(repositories={"fixture/control": {"full_name": "fixture/control", "private": True, "visibility": "private"}})
        result = self.run_code(source, fake)
        self.assertEqual(1, len(fake.calls))
        self.assertEqual(1, result["code_runs"][-1]["requests"])
        self.assertEqual(1, result["code_runs"][-1]["public_preflights"])
        self.assertEqual("REPOSITORY_NOT_PUBLIC", result["code_runs"][-1]["control"]["error_code"])

    def test_long_valid_scoped_query_and_failed_preflight_keep_exact_request_counts(self):
        repository = "a" * 39 + "/" + "b" * 100
        query = '"' + "x" * 180 + '" repo:' + repository + " in:file"
        fake = Fake()
        Broker("fixture", fetcher=fake).get(query, 1)
        self.assertEqual(2, len(fake.calls))
        exhausted = Broker("fixture", limit=0, fetcher=Fake())
        with self.assertRaisesRegex(CodeError, "REQUEST_BUDGET"):
            exhausted.preflight("fixture/control")
        self.assertEqual(0, exhausted.requests)
        self.assertEqual(0, exhausted.public_preflights)

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
                Broker("only-explicit-token").get('"fixture" repo:fixture/control in:file', 1)
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
