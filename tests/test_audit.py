"""Synthetic end-to-end case handoff, independent discovery, and crash recovery."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

from sudetect.audit import Case, init_case, main, report_case, run_case
from sudetect.policy import Scope
from sudetect.transport import FetchResult


def policy():
    return Scope.from_dict({"policy_id": "synthetic", "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://seed.test", "owner": "owner", "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]},
                    {"origin": "https://nebula-sales.github.io", "owner": "owner", "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}]})


def api(url, headers):
    path = urlsplit(url).path
    if path == "/search/users":
        return 200, {"items": [], "total_count": 0}, {}
    if path == "/search/repositories":
        return 200, {"items": [{"name": "guide", "full_name": "nebula-sales/guide", "private": False,
            "has_pages": True, "owner": {"login": "nebula-sales"}}], "total_count": 1}, {}
    return 200, [], {}


def response(url, scope):
    scope.authorize(url)
    scope.budget.consume()
    body = b'<html><body>Public welcome<script src="/rules.js"></script><a href="/policy.pdf">Policy</a></body></html>'
    content_type = "text/html"
    if url.endswith(".js"):
        body, content_type = b'const commission = 2 * 3;', "application/javascript"
    if url.endswith(".pdf"):
        body, content_type = b'%PDF-invalid-synthetic', "application/pdf"
    return FetchResult({"observation_id": str(uuid.uuid4()), "observed_at": datetime.now(timezone.utc).isoformat(),
        "policy_id": scope.policy_id, "access": "BODY_SERVED", "capture_complete": True,
        "http_status": 200, "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(),
        "redirects": []}, body, {"content-type": content_type})


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Nebula", "domains": ["seed.test"]}})

    def tearDown(self):
        self.temp.cleanup()

    def test_seed_only_discovery_and_new_link_followup_survive_handoff(self):
        calls = []
        def fetch(url, scope):
            calls.append(url)
            return response(url, scope)
        with Case(self.root) as case:
            result = run_case(case, {"max_requests": 35, "max_jobs": 15}, scope=policy(),
                              fetcher=fetch, api_fetch=api, agent="codex")
            self.assertIn("https://seed.test/", calls)
            self.assertIn("https://seed.test/rules.js", calls)
            self.assertIn("https://seed.test/policy.pdf", calls)
            self.assertTrue(any("nebula-sales.github.io" in u for u in calls))
            self.assertFalse(result["complete"])
            self.assertTrue(any(j["job_type"] == "content_review" for j in result["jobs"]))
            count = len(calls)
        with Case(self.root) as case:
            run_case(case, {"max_requests": 5}, scope=policy(), fetcher=fetch, agent="claude")
            self.assertEqual(count, len(calls), "completed captures must not be repeated")
            report = report_case(case)
            self.assertEqual(len(report["results"]), case.ledger.db.execute("SELECT COUNT(*) FROM audit_results").fetchone()[0])
            self.assertNotIn("Public welcome", json.dumps(report))

    def test_no_health_blocks_only_discovery_not_owned_capture(self):
        with Case(self.root) as case:
            status = run_case(case, {"max_requests": 4}, scope=policy(), fetcher=response)
            captures = [j for j in status["jobs"] if j["job_type"] == "capture"]
            self.assertTrue(any(j["state"] == "succeeded" for j in captures))
            self.assertTrue(any(j["last_error_code"] == "CHANNEL_HEALTH_REQUIRED" for j in status["jobs"]))
            self.assertFalse(status["complete"])

    def test_capture_partial_never_overwritten_by_classifier(self):
        def partial(url, scope):
            result = response(url, scope)
            result.observation["capture_complete"] = False
            return result
        with Case(self.root) as case:
            run_case(case, {"max_requests": 1}, scope=policy(), fetcher=partial)
            reports = report_case(case)["results"]
            self.assertFalse(reports[0]["report"]["capture_complete"])
            self.assertFalse(reports[0]["report"]["analysis_complete"])

    def test_committed_capture_recovered_without_duplicate_request(self):
        with Case(self.root) as case:
            run_case(case, {"max_requests": 1}, scope=policy(), fetcher=response)
            job = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "capture" and j["state"] == "succeeded")
            case.ledger.db.execute("UPDATE audit_jobs SET state='running',lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id=?", (job["job_id"],))
            case.ledger.db.commit()
            with patch("sudetect.audit._capture", wraps=__import__("sudetect.audit", fromlist=["_capture"])._capture):
                calls = []
                def fetched(url, scope):
                    calls.append(url)
                    return response(url, scope)
                run_case(case, {"max_requests": 3}, scope=policy(), fetcher=fetched)
                self.assertNotIn("https://seed.test/", calls)

    def test_cli_evaluate_is_only_reader_of_reference(self):
        reference = Path(self.temp.name) / "held-out.json"
        reference.write_text(json.dumps({"urls": ["https://seed.test/", "https://unknown.test/"]}), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["evaluate", "--case", str(self.root), "--reference", str(reference)]))
        self.assertEqual(1, json.loads(output.getvalue())["found"])
        with patch("sudetect.audit.read_json", wraps=__import__("sudetect.audit", fromlist=["read_json"]).read_json) as reader:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["status", "--case", str(self.root), "--json"]))
            self.assertFalse(any(str(reference) == str(call.args[0]) for call in reader.call_args_list))

    def test_adapters_share_contract(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "AGENTS.md").read_text(), (root / "CLAUDE.md").read_text())

    def test_transient_failure_survives_and_retries_after_due(self):
        def failure(url, scope):
            item = response(url, scope)
            item.body = b""
            item.observation.update(http_status=None, access="INDETERMINATE", capture_complete=False, reason="timeout")
            return item
        with Case(self.root) as case:
            run_case(case, {"max_requests": 2}, scope=policy(), fetcher=failure)
            job = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "capture")
            self.assertEqual("retry_wait", job["state"])
            case.ledger.db.execute("UPDATE audit_jobs SET next_eligible_at='2000-01-01T00:00:00Z' WHERE job_id=?", (job["job_id"],))
            case.ledger.db.commit()
            run_case(case, {"max_requests": 1}, scope=policy(), fetcher=response)
            item = next(j for j in case.queue.status()["jobs"] if j["job_id"] == job["job_id"])
            self.assertEqual("succeeded", item["state"])
            self.assertEqual(2, item["attempts"])

    def test_schema_and_result_append_only(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional jsonschema unavailable")
        import sqlite3
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas/audit-job.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        with Case(self.root) as case:
            run_case(case, {"max_requests": 1}, scope=policy(), fetcher=response)
            for job in case.queue.status()["jobs"]:
                jsonschema.validate(job, schema)
            with self.assertRaises(sqlite3.IntegrityError):
                case.ledger.db.execute("DELETE FROM audit_results")
            case.ledger.db.rollback()

    def test_report_cannot_replace_case_state(self):
        before = (self.root / "case.json").read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["report", "--case", str(self.root), "--output", str(self.root / "case.json")])
        self.assertEqual(2, code)
        self.assertEqual(before, (self.root / "case.json").read_bytes())

    def test_report_rejects_state_files_through_case_directory_alias(self):
        # A lexical alias reproduces the asymmetric resolve bug on every OS;
        # Windows CI additionally exercises short-name aliases in its TEMP path.
        alias_parent = self.root.parent / "alias"
        alias_parent.mkdir()
        alias = alias_parent / ".." / self.root.name
        for name in ("case.json", "search-plan.json", "ledger.sqlite", "locators.sqlite"):
            with self.subTest(name=name), patch("sudetect.audit.report_case") as report:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(["report", "--case", str(alias), "--output", str(self.root / name)])
                self.assertEqual(2, code)
                report.assert_not_called()
        with Case(self.root) as case:
            self.assertEqual("fixture", case.scope_id)

    def test_report_allows_separate_file_through_case_directory_alias(self):
        alias_parent = self.root.parent / "alias"
        alias_parent.mkdir()
        alias = alias_parent / ".." / self.root.name
        output = self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["report", "--case", str(alias), "--output", str(output)])
        self.assertEqual(0, code)
        self.assertIn("coverage", json.loads(output.read_text(encoding="utf-8")))

    def test_search_rate_limit_does_not_poison_core_transport(self):
        calls = []
        def limited(url, headers):
            calls.append(urlsplit(url).path)
            if urlsplit(url).path.startswith("/search/"):
                return 429, {}, {"retry-after": "180"}
            return 200, [], {}
        with Case(self.root) as case:
            result = run_case(case, {"max_requests": 12}, api_fetch=limited)
            self.assertTrue(any(path.startswith("/users/") for path in calls))
            plan = json.loads((self.root / "search-plan.json").read_text(encoding="utf-8"))
            limited_jobs = [j for j in plan["jobs"] if j.get("error_code") == "RATE_LIMITED"]
            self.assertTrue(limited_jobs)
            due = datetime.fromisoformat(limited_jobs[0]["next_eligible_at"].replace("Z", "+00:00"))
            self.assertGreater((due - datetime.now(timezone.utc)).total_seconds(), 150)

    def test_agent_labels_produce_same_normalized_outcomes(self):
        normalized = []
        for label in ("codex", "claude"):
            root = Path(self.temp.name) / label
            init_case(root, {"scope_id": "fixture", "identity": {"company_en": "Nebula", "domains": ["seed.test"]}})
            with Case(root) as case:
                result = run_case(case, {"max_requests": 4}, scope=policy(), fetcher=response, agent=label)
                def location(job):
                    return case.locators.get(case.scope_id, job["asset_ref"]) if job["asset_ref"].startswith("opaque:") else job["asset_ref"]
                normalized.append(sorted((j["job_type"], location(j), j["state"], j["last_error_code"] or "") for j in result["jobs"]))
        self.assertEqual(normalized[0], normalized[1])

    def test_repository_file_unlinked_from_page_enters_content_pipeline(self):
        scoped = Scope.from_dict({"policy_id": "repo-test", "expires_at": "2099-01-01T00:00:00Z",
            "targets": [{"origin": origin, "owner": "fixture-owner", "ownership_evidence": "fixture:owner", "path_prefixes": ["/"]}
                for origin in ("https://api.github.com", "https://raw.githubusercontent.com")]})
        def metadata(url, headers):
            result = api(url, headers)
            if urlsplit(url).path == "/search/repositories":
                result[1]["items"][0]["default_branch"] = "release-v2"
            return result
        calls = []
        def files(url, scope):
            calls.append(url)
            item = response(url, scope)
            if urlsplit(url).hostname == "api.github.com":
                item.body = json.dumps({"tree": [{"path": "private-plan.pdf", "type": "blob", "sha": "a" * 40, "size": 17}], "truncated": False}).encode()
                item.headers = {"content-type": "application/json"}
            return item
        with Case(self.root) as case:
            run_case(case, {"max_requests": 45, "max_jobs": 20}, scope=scoped, fetcher=files, api_fetch=metadata)
            self.assertIn("https://api.github.com/repos/nebula-sales/guide/git/trees/release-v2?recursive=1", calls)
            self.assertIn("https://raw.githubusercontent.com/nebula-sales/guide/release-v2/private-plan.pdf", calls)
            report = json.dumps(report_case(case))
            self.assertNotIn("private-plan.pdf", report)

    def test_redirect_uses_response_url_not_html_base_and_honors_limit(self):
        for maximum in (0, 1):
            root = Path(self.temp.name) / ("redirect" + str(maximum))
            init_case(root, {"scope_id": "fixture", "identity": {"company_en": "Nebula", "domains": ["seed.test"]}})
            calls = []
            def redirected(url, scope):
                calls.append(url)
                item = response(url, scope)
                item.body = b'<html><base href="/other/"><p>Welcome</p></html>'
                if url == "https://seed.test/":
                    item.observation.update(http_status=302, access="INDETERMINATE")
                    item.headers["location"] = "next"
                return item
            selected = policy()
            selected.max_redirects = maximum
            with Case(root) as case:
                run_case(case, {"max_requests": 5}, scope=selected, fetcher=redirected)
                self.assertNotIn("https://seed.test/other/next", calls)
                self.assertEqual(maximum == 1, "https://seed.test/next" in calls)

    def test_secret_redirect_not_persisted_and_stale_worker_cannot_save(self):
        def rejected(url, scope):
            item = response(url, scope)
            item.body = b""
            item.observation.update(http_status=302, access="INDETERMINATE")
            item.headers["location"] = "/next?token=SU_DETECT_SYNTHETIC_PRIVATE"
            return item
        with Case(self.root) as case:
            run_case(case, {"max_requests": 3}, scope=policy(), fetcher=rejected)
            urls = [row[0] for row in case.locators.db.execute("SELECT url FROM locators")]
            self.assertFalse(any("SU_DETECT_SYNTHETIC_PRIVATE" in url for url in urls))
            job = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "capture")
            with self.assertRaises(ValueError):
                case.save_result(job, {"status": "stale"})

    def test_result_checkpoint_precedes_ledger_projection(self):
        with Case(self.root) as case:
            with patch("sudetect.audit._project_observation", side_effect=KeyboardInterrupt):
                interrupted = run_case(case, {"max_requests": 1}, scope=policy(), fetcher=response)
            self.assertEqual("user_stop", interrupted["run"]["reason"])
            self.assertEqual(1, case.ledger.db.execute("SELECT COUNT(*) FROM audit_results").fetchone()[0])
            self.assertEqual(0, case.ledger.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0])
            def other(url, scope):
                self.assertNotEqual("https://seed.test/", url, "committed response must be reused")
                return response(url, scope)
            run_case(case, {"max_requests": 3}, scope=policy(), fetcher=other)
            self.assertGreater(case.ledger.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)

    @unittest.skipUnless(importlib.util.find_spec("playwright"), "optional browser unavailable")
    def test_runtime_constructed_endpoint_is_retained_without_duplicate_network(self):
        calls = []
        def runtime(url, scope):
            calls.append(url)
            item = response(url, scope)
            if url == "https://seed.test/":
                item.body = b'<html><body><script>const endpoint=["runtime","data"].join("-");fetch(endpoint);</script></body></html>'
            else:
                item.body = b'{"customer_name":"SYNTHETIC_CUSTOMER","phone":"010-1234-5678"}'
                item.headers = {"content-type": "application/json"}
            return item
        with Case(self.root) as case:
            run_case(case, {"max_requests": 5}, scope=policy(), fetcher=runtime)
            self.assertEqual(1, calls.count("https://seed.test/"))
            self.assertEqual(1, calls.count("https://seed.test/runtime-data"))
            locations = [case.locators.get(case.scope_id, j["asset_ref"]) for j in case.queue.status()["jobs"] if j["job_type"] == "capture"]
            self.assertIn("https://seed.test/runtime-data", locations)
            rendered = json.dumps(report_case(case))
            self.assertNotIn("SYNTHETIC_CUSTOMER", rendered)
            self.assertNotIn("010-1234-5678", rendered)
            self.assertEqual({}, case.transient_responses)

    def test_new_capability_resumes_pending_gate_without_per_page_instruction(self):
        calls = []
        def hidden(url, scope):
            calls.append(url)
            item = response(url, scope)
            item.body = b'<html><input type="password"><div hidden>commission 10%</div></html>'
            return item
        def gate(*args, capability=None, **kwargs):
            return {"auth_ui_present": True, "client_gate_tested": capability is not None}
        with Case(self.root) as case, patch("sudetect.gate_review.review_gate", side_effect=gate):
            run_case(case, {"max_requests": 3}, scope=policy(), fetcher=hidden)
            review = next(j for j in case.queue.status()["jobs"] if j["job_type"] == "content_review")
            self.assertEqual("blocked_input", review["state"])
            run_case(case, {"max_requests": 3}, scope=policy(), fetcher=hidden)
            self.assertEqual(1, len(calls), "unchanged missing input must not cause a retry loop")
            run_case(case, {"max_requests": 3}, scope=policy(), fetcher=hidden, capability={"authorization_ref": "fixture:approved"})
            revised = next(j for j in case.queue.status()["jobs"] if j["job_id"] == review["job_id"])
            self.assertEqual("succeeded", revised["state"])
            self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
