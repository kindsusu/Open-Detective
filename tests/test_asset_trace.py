import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sudetect.asset_trace import extract_references, trace_assets
from sudetect.locators import LocatorStore, LocatorError
from sudetect.policy import Scope
from sudetect.transport import fetch


def make_scope(**changes):
    raw = {
        "policy_id": "trace-test",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "targets": [{"origin": "https://app.example", "owner": "fixture-owner",
                     "ownership_evidence": "fixture-record", "path_prefixes": ["/"]}],
        "exclude_urls": [], "max_bytes": 65536, "max_requests": 20,
        "timeout": 3, "max_redirects": 3,
    }
    raw.update(changes)
    return Scope.from_dict(raw)


class Response:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body
        self.offset = 0
        self.headers = {key.casefold(): value for key, value in (headers or {}).items()}

    def read(self, amount=-1):
        if amount < 0:
            amount = len(self.body) - self.offset
        value = self.body[self.offset:self.offset + amount]
        self.offset += len(value)
        return value

    def getheader(self, name):
        return self.headers.get(name.casefold())


class Connection:
    def __init__(self, routes, calls, host, pin):
        self.routes = routes
        self.calls = calls
        self.host = host
        self.pin = pin
        self.target = None

    def request(self, method, target, headers):
        self.target = target
        self.calls.append((method, self.host, target, dict(headers), self.pin))

    def getresponse(self):
        route = self.routes.get((self.host, self.target), (404, b"missing", {"Content-Type": "text/plain"}))
        status, body, headers = route
        if isinstance(body, str):
            body = body.encode()
        return Response(status, body, headers)

    def close(self):
        pass


def production_broker(routes, calls):
    def connection_factory(host, port, pin, timeout):
        return Connection(routes, calls, host, pin)

    def broker(url, scope, **kwargs):
        return fetch(url, scope, resolver=lambda host, port: ["93.184.216.34"],
                     connection_factory=connection_factory, **kwargs)
    return broker


def route(status, body, content_type="text/html", **headers):
    values = {"Content-Type": content_type, **headers}
    return status, body, values


class AssetTraceTests(unittest.TestCase):
    def run_trace(self, routes, **kwargs):
        calls = []
        result = trace_assets("https://app.example/", make_scope(),
                              fetcher=production_broker(routes, calls), **kwargs)
        return result, calls

    def test_gate_source_script_and_literal_json_are_observed_with_anonymous_get(self):
        routes = {
            ("app.example", "/"): route(200, '<input type="password"><script src="/app.js"></script>'),
            ("app.example", "/app.js"): route(200, 'fetch("/data.json")', "text/javascript"),
            ("app.example", "/data.json"): route(200, '{"items":[1]}', "application/json"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual([row[2] for row in calls], ["/", "/app.js", "/data.json"])
        self.assertTrue(all(row[0] == "GET" for row in calls))
        self.assertTrue(all(not ({"authorization", "cookie", "referer", "origin"} &
                                    {key.casefold() for key in row[3]}) for row in calls))
        self.assertEqual([a["relation"] for a in result["assets"]], ["root", "script_src", "fetch_literal"])
        self.assertEqual("complete", result["coverage"]["state"])
        self.assertIn("LOGIN_FORM_INDICATOR", {s["code"] for s in result["assets"][0]["signals"]})

    def test_denied_json_is_access_denied_and_does_not_make_login_root_protected(self):
        routes = {
            ("app.example", "/"): route(200, '<input type="password"><script>fetch("/data")</script>'),
            ("app.example", "/data"): route(401, '{"error":"login required"}', "application/json"),
        }
        result, _ = self.run_trace(routes)
        self.assertEqual("BODY_SERVED", result["assets"][0]["access"])
        self.assertEqual("ACCESS_DENIED_OBSERVED", result["assets"][1]["access"])
        self.assertEqual("partial", result["coverage"]["state"])

    def test_offscope_reference_is_a_redacted_gap(self):
        routes = {("app.example", "/"): route(200, '<script src="https://outside.example/private/x.js"></script>')}
        result, calls = self.run_trace(routes)
        self.assertEqual(1, len(calls))
        self.assertIn("reference_out_of_scope_or_invalid", result["coverage"]["reason_codes"])
        self.assertNotIn("outside.example", json.dumps(result))
        self.assertNotIn("private/x.js", json.dumps(result))

    def test_redirected_document_base_is_used_for_script_and_script_fetch(self):
        routes = {
            ("app.example", "/"): route(302, b"move", Location="/ui/index.html"),
            ("app.example", "/ui/index.html"): route(200, '<script src="js/app.js"></script>'),
            ("app.example", "/ui/js/app.js"): route(200, 'fetch("./data.json")', "text/javascript"),
            ("app.example", "/ui/data.json"): route(200, "{}", "application/json"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual([row[2] for row in calls],
                         ["/", "/ui/index.html", "/ui/js/app.js", "/ui/data.json"])
        self.assertEqual(1, len(result["assets"][0]["redirects"]))
        self.assertEqual(4, result["usage"]["requests"])

    def test_valid_base_is_used_and_invalid_base_blocks_relative_references(self):
        routes = {
            ("app.example", "/"): route(200, '<base href="/assets/"><script src="app.js"></script>'),
            ("app.example", "/assets/app.js"): route(200, "", "text/javascript"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual(["/", "/assets/app.js"], [row[2] for row in calls])
        bad = {("app.example", "/"): route(200, '<base href="https://outside.example/"><script src="app.js"></script>')}
        result, calls = self.run_trace(bad)
        self.assertEqual(["/"], [row[2] for row in calls])
        self.assertIn("relative_reference_with_invalid_base", result["coverage"]["reason_codes"])

    def test_duplicates_and_cycles_are_fetched_once(self):
        routes = {
            ("app.example", "/"): route(200, '<script src="/a.js"></script><script src="/a.js"></script>'),
            ("app.example", "/a.js"): route(200, 'fetch("/");fetch("/a.js")', "text/javascript"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual(["/", "/a.js"], [row[2] for row in calls])
        self.assertEqual(2, len(result["assets"]))

    def test_requests_redirects_and_bytes_share_hard_budgets(self):
        routes = {
            ("app.example", "/"): route(302, "1234", Location="/index"),
            ("app.example", "/index"): route(200, '<script src="/a.js"></script>'),
            ("app.example", "/a.js"): route(200, "abcdef", "text/javascript"),
        }
        result, calls = self.run_trace(routes, max_requests=2, max_total_bytes=100)
        self.assertEqual(2, result["usage"]["requests"])
        self.assertEqual(["/", "/index"], [row[2] for row in calls])
        self.assertEqual("partial", result["coverage"]["state"])
        result, calls = self.run_trace(routes, max_requests=5, max_total_bytes=8)
        self.assertEqual(8, result["usage"]["bytes_captured"])
        self.assertIn("capture_incomplete", result["coverage"]["reason_codes"])

    def test_sensitive_script_stops_before_discovered_json(self):
        routes = {
            ("app.example", "/"): route(200, '<script src="/gate.js"></script>'),
            ("app.example", "/gate.js"): route(200, 'const password="usable-fixture"; fetch("/data")', "text/javascript"),
            ("app.example", "/data"): route(200, "{}", "application/json"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual(["/", "/gate.js"], [row[2] for row in calls])
        self.assertEqual("stopped_sensitive", result["coverage"]["state"])
        self.assertNotIn("usable-fixture", json.dumps(result))

    def test_locator_store_is_private_scope_isolated_and_report_is_redacted(self):
        routes = {
            ("app.example", "/"): route(200, '<script src="/private/path/app.js?view=1"></script>'),
            ("app.example", "/private/path/app.js?view=1"): route(200, "", "text/javascript"),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "locators.sqlite"
            with LocatorStore(path) as store:
                result = trace_assets("https://app.example/", make_scope(),
                                      fetcher=production_broker(routes, []), locator_store=store,
                                      locator_scope="team")
                ref = result["assets"][1]["locator_ref"]
                self.assertEqual("https://app.example/private/path/app.js?view=1", store.get("team", ref))
                with self.assertRaises(LocatorError):
                    store.get("other", ref)
            public = json.dumps(result)
            self.assertNotIn("private/path", public)
            self.assertNotIn("view=1", public)

    def test_dynamic_unknown_options_comments_and_strings_are_not_followed(self):
        js = b'''// fetch("/comment")\nconst x="fetch('/string')"; fetch(`${API}/x`); fetch("/post", {method:"POST"}); fetch("/ok", {method:"GET"})'''
        refs, gaps, _ = extract_references(js, "text/javascript")
        self.assertEqual([("fetch_literal", "/ok")], refs)
        self.assertIn("fetch_not_static_get", gaps)
        routes = {
            ("app.example", "/"): route(200, '<script src="/app.js"></script>'),
            ("app.example", "/app.js"): route(200, js, "text/javascript"),
            ("app.example", "/ok"): route(200, "{}", "application/json"),
        }
        result, calls = self.run_trace(routes)
        self.assertEqual(["/", "/app.js", "/ok"], [row[2] for row in calls])
        self.assertIn("fetch_not_static_get", result["coverage"]["reason_codes"])

    def test_standalone_javascript_relative_fetch_is_unresolved(self):
        calls = []
        routes = {("app.example", "/root.js"): route(200, 'fetch("./data")', "text/javascript")}
        result = trace_assets("https://app.example/root.js", make_scope(),
                              fetcher=production_broker(routes, calls))
        self.assertEqual(["/root.js"], [row[2] for row in calls])
        self.assertIn("relative_fetch_without_document_context", result["coverage"]["reason_codes"])

    def test_sensitive_prefix_and_redirect_body_stop_before_next_request(self):
        for status, headers in ((200, {}), (302, {"Location": "/next"})):
            body = '<script>const password="fixture-only";</script>' + "x" * 200
            calls = []
            report = trace_assets("https://app.example/", make_scope(max_bytes=75),
                fetcher=production_broker({("app.example", "/"): route(status, body, **headers)}, calls))
            self.assertEqual(1, len(calls))
            self.assertEqual("stopped_sensitive", report["coverage"]["state"])
            self.assertFalse(report["assets"][0]["capture_complete"])
            self.assertNotIn("fixture-only", json.dumps(report))

    def test_budget_stopped_redirect_retains_observed_locator(self):
        routes = {("app.example", "/"): route(302, "redirect", Location="/never-requested")}
        with tempfile.TemporaryDirectory() as directory, LocatorStore(Path(directory) / "locations.db") as store:
            report, calls = self.run_trace(routes, max_requests=1, locator_store=store, locator_scope="team")
            self.assertEqual(["/"], [c[2] for c in calls])
            self.assertEqual("https://app.example/", store.get("team", report["assets"][0]["locator_ref"]))
            self.assertEqual("team", report["scope_id"])

    def test_depth_limit_keeps_unobserved_json_as_gap(self):
        routes = {
            ("app.example", "/"): route(200, '<script src="/code.js"></script>'),
            ("app.example", "/code.js"): route(200, 'fetch("/pending.json")', "text/javascript"),
        }
        report, calls = self.run_trace(routes, max_depth=1)
        self.assertEqual(2, len(calls))
        self.assertIn("depth_limit_reached", report["coverage"]["reason_codes"])

    def test_duration_deadline_prevents_even_first_request(self):
        calls = []
        with patch("sudetect.asset_trace.time.monotonic", side_effect=[0.0, 2.0, 2.0]):
            report = trace_assets("https://app.example/", make_scope(), max_duration=1,
                                 fetcher=production_broker({}, calls))
        self.assertEqual([], calls)
        self.assertEqual("partial", report["coverage"]["state"])

    def test_encoded_redirect_is_not_followed(self):
        report, calls = self.run_trace({("app.example", "/"): route(302, b"encoded",
                                      Location="/next", **{"Content-Encoding": "gzip"})})
        self.assertEqual(1, len(calls))
        self.assertIn("unsupported_content_encoding", report["coverage"]["reason_codes"])

    def test_noncode_and_regex_literals_do_not_invent_requests(self):
        samples = [
            (b'<p>fetch("/fake")</p>', "text/html"),
            (b'const pattern = /fetch("fake")/;', "text/javascript"),
            (b'{"text":"<script>fetch(\'/fake\')</script>"}', "application/json"),
            (b'FETCH("/fake")', "text/javascript"),
        ]
        for body, mime in samples:
            self.assertEqual([], extract_references(body, mime)[0])
        self.assertEqual([("fetch_literal", "/real")],
                         extract_references(b'fetch("/real")', "text/javascript")[0])

    def test_report_contains_data_profile_not_raw_business_values(self):
        routes = {
            ("app.example", "/"): route(200, '<script>fetch("/pricing.json")</script>'),
            ("app.example", "/pricing.json"): route(200, '{"price":987654321}', "application/json"),
        }
        report, _ = self.run_trace(routes)
        profile = report["assets"][1]["asset_profile"]
        self.assertIn("pricing", {x["category"] for x in profile["business_data_categories"]})
        self.assertNotIn("987654321", json.dumps(report))

    def test_cli_rejects_existing_output_before_network(self):
        from sudetect.asset_trace import main
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("keep me", encoding="utf-8")
            with patch("sudetect.asset_trace.trace_assets") as tracer, patch("builtins.print"):
                rc = main(["--scope", "unused", "--url", "https://app.example/", "--output", str(output)])
            self.assertEqual(2, rc)
            tracer.assert_not_called()
            self.assertEqual("keep me", output.read_text(encoding="utf-8"))

    def test_cli_report_resolves_through_private_location_export(self):
        from sudetect.asset_trace import main
        from sudetect.asset_locations import export_locations
        from contextlib import redirect_stdout
        import io
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path, store_path = root / "report.json", root / "store.sqlite"
            routes = {("app.example", "/"): route(200, '<input type="password">')}
            with patch("sudetect.asset_trace.Scope.load", return_value=make_scope()), \
                 patch("sudetect.asset_trace.fetch", production_broker(routes, [])), redirect_stdout(io.StringIO()) as output:
                rc = main(["--scope", "fixture", "--url", "https://app.example/", "--output", str(report_path),
                           "--locator-store", str(store_path), "--scope-id", "team"])
            self.assertEqual(0, rc)
            self.assertNotIn("app.example", output.getvalue())
            self.assertEqual("RESOLVED", export_locations(report_path, store_path, "team")["assets"][0]["location_state"])
            with self.assertRaises(ValueError):
                export_locations(report_path, store_path, "wrong-team")


if __name__ == "__main__":
    unittest.main()
