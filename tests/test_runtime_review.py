"""Synthetic offline browser tests; no external target is contacted."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import unittest

from sudetect.runtime_review import review_runtime_source


def approval(body, resources=None):
    resources = resources or {}
    return {"case_id": "case_" + "1" * 32, "owner_ref": "opaque:fixture-owner",
            "action": "execute_captured_javascript",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "source_sha256": hashlib.sha256(body).hexdigest(),
            "resource_sha256": {path: hashlib.sha256(row["body"]).hexdigest()
                                for path, row in resources.items()}}


def _browser_ready():
    if importlib.util.find_spec("playwright") is None:
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).is_file()
    except Exception:
        return False


@unittest.skipUnless(_browser_ready(), "Playwright Chromium fixture unavailable")
class RuntimeReviewTests(unittest.TestCase):
    def test_exact_gate_and_two_panels_reveal_after_original_javascript(self):
        body = (b"<div id='siteGate'>Login</div><section id='siteContent' style='display:none'>"
                b"<table><tr><td>PRIVATE_TEST_PRICE</td></tr></table></section>"
                b"<section id='promoContent' style='display:none'></section>"
                b"<script>document.getElementById('promoContent').innerHTML="
                b"'<input name=customerPhone value=PRIVATE_TEST_PHONE>';</script>")
        allowed = approval(body)
        allowed["client_ui_reveal"] = {"hide_ids": ["siteGate"],
                                       "show_ids": ["siteContent", "promoContent"],
                                       "display": "block"}
        result = review_runtime_source(body, "text/html", authorization=allowed, max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["original_script_executed"])
        self.assertTrue(result["client_reveal_applied"])
        self.assertTrue(result["client_reveal_visibility_verified"])
        self.assertEqual(0, result["initial_dom"]["counts"]["visible_tables"])
        self.assertEqual(1, result["after_client_reveal"]["counts"]["visible_tables"])
        self.assertEqual(1, result["after_client_reveal"]["counts"]["visible_fields"])
        self.assertRegex(result["client_reveal_action_digest"], r"^[0-9a-f]{64}$")
        self.assertNotIn("PRIVATE_TEST", json.dumps(result))

    def test_missing_duplicate_and_ancestor_reveal_targets_are_gaps(self):
        fixtures = (
            (b"<div id='gate'></div><div id='panel'></div>",
             {"hide_ids": ["missing"], "show_ids": ["panel"], "display": "block"},
             "target_missing"),
            (b"<div id='gate'></div><div id='panel'></div><div id='panel'></div>",
             {"hide_ids": ["gate"], "show_ids": ["panel"], "display": "block"},
             "duplicate_target"),
            (b"<div id='gate'><div id='panel'></div></div>",
             {"hide_ids": ["gate"], "show_ids": ["panel"], "display": "block"},
             "hidden_ancestor"),
        )
        for body, config, expected in fixtures:
            with self.subTest(expected=expected):
                allowed = approval(body)
                allowed["client_ui_reveal"] = config
                result = review_runtime_source(body, "text/html", authorization=allowed,
                                               max_seconds=25)
                self.assertEqual("partial", result["status"], result)
                self.assertFalse(result["client_reveal_applied"])
                self.assertEqual(expected, result["client_reveal_failure"])
                self.assertIn("client_reveal_" + expected, result["pending_reviews"])
                self.assertIsNone(result["after_client_reveal"])

    def test_reveal_applied_but_hidden_by_other_ancestor_or_important_rule_is_gap(self):
        fixtures = (
            b"<div id='gate'></div><div style='display:none'><div id='panel'>fixture</div></div>",
            b"<style>#panel{display:none!important}</style><div id='gate'></div>"
            b"<div id='panel'>fixture</div>",
        )
        for body in fixtures:
            with self.subTest(body_sha256=hashlib.sha256(body).hexdigest()):
                allowed = approval(body)
                allowed["client_ui_reveal"] = {"hide_ids": ["gate"],
                                               "show_ids": ["panel"], "display": "block"}
                result = review_runtime_source(body, "text/html", authorization=allowed,
                                               max_seconds=25)
                self.assertEqual("partial", result["status"], result)
                self.assertTrue(result["client_reveal_applied"])
                self.assertFalse(result["client_reveal_visibility_verified"])
                self.assertEqual("target_not_visible", result["client_reveal_failure"])
                self.assertIn("client_reveal_target_not_visible", result["pending_reviews"])
                self.assertIsNotNone(result["after_client_reveal"])

    def test_dynamic_table_and_client_reveal_are_measured_without_values(self):
        marker = "PRIVATE_FIXTURE_VALUE"
        body = ("<div id='login-screen'>Sign in</div><div id='app' style='display:none'></div>"
                "<script>document.getElementById('app').innerHTML="
                f"'<table><tr><td>{marker}</td></tr></table>';</script>").encode()
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["original_script_executed"])
        self.assertGreater(result["script_executed_count"], 0)
        self.assertEqual(0, result["initial_dom"]["counts"]["visible_tables"])
        self.assertTrue(result["client_reveal_applied"])
        self.assertEqual(1, result["after_client_reveal"]["counts"]["visible_tables"])
        self.assertNotIn(marker, json.dumps(result))
        self.assertFalse(result["all_runtime_states_verified"])

    def test_delayed_render_within_observation_window_is_counted(self):
        body = (b"<script>setTimeout(()=>{document.body.innerHTML="
                b"'<table><tr><td>fixture</td></tr></table>'},500);</script>")
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(1000, result["observation_window_ms"])
        self.assertEqual(1, result["initial_dom"]["counts"]["visible_tables"])

    def test_only_hash_bound_captured_get_dependency_is_fulfilled(self):
        body = b'<script src="/data.js"></script>'
        resources = {"/data.js": {"body": b"document.addEventListener('DOMContentLoaded',()=>{document.body.innerHTML='<table><tr><td>x</td></tr></table>';});",
                                  "content_type": "application/javascript"}}
        result = review_runtime_source(body, "text/html", authorization=approval(body, resources),
                                       resources=resources, max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertGreaterEqual(result["captured_resource_requests"], 2)
        self.assertEqual(1, result["initial_dom"]["counts"]["visible_tables"])
        self.assertEqual(0, result["network_fetches_performed"])

    def test_exact_captured_external_script_runs_without_fetching(self):
        url = "https://cdn.example.invalid/lib.js"
        body = ('<script src="' + url + '"></script>').encode()
        resources = {url: {"body": b"document.addEventListener('DOMContentLoaded',()=>{document.body.innerHTML='<table><tr><td>fixture</td></tr></table>';});",
                           "content_type": "application/javascript"}}
        result = review_runtime_source(body, "text/html", authorization=approval(body, resources),
                                       resources=resources, max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertTrue(result["original_script_executed"])
        self.assertEqual(1, result["initial_dom"]["counts"]["visible_tables"])
        self.assertIn("external_response_headers_unverified", result["pending_reviews"])
        self.assertEqual(0, result["network_fetches_performed"])
        self.assertNotIn(url, json.dumps(result))

    def test_missing_dependency_is_a_gap(self):
        body = b"<script>fetch('/missing.json').catch(() => {});</script>"
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertGreater(result["blocked_request_count"] + result["failed_request_count"]
                           + result["console_error_count"], 0, result)
        self.assertTrue({"uncaptured_dependency_blocked", "request_failure_observed",
                         "console_error_observed"} & set(result["pending_reviews"]))
        self.assertNotIn("missing.json", json.dumps(result))

    def test_send_beacon_is_silently_blocked_but_counted(self):
        body = b"<script>navigator.sendBeacon('/collector','fixture');</script>"
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertGreater(result["blocked_beacon_count"], 0, result)
        self.assertIn("beacon_blocked", result["pending_reviews"])

    def test_javascript_only_harness_does_not_claim_original_dom(self):
        body = b"document.body.innerHTML='<table><tr><td>fixture</td></tr></table>';"
        result = review_runtime_source(body, "application/javascript",
                                       authorization=approval(body), max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertTrue(result["original_script_executed"])
        self.assertIn("original_html_unavailable", result["pending_reviews"])
        self.assertFalse(result["all_runtime_states_verified"])

    def test_blocked_websocket_and_navigation_do_not_look_complete(self):
        body = (b"<script>try{new WebSocket('wss://captured.invalid/socket')}catch(e){};"
                b"location.href='/not-captured';</script>")
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("partial", result["status"])
        self.assertFalse(result["runtime_observation_complete"])
        self.assertGreater(result["blocked_request_count"] + result["failed_request_count"]
                           + result["blocked_websocket_count"] + result["console_error_count"], 0)
        self.assertNotIn("not-captured", json.dumps(result))

    def test_ancestor_opacity_hides_rendered_table(self):
        body = b"<div style='opacity:0'><table><tr><td>fixture</td></tr></table></div>"
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(0, result["initial_dom"]["counts"]["visible_tables"])

    def test_unbounded_script_is_killed_by_parent_deadline(self):
        body = b"<script>while(true){}</script>"
        started = time.monotonic()
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=3)
        self.assertLess(time.monotonic() - started, 9)
        self.assertEqual("partial", result["status"])
        self.assertEqual("runtime_time_limit", result["reason"])
        self.assertFalse(result["runtime_observation_complete"])


class RuntimeAuthorizationTests(unittest.TestCase):
    def test_exact_reveal_config_is_bounded_and_source_hash_bound(self):
        body = b"<div id='siteGate'></div><div id='siteContent'></div>"
        bad = [
            {"hide_ids": ["siteGate"], "show_ids": ["siteContent"], "display": "none"},
            {"hide_ids": ["siteGate"], "show_ids": ["siteGate"], "display": "block"},
            {"hide_ids": ["siteGate"], "show_ids": ["x" * 101], "display": "block"},
            {"hide_ids": ["siteGate"], "show_ids": ["siteContent"], "display": []},
            {"hide_ids": ["siteGate"], "show_ids": ["siteContent"]},
        ]
        for config in bad:
            allowed = approval(body)
            allowed["client_ui_reveal"] = config
            result = review_runtime_source(body, "text/html", authorization=allowed)
            self.assertEqual("invalid_client_ui_reveal", result["reason"])
        allowed = approval(body)
        allowed["client_ui_reveal"] = {"hide_ids": ["siteGate"],
                                       "show_ids": ["siteContent"], "display": "block"}
        changed = body + b"<span></span>"
        self.assertEqual("source_hash_mismatch", review_runtime_source(
            changed, "text/html", authorization=allowed)["reason"])

    def test_authorization_hash_and_expiry_must_match(self):
        body = b"<script>document.body.textContent='value'</script>"
        wrong = approval(body)
        wrong["source_sha256"] = "0" * 64
        self.assertEqual("source_hash_mismatch", review_runtime_source(
            body, "text/html", authorization=wrong)["reason"])
        expired = approval(body)
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.assertEqual("authorization_expired", review_runtime_source(
            body, "text/html", authorization=expired)["reason"])

    def test_resource_hash_mismatch_blocks_before_browser(self):
        body = b"<script src='/fixture.js'></script>"
        resources = {"/fixture.js": {"body": b"document.body.textContent='fixture'",
                                     "content_type": "application/javascript"}}
        allowed = approval(body, resources)
        allowed["resource_sha256"]["/fixture.js"] = "0" * 64
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       resources=resources)
        self.assertEqual("blocked", result["status"])
        self.assertEqual("resource_hash_mismatch", result["reason"])

    def test_external_resource_fragment_is_rejected(self):
        body = b"<script src='https://cdn.example.invalid/lib.js'></script>"
        url = "https://cdn.example.invalid/lib.js#fragment"
        resources = {url: {"body": b"document.body.textContent='fixture'",
                           "content_type": "application/javascript"}}
        result = review_runtime_source(body, "text/html", authorization=approval(body, resources),
                                       resources=resources)
        self.assertEqual("blocked", result["status"])
        self.assertEqual("invalid_resources", result["reason"])


if __name__ == "__main__":
    unittest.main()
