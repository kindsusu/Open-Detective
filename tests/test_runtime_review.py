"""Synthetic offline browser tests; no external target is contacted."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import time
import unittest
import zlib

from sudetect.runtime_review import (_base_result, _count_diagnostic,
                                     review_runtime_source)


def _png_fixture():
    def chunk(kind, payload):
        return (struct.pack(">I", len(payload)) + kind + payload +
                struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))
    data = (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) +
            chunk(b"IEND", b""))
    return base64.b64encode(data).decode("ascii")


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
    def test_declared_target_diagnostics_are_bounded_and_value_free(self):
        body = (b"<div id='visiblePanel'>Public</div>"
                b"<div style='display:none'><div id='hiddenPanel'>PRIVATE_EMAIL</div></div>"
                b"<div id='hiddenAttr' hidden>PRIVATE_PHONE</div>"
                b"<fieldset disabled><select id='carSelect'>"
                b"<option value='PRIVATE_ONE'>Secret label</option>"
                b"<option value='PRIVATE_TWO' selected>Secret label two</option>"
                b"</select></fieldset><div id='dup'></div><div id='dup'></div>")
        allowed = approval(body)
        allowed["observe_target_ids"] = ["visiblePanel", "hiddenPanel", "hiddenAttr",
                                         "carSelect", "missingPanel", "dup"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        rows = result["observed_targets_initial"]
        self.assertEqual(allowed["observe_target_ids"], result["observed_target_ids"])
        self.assertEqual(6, len(rows))
        self.assertEqual(("unique", True, None),
                         (rows[0]["presence"], rows[0]["visible"], rows[0]["hidden_reason"]))
        self.assertEqual("ancestor_display", rows[1]["hidden_reason"])
        self.assertEqual("self_hidden", rows[2]["hidden_reason"])
        self.assertTrue(rows[3]["disabled"])
        self.assertEqual((2, 1), (rows[3]["option_count"], rows[3]["selected_index"]))
        self.assertEqual("missing", rows[4]["presence"])
        self.assertEqual("duplicate", rows[5]["presence"])
        rendered = json.dumps(result, ensure_ascii=False)
        for secret in ("PRIVATE_EMAIL", "PRIVATE_PHONE", "PRIVATE_ONE", "PRIVATE_TWO",
                       "Secret label"):
            self.assertNotIn(secret, rendered)

    def test_visible_to_hidden_transition_is_branch_evidence(self):
        body = (b"<button id='closeBtn' type='button'>Close</button>"
                b"<div id='panel'>PRIVATE_CONTENT</div>"
                b"<script>document.getElementById('closeBtn').onclick=()=>{"
                b"document.getElementById('panel').style.display='none'};</script>")
        allowed = approval(body)
        allowed["observe_target_ids"] = ["panel"]
        allowed["ui_steps"] = [{"action": "click", "target_id": "closeBtn",
                                "expect_hidden_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["observed_targets_initial"][0]["visible"])
        step = result["ui_steps"][0]
        self.assertTrue(step["expected_hidden_verified"])
        self.assertTrue(step["hidden_transition_verified"])
        self.assertTrue(step["branch_verified"])
        self.assertEqual("self_display", step["observed_targets_after"][0]["hidden_reason"])
        self.assertFalse(step["action_target_before"]["disabled"])
        self.assertNotIn("PRIVATE_CONTENT", json.dumps(result))

    def test_already_hidden_expectation_is_not_branch_evidence(self):
        body = (b"<button id='closeBtn' type='button'>Close</button>"
                b"<div id='panel' style='display:none'>PRIVATE_CONTENT</div>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_id": "closeBtn",
                                "expect_hidden_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        step = result["ui_steps"][0]
        self.assertTrue(step["expected_hidden_verified"])
        self.assertFalse(step["hidden_transition_verified"])
        self.assertFalse(step["branch_verified"])

    def test_disabled_action_target_is_diagnosed_without_click(self):
        body = (b"<fieldset disabled><select id='carSelect'>"
                b"<option value='PRIVATE_A'>A</option><option value='PRIVATE_B'>B</option>"
                b"</select></fieldset>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "select", "target_id": "carSelect",
                                "index": 1, "expect_dom_change": True}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        step = result["ui_steps"][0]
        self.assertEqual("target_disabled", step["status"])
        self.assertTrue(step["action_target_before"]["disabled"])
        self.assertEqual(2, step["action_target_before"]["option_count"])
        self.assertEqual(0, step["action_target_after"]["selected_index"])
        self.assertNotIn("PRIVATE_A", json.dumps(result))

    def test_delayed_visible_button_keeps_playwright_auto_wait(self):
        body = (b"<button id='laterBtn' type='button' style='display:none'>Later</button>"
                b"<div id='panel' style='display:none'>Panel</div>"
                b"<script>setTimeout(()=>document.getElementById('laterBtn').style.display="
                b"'block',1300);document.getElementById('laterBtn').onclick=()=>{"
                b"document.getElementById('panel').style.display='block'};</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_id": "laterBtn",
                                "expect_visible_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual("self_display", result["ui_steps"][0]["action_target_before"][
            "hidden_reason"])
        self.assertTrue(result["ui_steps"][0]["action_target_after"]["visible"])
        self.assertEqual(1, result["ui_steps_completed"])

    def test_child_visibility_override_does_not_inherit_hidden_state(self):
        body = (b"<div style='visibility:hidden'>"
                b"<div id='child' style='visibility:visible'>Child</div></div>")
        allowed = approval(body)
        allowed["observe_target_ids"] = ["child"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["observed_targets_initial"][0]["visible"])

    def test_overridden_hidden_attribute_uses_rendered_style(self):
        body = (b"<style>[hidden]{display:block}</style>"
                b"<div id='panel' hidden>Rendered</div>")
        allowed = approval(body)
        allowed["observe_target_ids"] = ["panel"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["observed_targets_initial"][0]["visible"])

    def test_depth_limit_is_not_accepted_as_hidden_expectation(self):
        body = (b"<button id='observeBtn' type='button'>Observe</button>" +
                b"<div>" * 130 + b"<div id='panel'>Deep</div>" + b"</div>" * 130)
        allowed = approval(body)
        allowed["observe_target_ids"] = ["panel"]
        allowed["ui_steps"] = [{"action": "click", "target_id": "observeBtn",
                                "expect_hidden_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual("ancestor_depth_limit", result["observed_targets_initial"][0][
            "hidden_reason"])
        self.assertFalse(result["ui_steps"][0]["expected_hidden_verified"])
        self.assertFalse(result["ui_steps"][0]["branch_verified"])

    def test_unique_idless_standalone_calculate_button_runs_original_handler(self):
        body = (b"<button class='calc-btn'>Calculate</button><div id='result'></div>"
                b"<script>document.getElementsByClassName('calc-btn')[0].onclick=()=>{"
                b"document.getElementById('result').innerHTML="
                b"'<table><tr><td>PRIVATE_CALC</td></tr></table>'};</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_button_class": "calc-btn",
                                "expect_dom_change": True}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(1, result["ui_steps_completed"])
        self.assertEqual(1, result["ui_steps"][0]["dom"]["counts"]["visible_tables"])
        self.assertNotIn("PRIVATE_CALC", json.dumps(result))

    def test_hash_bound_index_selects_one_of_multiple_class_buttons(self):
        body = (b"<button class='nd-brand-card' type='button'>First</button>"
                b"<button class='nd-brand-card' type='button'>Second</button>"
                b"<div id='selected' style='display:none'>PRIVATE_BRAND</div>"
                b"<script>document.getElementsByClassName('nd-brand-card')[1].onclick=()=>{"
                b"document.getElementById('selected').style.display='block'};</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_button_class": "nd-brand-card",
                                "target_index": 1, "expect_visible_ids": ["selected"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        step = result["ui_steps"][0]
        self.assertEqual(2, step["action_target_before"]["match_count"])
        self.assertEqual("unique", step["action_target_before"]["presence"])
        self.assertTrue(step["branch_verified"])
        self.assertNotIn("PRIVATE_BRAND", json.dumps(result))

    def test_class_button_index_out_of_range_or_unsafe_target_is_rejected(self):
        fixtures = (
            (b"<button class='nd-brand-card' type='button'>First</button>", 1,
             "target_missing"),
            (b"<button class='nd-brand-card' type='button'>First</button>"
             b"<form><button class='nd-brand-card'>Submit</button></form>", 1,
             "prohibited_target"),
            (b"<button class='nd-brand-card' type='button'>First</button>"
             b"<button class='nd-brand-card' type='submit'>Calculate</button>", 1,
             "prohibited_target"),
        )
        for body, index, expected in fixtures:
            with self.subTest(expected=expected):
                allowed = approval(body)
                allowed["ui_steps"] = [{"action": "click",
                                        "target_button_class": "nd-brand-card",
                                        "target_index": index,
                                        "expect_dom_change": True}]
                result = review_runtime_source(body, "text/html", authorization=allowed,
                                               max_seconds=25)
                self.assertEqual("partial", result["status"], result)
                self.assertEqual(expected, result["ui_steps"][0]["status"])
                self.assertFalse(result["ui_steps"][0]["action_applied"])

    def test_class_button_index_rejects_more_than_64_matches(self):
        body = b"<button class='nd-brand-card' type='button'>Card</button>" * 65
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_button_class": "nd-brand-card",
                                "target_index": 0, "expect_dom_change": True}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual("dom_limit", result["ui_steps"][0]["status"])
        self.assertFalse(result["ui_steps"][0]["action_applied"])

    def test_class_button_ambiguity_form_and_auth_name_are_rejected(self):
        fixtures = (
            (b"<button class='calc-btn'>One</button><button class='calc-btn'>Two</button>",
             "duplicate_target"),
            (b"<div class='calc-btn'>Not button</div>", "prohibited_target"),
            (b"<button id='buttonId' class='calc-btn'>Named</button>", "prohibited_target"),
            (b"<form><button class='calc-btn'>Submit</button></form>", "prohibited_target"),
            (b"<form id='f'></form><button class='calc-btn' form='f'>Submit</button>",
             "prohibited_target"),
            (b"<button class='calc-btn' name='loginAction'>Login</button>",
             "prohibited_target"),
            (b"<button class='calc-btn'>Login</button>", "prohibited_target"),
            (b"<button class='calc-btn' aria-label='Sign in'>Continue</button>",
             "prohibited_target"),
            ("<meta charset='utf-8'><button class='calc-btn'>로그인</button>".encode("utf-8"),
             "prohibited_target"),
            ("<meta charset='utf-8'><button class='calc-btn' aria-label='비밀번호 제출'>Continue</button>".encode("utf-8"),
             "prohibited_target"),
        )
        for body, expected in fixtures:
            with self.subTest(expected=expected):
                allowed = approval(body)
                allowed["ui_steps"] = [{"action": "click", "target_button_class": "calc-btn",
                                        "expect_dom_change": True}]
                result = review_runtime_source(body, "text/html", authorization=allowed,
                                               max_seconds=25)
                self.assertEqual("partial", result["status"], result)
                self.assertEqual(expected, result["ui_steps"][0]["status"])
                self.assertFalse(result["ui_steps"][0]["action_applied"])

    def test_declared_tab_and_local_png_download_have_separate_evidence(self):
        png = _png_fixture()
        body = ("<button type='button' id='tabPreviewBtn'>Preview</button>"
                "<button type='button' id='downloadBtn'>Export</button>"
                "<section id='previewPanel' style='display:none'></section>"
                "<script>document.getElementById('tabPreviewBtn').onclick=()=>{"
                "document.getElementById('previewPanel').style.display='block';"
                "document.getElementById('previewPanel').innerHTML='<table><tr><td>PRIVATE</td></tr></table>';};"
                "document.getElementById('downloadBtn').onclick=()=>{let a=document.createElement('a');"
                f"a.href='data:image/png;base64,{png}';a.download='private.png';a.click();}};"
                "</script>").encode()
        allowed = approval(body)
        allowed["observe_png_download"] = True
        allowed["ui_steps"] = [
            {"action": "click", "target_id": "tabPreviewBtn",
             "expect_visible_ids": ["previewPanel"], "expect_dom_change": True},
            {"action": "click", "target_id": "downloadBtn", "expect_png_download": True},
        ]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(2, result["ui_steps_completed"])
        self.assertEqual(1, result["ui_steps"][0]["dom"]["counts"]["visible_tables"])
        self.assertTrue(all(step["branch_verified"] for step in result["ui_steps"]))
        self.assertGreater(result["ui_steps"][0]["script_coverage"]["observed_range_count"], 0)
        coverage = result["script_coverage_observed"]
        self.assertGreaterEqual(coverage["observed_total_range_count"],
                                coverage["ever_executed_range_count"])
        self.assertFalse(coverage["semantic_branch_coverage_verified"])
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         coverage["sources"][0]["source_sha256"])
        self.assertEqual("primary", coverage["sources"][0]["source_kind"])
        self.assertEqual("verified_png", result["png_downloads"][0]["status"])
        self.assertEqual((1, 1), (result["png_downloads"][0]["width"],
                                  result["png_downloads"][0]["height"]))
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("data:image", json.dumps(result))

    def test_blob_png_download_is_verified_without_filename_or_pixels(self):
        png = _png_fixture()
        body = ("<button type='button' id='downloadBtn'>Export</button><script>"
                "document.getElementById('downloadBtn').onclick=()=>{"
                f"let raw=atob('{png}');let bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));"
                "let url=URL.createObjectURL(new Blob([bytes],{type:'image/png'}));"
                "let a=document.createElement('a');a.href=url;a.download='PRIVATE.png';a.click();};"
                "</script>").encode()
        allowed = approval(body)
        allowed.update(observe_png_download=True,
                       ui_steps=[{"action": "click", "target_id": "downloadBtn",
                                  "expect_png_download": True}])
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(1, result["ui_steps_completed"])
        self.assertEqual("verified_png", result["png_downloads"][0]["status"])
        self.assertFalse(result["png_downloads"][0]["visual_content_verified"])
        self.assertNotIn("PRIVATE.png", json.dumps(result))

    def test_fifth_png_download_is_cancelled_and_marks_gap(self):
        png = _png_fixture()
        body = ("<button type='button' id='downloadBtn'>Export</button><script>"
                "document.getElementById('downloadBtn').onclick=()=>{let a=document.createElement('a');"
                f"a.href='data:image/png;base64,{png}';a.download='fixture.png';a.click();}};"
                "</script>").encode()
        allowed = approval(body)
        allowed.update(observe_png_download=True,
                       ui_steps=[{"action": "click", "target_id": "downloadBtn",
                                  "expect_png_download": True} for _ in range(5)])
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual(4, result["ui_steps_completed"])
        self.assertEqual(4, len(result["png_downloads"]))
        self.assertIn("png_download_count_limit", result["pending_reviews"])

    def test_oversized_blob_png_cannot_be_verified(self):
        body = (b"<button type='button' id='downloadBtn'>Export</button><script>"
                b"document.getElementById('downloadBtn').onclick=()=>{"
                b"let a=document.createElement('a');"
                b"a.href=URL.createObjectURL(new Blob([new Uint8Array(9*1024*1024)],"
                b"{type:'image/png'}));a.download='fixture.png';a.click();};</script>")
        allowed = approval(body)
        allowed.update(observe_png_download=True,
                       ui_steps=[{"action": "click", "target_id": "downloadBtn",
                                  "expect_png_download": True}])
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual(0, result["ui_steps_completed"])
        self.assertTrue({"png_progress_byte_limit", "png_download_unverified",
                         "download_storage_limit"} & set(result["pending_reviews"]), result)

    def test_local_blank_frame_render_can_export_without_external_navigation(self):
        png = _png_fixture()
        body = ("<button type='button' id='downloadBtn'>Export</button>"
                "<script>document.getElementById('downloadBtn').onclick=()=>{"
                "let f=document.createElement('iframe');document.body.append(f);"
                "f.contentDocument.body.innerHTML='<div>fixture</div>';"
                "let a=document.createElement('a');"
                f"a.href='data:image/png;base64,{png}';a.download='fixture.png';a.click();}};"
                "</script>").encode()
        allowed = approval(body)
        allowed.update(observe_png_download=True, allow_local_render_frames=True,
                       ui_steps=[{"action": "click", "target_id": "downloadBtn",
                                  "expect_png_download": True}])
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual(1, result["ui_steps_completed"])
        self.assertGreaterEqual(result["local_render_frame_count"], 1)
        self.assertIn("local_render_frame_content_unverified", result["pending_reviews"])
        self.assertEqual("verified_png", result["png_downloads"][0]["status"])
        self.assertEqual(0, result["network_fetches_performed"])

    def test_declared_mobile_viewport_controls_visible_tab(self):
        body = (b"<style>#mobileTab{display:none}@media(max-width:500px){"
                b"#mobileTab{display:block}}</style>"
                b"<button type='button' id='mobileTab'>Tab</button>"
                b"<div id='panel' style='display:none'>fixture</div>"
                b"<script>document.getElementById('mobileTab').onclick=()=>"
                b"document.getElementById('panel').style.display='block'</script>")
        allowed = approval(body)
        allowed["viewport"] = {"width": 375, "height": 812}
        allowed["ui_steps"] = [{"action": "click", "target_id": "mobileTab",
                                "expect_visible_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(1, result["ui_steps_completed"])
        self.assertEqual(375, result["viewport"]["width"])

    def test_select_change_with_same_length_values_is_only_input_evidence(self):
        body = b"<select id='carSelect'><option value='AA'>A</option><option value='BB'>B</option></select>"
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "select", "target_id": "carSelect",
                                "index": 1, "expect_dom_change": True}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertTrue(result["ui_steps"][0]["input_state_changed"])
        self.assertFalse(result["ui_steps"][0]["dom_change_verified"])
        self.assertFalse(result["ui_steps"][0]["branch_verified"])
        self.assertEqual(0, result["ui_steps_completed"])
        self.assertNotIn("BB", json.dumps(result))

    def test_select_handler_changes_application_output(self):
        body = (b"<select id='carSelect'><option value='AA'>A</option>"
                b"<option value='BB'>B</option></select><div id='summary'></div>"
                b"<script>document.getElementById('carSelect').onchange=()=>{"
                b"document.getElementById('summary').innerHTML="
                b"'<table><tr><td>PRIVATE_PRICE</td></tr></table>'};</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "select", "target_id": "carSelect",
                                "index": 1, "expect_dom_change": True}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertTrue(result["ui_steps"][0]["input_state_changed"])
        self.assertTrue(result["ui_steps"][0]["dom_change_verified"])
        self.assertEqual(1, result["ui_steps_completed"])
        self.assertNotIn("PRIVATE_PRICE", json.dumps(result))

    def test_already_visible_expectation_is_not_branch_evidence(self):
        body = b"<button type='button' id='tabBtn'>Tab</button><div id='panel'>Visible</div>"
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_id": "tabBtn",
                                "expect_visible_ids": ["panel"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertTrue(result["ui_steps"][0]["expected_visible_verified"])
        self.assertFalse(result["ui_steps"][0]["visible_transition_verified"])
        self.assertFalse(result["ui_steps"][0]["branch_verified"])

    def test_fixed_clock_distinguishes_before_during_and_after_without_source_changes(self):
        body = (b"<body><div>fixture</div><script>let m=new Date().getMonth();"
                b"document.body.innerHTML=m===5?'<table><tr><td>PRIVATE_PROMO</td></tr></table>'"
                b":'<div>inactive</div>';</script>")
        observations = []
        for instant in ("2026-05-31T12:00:00+09:00", "2026-06-15T12:00:00+09:00",
                        "2026-07-01T12:00:00+09:00"):
            allowed = approval(body)
            allowed["clock_time"] = instant
            allowed["timezone_id"] = "Asia/Seoul"
            result = review_runtime_source(body, "text/html", authorization=allowed,
                                           max_seconds=25)
            self.assertEqual("reviewed", result["status"], result)
            self.assertTrue(result["simulated_clock_used"])
            self.assertEqual("Asia/Seoul", result["timezone_id"])
            self.assertRegex(result["clock_fixture_digest"], r"^[0-9a-f]{64}$")
            self.assertNotIn(instant, json.dumps(result))
            self.assertNotIn("PRIVATE_PROMO", json.dumps(result))
            observations.append(result["initial_dom"]["counts"]["visible_tables"])
        self.assertEqual([0, 1, 0], observations)

    def test_uncaptured_external_download_is_not_png_evidence(self):
        body = (b"<a id='downloadBtn' href='https://outside.invalid/file.png' "
                b"download='fixture.png'>Export</a>")
        allowed = approval(body)
        allowed.update(observe_png_download=True,
                       ui_steps=[{"action": "click", "target_id": "downloadBtn",
                                  "expect_png_download": True}])
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=12)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual(0, result["ui_steps_completed"])
        self.assertEqual(0, result["network_fetches_performed"])
        self.assertFalse(any(item["status"] == "verified_png"
                             for item in result["png_downloads"]))

    def test_missing_duplicate_and_submit_action_targets_stop_without_effect(self):
        fixtures = (
            (b"<button type='button' id='otherBtn'>x</button>", "tabBtn",
             "target_missing"),
            (b"<button type='button' id='tabBtn'>x</button>"
             b"<button type='button' id='tabBtn'>x</button>", "tabBtn",
             "duplicate_target"),
            (b"<form><button id='tabBtn'>Submit</button></form>", "tabBtn",
             "prohibited_target"),
            (b"<form><input type='password'><button type='button' id='tabBtn'>x</button>"
             b"</form>", "tabBtn", "prohibited_target"),
        )
        for body, target, expected in fixtures:
            with self.subTest(expected=expected):
                allowed = approval(body)
                allowed["ui_steps"] = [{"action": "click", "target_id": target,
                                        "expect_dom_change": True}]
                result = review_runtime_source(body, "text/html", authorization=allowed,
                                               max_seconds=25)
                self.assertEqual("partial", result["status"], result)
                self.assertEqual(expected, result["ui_steps"][0]["status"])
                self.assertFalse(result["ui_steps"][0]["action_applied"])

    def test_step_timeout_keeps_previous_step_evidence(self):
        body = (b"<button type='button' id='readyBtn'>Ready</button>"
                b"<button type='button' id='stallBtn'>Stall</button>"
                b"<div id='readyPanel' style='display:none'>ok</div>"
                b"<script>document.getElementById('readyBtn').onclick=()=>{"
                b"document.getElementById('readyPanel').style.display='block'};"
                b"document.getElementById('stallBtn').onclick=()=>{while(true){}};</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [
            {"action": "click", "target_id": "readyBtn",
             "expect_visible_ids": ["readyPanel"]},
            {"action": "click", "target_id": "stallBtn", "expect_dom_change": True},
        ]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertEqual("runtime_time_limit", result["reason"])
        self.assertGreaterEqual(result["ui_steps_completed"], 1, result)
        self.assertTrue(result["ui_steps"][0]["branch_verified"])

    def test_percent_encoded_image_with_fixed_query_is_replayed_exactly(self):
        path = ("/images/cars/sonata/%EC%84%B8%EB%A0%88%EB%8B%88%ED%8B%B0_"
                "%ED%99%94%EC%9D%B4%ED%8A%B8_%ED%8E%84.png?v=1")
        body = f'<img src="{path}">'.encode()
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4"
            "/5+hHgAHggJ/PchI2QAAAABJRU5ErkJggg==")
        resources = {path: {"body": png, "content_type": "image/png"}}
        result = review_runtime_source(body, "text/html", authorization=approval(body, resources),
                                       resources=resources, max_seconds=25)
        self.assertEqual("reviewed", result["status"], result)
        self.assertEqual(2, result["captured_resource_requests"])
        self.assertEqual(0, result["blocked_request_count"])
        self.assertEqual(0, result["network_fetches_performed"])

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

    def test_target_ancestor_limit_keeps_observation_incomplete(self):
        body = (b"<div>" * 130 + b"<button id='deep'>fixture</button>" +
                b"</div>" * 130)
        allowed = approval(body)
        allowed["observe_target_ids"] = ["deep"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual("ancestor_depth_limit",
                         result["observed_targets_initial"][0]["hidden_reason"])
        self.assertIn("target_diagnostics_limit", result["pending_reviews"])
        self.assertFalse(result["runtime_observation_complete"])

    def test_missing_dependency_is_a_gap(self):
        body = b"<script>fetch('/missing.json').catch(() => {});</script>"
        result = review_runtime_source(body, "text/html", authorization=approval(body), max_seconds=25)
        self.assertEqual("partial", result["status"], result)
        self.assertGreater(result["blocked_request_count"] + result["failed_request_count"]
                           + result["console_error_count"], 0, result)
        self.assertTrue({"uncaptured_dependency_blocked", "request_failure_observed",
                         "console_error_observed"} & set(result["pending_reviews"]))
        self.assertNotIn("missing.json", json.dumps(result))

    def test_bounded_runtime_diagnostics_classify_without_leaking_content(self):
        body = (b"<img src='/private-image-token.png'>"
                b"<script src='/private-script-token.js'></script>"
                b"<script>fetch('/private-fetch-token.json').catch(()=>{});"
                b"throw new ReferenceError('private-error-token');</script>")
        result = review_runtime_source(body, "text/html", authorization=approval(body),
                                       max_seconds=25)
        diagnostics = result["runtime_diagnostics"]
        self.assertGreaterEqual(diagnostics["blocked_requests_by_type"].get("image", 0), 1)
        self.assertGreaterEqual(diagnostics["blocked_requests_by_type"].get("script", 0), 1)
        self.assertGreaterEqual(diagnostics["blocked_requests_by_type"].get("fetch", 0), 1)
        self.assertGreaterEqual(diagnostics["blocked_requests_by_reason"].get(
            "uncaptured_get", 0), 3)
        self.assertGreaterEqual(diagnostics["script_errors_by_kind"].get(
            "ReferenceError", 0), 1)
        self.assertGreaterEqual(diagnostics["failed_requests_by_type"].get("fetch", 0), 1)
        self.assertEqual("partial", result["status"])
        self.assertFalse(result["diagnostic_limit_reached"])
        serialized = json.dumps(result)
        for marker in ("private-image-token", "private-script-token",
                       "private-fetch-token", "private-error-token"):
            self.assertNotIn(marker, serialized)

    def test_reference_error_identifier_requires_exact_approved_message(self):
        body = (b"<script>throw new ReferenceError('CATALOG is not defined')</script>"
                b"<script>throw new ReferenceError('OTHER is not defined\\nprivate-token')</script>"
                b"<script>throw new TypeError('PRICES is not defined')</script>")
        allowed = approval(body)
        allowed["reference_error_identifiers"] = ["CATALOG", "OTHER", "PRICES"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual({"CATALOG": True, "OTHER": False, "PRICES": False},
                         result["reference_error_identifier_observed"])
        self.assertEqual("partial", result["status"])
        self.assertNotIn("private-token", json.dumps(result))

    def test_reference_error_identifier_matches_unqualified_symbol_access(self):
        body = b"<script>CATALOG;</script>"
        allowed = approval(body)
        allowed["reference_error_identifiers"] = ["CATALOG"]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        self.assertEqual({"CATALOG": True},
                         result["reference_error_identifier_observed"])
        self.assertEqual("partial", result["status"])

    def test_reference_error_identifier_authorization_is_bounded(self):
        body = b"<script>throw new ReferenceError('CATALOG is not defined')</script>"
        for identifiers in (["CATALOG"] * 2, ["x"] * 9, ["with-hyphen"],
                            ["x" * 65], ["한글"], "CATALOG"):
            with self.subTest(identifiers=identifiers):
                allowed = approval(body)
                allowed["reference_error_identifiers"] = identifiers
                result = review_runtime_source(body, "text/html", authorization=allowed)
                self.assertEqual("blocked", result["status"])
                self.assertEqual("invalid_reference_error_identifiers", result["reason"])

    def test_runtime_diagnostic_limit_is_value_free_and_incomplete(self):
        result = _base_result(b"private-value-token", "html")
        for _ in range(257):
            _count_diagnostic(result, "blocked_requests_by_type", "fetch")
        self.assertEqual(256, result["runtime_diagnostics"][
            "blocked_requests_by_type"]["fetch"])
        self.assertTrue(result["diagnostic_limit_reached"])
        self.assertNotIn("private-value-token", json.dumps(result))

    def test_ui_step_reports_only_resource_diagnostic_deltas(self):
        body = (b"<button id='go' type='button'>Go</button><div id='done' hidden>Done</div>"
                b"<script>document.getElementById('go').addEventListener('click',()=>{"
                b"fetch('/private-step-token.json').catch(()=>{});"
                b"document.getElementById('done').hidden=false;});</script>")
        allowed = approval(body)
        allowed["ui_steps"] = [{"action": "click", "target_id": "go",
                                "expect_visible_ids": ["done"]}]
        result = review_runtime_source(body, "text/html", authorization=allowed,
                                       max_seconds=25)
        step = result["ui_steps"][0]
        self.assertGreaterEqual(step["runtime_diagnostic_delta"][
            "blocked_requests_by_type"].get("fetch", 0), 1, step)
        self.assertFalse(step["branch_verified"])
        self.assertNotIn("private-step-token", json.dumps(result))

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
    def test_target_diagnostic_scope_and_hidden_expectations_are_validated(self):
        body = b"<div id='panel'></div>"
        bad_approvals = (
            {"observe_target_ids": ["panel"] * 2},
            {"observe_target_ids": ["x" + str(i) for i in range(17)]},
            {"ui_steps": [{"action": "wait", "milliseconds": 1,
                           "expect_hidden_ids": ["panel"],
                           "expect_visible_ids": ["panel"]}]},
            {"ui_steps": [{"action": "wait", "milliseconds": 1,
                           "expect_hidden_ids": ["panel"] * 2}]},
        )
        for values in bad_approvals:
            allowed = approval(body)
            allowed.update(values)
            result = review_runtime_source(body, "text/html", authorization=allowed)
            self.assertEqual("blocked", result["status"])
            self.assertIn(result["reason"], {"invalid_observe_target_ids",
                                             "invalid_ui_steps"})

    def test_class_button_index_must_be_bounded_and_class_scoped(self):
        body = b"<button class='nd-brand-card' type='button'>Card</button>"
        for step in (
            {"action": "click", "target_button_class": "nd-brand-card", "target_index": -1},
            {"action": "click", "target_button_class": "nd-brand-card", "target_index": 64},
            {"action": "click", "target_button_class": "nd-brand-card", "target_index": True},
            {"action": "click", "target_id": "card", "target_index": 0},
            {"action": "select", "target_id": "card", "index": 0, "target_index": 0},
        ):
            with self.subTest(step=step):
                allowed = approval(body)
                allowed["ui_steps"] = [step]
                result = review_runtime_source(body, "text/html", authorization=allowed)
                self.assertEqual("blocked", result["status"])
                self.assertEqual("invalid_ui_steps", result["reason"])

    def test_ui_steps_reject_secret_submit_and_unbounded_actions(self):
        body = b"<button id='tabBtn' type='button'></button>"
        bad = [
            [{"action": "click", "target_id": "loginButton"}],
            [{"action": "fill", "target_id": "inputField", "value": "real_password"}],
            [{"action": "wait", "milliseconds": 2001}],
            [{"action": "click", "target_id": "tabBtn", "script": "run()"}],
            [{"action": "click", "target_id": "tabBtn", "expect_png_download": True}],
            [{"action": "click", "target_id": "tabBtn"}] * 13,
            [{"action": "click", "target_button_class": "calc-btn",
              "target_id": "tabBtn"}],
            [{"action": "select", "target_button_class": "calc-btn", "index": 0}],
            [{"action": "click", "target_button_class": "calc.btn"}],
            [{"action": "click", "target_button_class": "login-btn"}],
        ]
        for steps in bad:
            allowed = approval(body)
            allowed["ui_steps"] = steps
            result = review_runtime_source(body, "text/html", authorization=allowed)
            self.assertEqual("blocked", result["status"])
            self.assertIn(result["reason"], {"invalid_ui_steps", "prohibited_ui_target",
                                             "prohibited_ui_value",
                                             "png_observation_not_authorized"})
        allowed = approval(body)
        allowed["viewport"] = {"width": 200, "height": 800}
        self.assertEqual("invalid_viewport", review_runtime_source(
            body, "text/html", authorization=allowed)["reason"])
        allowed = approval(body)
        allowed["clock_time"] = "2026-06-15T12:00:00"
        self.assertEqual("invalid_clock_time", review_runtime_source(
            body, "text/html", authorization=allowed)["reason"])
        allowed = approval(body)
        allowed["timezone_id"] = "../bad"
        self.assertEqual("invalid_timezone_id", review_runtime_source(
            body, "text/html", authorization=allowed)["reason"])

    def test_local_resource_url_ambiguities_are_rejected(self):
        body = b"<img src='/fixture.png'>"
        bad_paths = (
            "/%2e%2e/file.png", "/a/%2E/file.png", "/a/../file.png",
            "/a%2ffile.png", "/a%5cfile.png", "/%00.png", "/%7F.png",
            "/%252e%252e/file.png", "/bad%GG.png", "/bad%.png",
            "/a.png#fragment", "//external.invalid/a.png", "/__main__.js?v=1",
            "/a.png?x=%2f", "/a.png?x=%0a", "/a.png?x=%GG",
            "/" + "a" * 2048,
        )
        for path in bad_paths:
            with self.subTest(path=path):
                resources = {path: {"body": b"image", "content_type": "image/png"}}
                result = review_runtime_source(body, "text/html",
                    authorization=approval(body, resources), resources=resources)
                self.assertEqual("invalid_resources", result["reason"], result)
        canonical_twins = {
            "/a.png?v=1": {"body": b"one", "content_type": "image/png"},
            "/%61.png?v=%31": {"body": b"two", "content_type": "image/png"},
        }
        result = review_runtime_source(body, "text/html",
            authorization=approval(body, canonical_twins), resources=canonical_twins)
        self.assertEqual("invalid_resources", result["reason"])

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
