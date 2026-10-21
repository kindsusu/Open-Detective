"""Offline synthetic regressions for authorized candidate continuation."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch as mock_patch

from sudetect.candidate_review import review_candidate_bytes
from sudetect.github_history import analyze_repository_patch
from sudetect.locators import LocatorStore
from sudetect.media_review import analyze_inline_images


SHA = "a" * 40
URL = f"https://github.com/fixture/repo/commit/{SHA}.patch"


def make_patch(rows):
    return ("\n".join([f"From {SHA} Mon Sep 17 00:00:00 2001",
                       "From: Fixture <example@example.test>",
                       "Subject: [PATCH] fixture", "", "---",
                       "diff --git a/a.js b/a.js", "--- /dev/null", "+++ b/a.js",
                       f"@@ -0,0 +1,{len(rows)} @@", *rows, ""])).encode()


class CandidateContinuationTests(unittest.TestCase):
    def test_patch_continues_past_early_candidate_and_keeps_default_stop(self):
        rows = ['+const password = "fixture-credential";']
        rows += ["+const filler = '" + "x" * 3000 + "';" for _ in range(100)]
        rows += ['+const password = "later-fixture";',
                 '+fetch("https://fixture.example.test/late.json")']
        body = make_patch(rows)
        with tempfile.TemporaryDirectory() as directory, \
                LocatorStore(Path(directory) / "locators.sqlite") as store:
            stopped = analyze_repository_patch(body, URL, store, "fixture", max_bytes=1_000_000)
            self.assertEqual("stopped_sensitive_candidate", stopped["content_review"])
            self.assertTrue(stopped["hold_repository_patch_lineage"])
            continued = analyze_repository_patch(body, URL, store, "fixture",
                max_bytes=1_000_000, continue_sensitive_review=True)
            self.assertTrue(continued["authorized_sensitive_review"])
            self.assertFalse(continued.get("hold_repository_patch_lineage", False))
            self.assertIn("RUNTIME_ENDPOINT_CANDIDATE", continued["signal_codes"])
            self.assertNotIn("sensitive_candidate_stop", continued["pending_reviews"])
            self.assertNotIn("fixture-credential", json.dumps(continued))

    def test_candidate_summary_distinguishes_labels_values_and_templates(self):
        raw = (b'{"phone":"example","customer_name":"fixture",'
               b'"password":"fixture-credential"}\n'
               b'const password = "fixture-credential";')
        report = review_candidate_bytes(raw, content_type="text/plain")
        kinds = {item["kind"] for item in report["findings"]}
        self.assertIn("sensitive_field_label", kinds)
        self.assertIn("template_or_example", kinds)
        self.assertIn("client_password_source_literal", kinds)
        self.assertNotIn("fixture-credential", json.dumps(report))
        self.assertFalse(any("hash" in key for key in report))

    def test_candidate_byte_limit_is_explicit(self):
        report = review_candidate_bytes(b"x" * 500_000, max_bytes=240_000)
        self.assertEqual(240_000, report["bytes_examined"])
        self.assertFalse(report["analysis_complete"])
        self.assertIn("candidate_review_byte_or_time_limit", report["pending_reviews"])

    def test_inline_base64_lookalike_is_excluded_but_later_literal_is_reviewed(self):
        image = b'<img src="data:image/png;base64,AAAA01012345678AAAA">'
        only_image = review_candidate_bytes(image)
        self.assertNotIn("phone_format", {item["kind"] for item in only_image["findings"]})
        self.assertEqual(1, only_image["inline_images_excluded_from_text"])
        self.assertTrue(only_image["text_analysis_complete"])
        self.assertFalse(only_image["analysis_complete"])
        self.assertIn("inline_image_ocr_unexamined", only_image["pending_reviews"])
        with_literal = review_candidate_bytes(image + b'\ncontact = "010-1234-5678";')
        self.assertIn("phone_format", {item["kind"] for item in with_literal["findings"]})
        self.assertNotIn("010-1234-5678", json.dumps(with_literal))

    def test_large_valid_json_html_js_keep_whole_document_structure(self):
        cases = (
            (b'{"padding":"' + b'x' * 300_000 + b'","phone":"010-1234-5678"}',
             "application/json", "phone_format"),
            (b'<html><body><p>' + b'x' * 300_000 +
             b'</p><p>010-1234-5678</p></body></html>',
             "text/html", "phone_format"),
            (b'const padding = "' + b'x' * 300_000 +
             b'"; const password = "fixture-credential";',
             "application/javascript", "client_password_source_literal"),
        )
        for body, content_type, expected in cases:
            with self.subTest(content_type=content_type):
                result = review_candidate_bytes(body, content_type=content_type)
                self.assertTrue(result["text_analysis_complete"], result["pending_reviews"])
                self.assertTrue(result["structure_analysis_complete"], result["pending_reviews"])
                self.assertNotIn("candidate_structure_review_pending", result["pending_reviews"])
                self.assertIn(expected, {item["kind"] for item in result["findings"]})

    def test_large_invalid_json_has_text_coverage_and_real_structure_gap(self):
        body = b'{"padding":"' + b'x' * 300_000 + b'","phone":"010-1234-5678"'
        result = review_candidate_bytes(body, content_type="application/json")
        self.assertEqual(len(body), result["bytes_examined"])
        self.assertTrue(result["text_analysis_complete"])
        self.assertFalse(result["structure_analysis_complete"])
        self.assertIn("candidate_structure_review_pending", result["pending_reviews"])
        self.assertIn("phone_format", {item["kind"] for item in result["findings"]})

    def test_resident_format_is_candidate_without_identity_or_raw_value(self):
        marker = "900101-1234567"
        result = review_candidate_bytes(("fixture " + marker).encode())
        self.assertIn("KR_RESIDENT_VALUE_CANDIDATE", result["candidate_signal_codes"])
        finding = next(item for item in result["findings"]
                       if item["kind"] == "resident_number_format")
        self.assertEqual("not_verified", finding["identity"])
        self.assertNotIn(marker, json.dumps(result))

    def test_patch_mail_author_is_not_a_content_candidate(self):
        metadata_only = review_candidate_bytes(make_patch(['+const okay = true;']))
        self.assertEqual("patch_changed_lines", metadata_only["source_format"])
        self.assertTrue(metadata_only["text_analysis_complete"])
        self.assertTrue(metadata_only["structure_analysis_complete"])
        self.assertNotIn("email_format", {item["kind"] for item in metadata_only["findings"]})
        self.assertNotIn("candidate_structure_review_pending", metadata_only["pending_reviews"])
        changed = review_candidate_bytes(make_patch(['+const contact = "fixture@example.test";',
                                                     '+const rows = [{']))
        self.assertIn("email_format", {item["kind"] for item in changed["findings"]})
        self.assertNotIn("candidate_structure_review_pending", changed["pending_reviews"])

    def test_unmapped_classifier_candidate_is_preserved_value_free(self):
        fake = SimpleNamespace(report={"signals": [{"code": "FUTURE_MATERIAL_CANDIDATE"}],
                                       "structure_analysis_complete": True})
        with mock_patch("sudetect.candidate_review.analyze", return_value=fake):
            result = review_candidate_bytes(b"fixture")
        self.assertIn({"kind": "classifier_candidate", "code": "FUTURE_MATERIAL_CANDIDATE",
                       "evidence": "classifier_signal", "validity": "not_tested"}, result["findings"])

    def test_inline_images_resume_and_continue_after_candidate(self):
        body = b" ".join(b"data:image/png;base64," + base64.b64encode(bytes([index]))
                         for index in range(3))
        sensitive = {"ocr_state": "completed", "pending_reviews": [],
                     "content": "SENSITIVE_CANDIDATE", "signals": [{"code": "KR_PHONE_VALUE_CANDIDATE"}]}
        clean = {"ocr_state": "completed", "pending_reviews": [],
                 "content": "NOT_INSPECTED", "signals": []}
        with mock_patch("sudetect.media_review.analyze_image", side_effect=[sensitive, clean, clean]):
            result = analyze_inline_images(body, max_images=3, continue_sensitive_review=True)
        self.assertEqual(3, result["inline_images_examined"])
        self.assertEqual(3, result["inline_images_next_index"])
        self.assertEqual(0, result["inline_images_unexamined"])
        self.assertNotIn("inline_image_sensitive_candidate_stop", result["pending_reviews"])
        with mock_patch("sudetect.media_review.analyze_image", return_value=sensitive):
            stopped = analyze_inline_images(body)
        self.assertEqual(1, stopped["inline_images_examined"])
        self.assertIn("inline_image_sensitive_candidate_stop", stopped["pending_reviews"])
        with mock_patch("sudetect.media_review.analyze_image", return_value=clean):
            resumed = analyze_inline_images(body, start_index=1, max_images=1,
                                            continue_sensitive_review=True)
        self.assertEqual(2, resumed["inline_images_next_index"])
        self.assertEqual(1, resumed["inline_images_unexamined"])


if __name__ == "__main__":
    unittest.main()
