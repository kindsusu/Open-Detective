"""Offline boundaries for explicitly authorized patch followup."""
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sudetect.audit import Case, init_case
from sudetect.patch_followup import ANALYSIS_VERSION, _file_review, _setup, review
from sudetect.transport import FetchResult

SHA = "a" * 40
PARENT = "b" * 40
PATCH = f"https://github.com/fixture/repo/commit/{SHA}.patch"
SECRET = "ghp_" + "x" * 24
BODY = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <fixture@example.test>\n"
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\nSubject: [PATCH] fixture\n\n"
        "diff --git a/data/a.json b/data/a.json\nnew file mode 100644\n--- /dev/null\n"
        "+++ b/data/a.json\n@@ -0,0 +1 @@\n+{\"clientPassword\":\"" + SECRET + "\"}\n").encode()


class PatchFollowupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case_path = self.root / "case"
        init_case(self.case_path, {"scope_id": "fixture", "identity": {"company_en": "Fixture"}})
        binding = {"schema_version": "1.0", "scope_id": "fixture", "expires_at": "2099-01-01T00:00:00Z",
                   "repositories": [{"repository": "fixture/repo", "branch": "main", "owner_ref": "fixture:owner",
                                     "ownership_status": "confirmed", "pages": [], "deployment_urls": []}]}
        (self.case_path / "repository-bindings.json").write_text(json.dumps(binding), encoding="utf-8")
        self.scope_path = self.root / "scope.json"
        self.scope_path.write_text(json.dumps({"policy_id": "fixture-policy", "expires_at": "2099-01-01T00:00:00Z",
            "max_requests": 20, "max_bytes": 4_000_000,
            "targets": [{"origin": "https://github.com", "owner": "fixture", "ownership_evidence": "fixture:owner",
                         "path_prefixes": ["/fixture/repo/commit/"]},
                        {"origin": "https://api.github.com", "owner": "fixture", "ownership_evidence": "fixture:owner",
                         "path_prefixes": ["/repos/fixture/repo/commits"]},
                        {"origin": "https://raw.githubusercontent.com", "owner": "fixture",
                         "ownership_evidence": "fixture:owner", "path_prefixes": ["/fixture/repo/"]}]}), encoding="utf-8")
        with Case(self.case_path) as case:
            self.ref = case.locators.put(case.scope_id, PATCH)
        self.manifest_path = self.root / "followup.json"
        self.manifest = {"schema_version": "1.0", "case_id": json.loads((self.case_path / "case.json").read_text())["case_id"],
                         "authorization_ref": "fixture:approved", "expires_at": "2099-01-01T00:00:00Z",
                         "continue_sensitive_review": True, "asset_refs": [self.ref],
                         "budgets": {"max_requests": 10, "max_total_bytes": 4_000_000, "max_patch_bytes": 100_000,
                                     "max_file_bytes": 100_000, "max_seconds": 60, "max_attempts": 3,
                                     "max_files": 10, "max_ocr_seconds": 10}}
        self._write_manifest()

    def tearDown(self):
        self.temp.cleanup()

    def _write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def _anon(self, url, scope, **kwargs):
        self.calls.append(url)
        body = BODY if url == PATCH else json.dumps({"clientPassword": SECRET}).encode()
        return FetchResult({"http_status": 200, "capture_complete": True,
                            "sha256": hashlib.sha256(body).hexdigest()}, body,
                           {"content-type": "text/plain"})

    def _meta(self, url, token, limit, timeout):
        self.assertEqual("fixture-token", token)
        self.assertIn("/commits/" + SHA, url)
        return 200, json.dumps({"sha": SHA, "parents": [{"sha": PARENT}],
                                 "files": [{"status": "added", "filename": "data/a.json"}]}).encode(), ""

    def _run(self):
        self.calls = []
        with patch.dict(os.environ, {"FIXTURE_GH_TOKEN": "fixture-token"}):
            return review(self.case_path, self.scope_path, self.manifest_path,
                          token_env="FIXTURE_GH_TOKEN", anonymous_fetcher=self._anon,
                          metadata_fetcher=self._meta)

    def test_exact_patch_metadata_and_anonymous_file_are_separate_and_resumable(self):
        result = self._run()
        self.assertEqual(1, result["attempted"])
        self.assertEqual(1, result["processing_complete"])
        self.assertEqual(0, result["overall_verified"])
        self.assertEqual(2, len(self.calls))
        self.assertEqual(PATCH, self.calls[0])
        self.assertEqual(f"https://raw.githubusercontent.com/fixture/repo/{SHA}/data/a.json", self.calls[1])
        with Case(self.case_path) as case:
            stored = case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0]
            self.assertNotIn(SECRET, stored)
            self.assertNotIn("fixture-token", stored)
            self.assertNotIn("data/a.json", stored)
            report = json.loads(stored)
            self.assertEqual("authenticated_metadata", report["metadata_access"])
            self.assertEqual("full_before_after_files", report["file_comparison"])
            self.assertEqual("candidate_detected", report["candidate_review"])
            self.assertTrue(report["file_review_summary"][0]["candidate_findings"])
            self.assertTrue(report["file_review_summary"][0]["revision_reviews"][0]["file_locator_ref"].startswith("opaque:"))
        again = self._run()
        self.assertEqual(0, again["attempted"])
        self.assertEqual(1, again["already_complete"])
        self.assertEqual([], self.calls)

    def test_forged_ref_or_expired_manifest_cannot_fetch(self):
        self.calls = []
        self.manifest["asset_refs"] = ["opaque:" + "x" * 32]
        self._write_manifest()
        with self.assertRaises(ValueError):
            self._run()
        self.assertEqual([], self.calls)
        self.manifest["asset_refs"] = [self.ref]
        self.manifest["expires_at"] = "2020-01-01T00:00:00Z"
        self._write_manifest()
        with self.assertRaises(ValueError):
            self._run()
        self.assertEqual([], self.calls)

    def test_incomplete_raw_file_does_not_count_as_processed(self):
        self.calls = []
        def partial(url, scope, **kwargs):
            if url == PATCH:
                return self._anon(url, scope, **kwargs)
            return FetchResult({"http_status": 503, "capture_complete": True}, b"", {})
        with patch.dict(os.environ, {"FIXTURE_GH_TOKEN": "fixture-token"}):
            result = review(self.case_path, self.scope_path, self.manifest_path,
                            token_env="FIXTURE_GH_TOKEN", anonymous_fetcher=partial,
                            metadata_fetcher=self._meta)
        self.assertEqual(0, result["processing_complete"])
        self.assertEqual(1, result["remaining"])
        with Case(self.case_path) as case:
            stored = json.loads(case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0])
        self.assertEqual("partial", stored["file_comparison"])
        self.assertIn("raw_file_capture_incomplete", stored["pending_reviews"])

    def test_missing_token_is_recorded_as_gap_without_authenticated_request(self):
        self.calls = []
        result = review(self.case_path, self.scope_path, self.manifest_path,
                        anonymous_fetcher=self._anon, metadata_fetcher=lambda *args: self.fail("metadata called"))
        self.assertEqual(0, result["processing_complete"])
        with Case(self.case_path) as case:
            stored = json.loads(case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0])
        self.assertIn("authenticated_metadata_unavailable", stored["pending_reviews"])
        self.assertEqual("not_available", stored["metadata_access"])

    def test_patch_service_error_does_not_skip_after_raw_fallback(self):
        self.calls = []
        def unavailable(url, scope, **kwargs):
            if url == PATCH:
                return FetchResult({"http_status": 503, "capture_complete": True}, b"", {})
            return self._anon(url, scope, **kwargs)
        with patch.dict(os.environ, {"FIXTURE_GH_TOKEN": "fixture-token"}):
            first = review(self.case_path, self.scope_path, self.manifest_path,
                           token_env="FIXTURE_GH_TOKEN", anonymous_fetcher=unavailable,
                           metadata_fetcher=self._meta)
        self.assertEqual(0, first["processing_complete"])
        with Case(self.case_path) as case:
            stored = json.loads(case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0])
        self.assertEqual("full_before_after_files", stored["file_comparison"])
        self.assertIn("patch_anonymous_capture_incomplete", stored["pending_reviews"])
        second = self._run()
        self.assertEqual(0, second["attempted"])
        self.assertEqual(1, second["remaining"])

    def test_binary_patch_is_processed_without_claiming_binary_hunk_decode(self):
        self.calls = []
        binary_patch = (f"From {SHA} Mon Sep 17 00:00:00 2001\nFrom: Fixture <fixture@example.test>\n"
                        "Date: Mon, 1 Jan 2024 00:00:00 +0000\nSubject: [PATCH] fixture\n\n"
                        "diff --git a/picture.bin b/picture.bin\nGIT binary patch\nliteral 2\nab\n").encode()
        def binary_fetch(url, scope, **kwargs):
            if url == PATCH:
                return FetchResult({"http_status": 200, "capture_complete": True,
                                    "sha256": hashlib.sha256(binary_patch).hexdigest()}, binary_patch,
                                   {"content-type": "text/plain"})
            return self._anon(url, scope, **kwargs)
        with patch.dict(os.environ, {"FIXTURE_GH_TOKEN": "fixture-token"}):
            result = review(self.case_path, self.scope_path, self.manifest_path,
                            token_env="FIXTURE_GH_TOKEN", anonymous_fetcher=binary_fetch,
                            metadata_fetcher=self._meta)
        self.assertEqual(1, result["processing_complete"])
        self.assertEqual(0, result["overall_verified"])
        with Case(self.case_path) as case:
            stored = json.loads(case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0])
        self.assertTrue(stored["binary_hunks_not_decoded"])
        self.assertIn("binary_patch_not_inspected", stored["pending_reviews"])

    def test_exact_diff_fallback_never_claims_patch_capture(self):
        self.calls = []
        diff_body = BODY.split(b"\n\ndiff --git ", 1)[1]
        diff_body = b"diff --git " + diff_body
        def fallback(url, scope, **kwargs):
            if url == PATCH:
                return FetchResult({"http_status": 503, "capture_complete": True}, b"", {})
            if url == PATCH[:-6] + ".diff":
                self.calls.append(url)
                return FetchResult({"http_status": 200, "capture_complete": True,
                                    "sha256": hashlib.sha256(diff_body).hexdigest()}, diff_body,
                                   {"content-type": "text/plain"})
            return self._anon(url, scope, **kwargs)
        with patch.dict(os.environ, {"FIXTURE_GH_TOKEN": "fixture-token"}):
            result = review(self.case_path, self.scope_path, self.manifest_path,
                            token_env="FIXTURE_GH_TOKEN", anonymous_fetcher=fallback,
                            metadata_fetcher=self._meta)
        self.assertEqual(1, result["processing_complete"])
        self.assertEqual(0, result["overall_verified"])
        with Case(self.case_path) as case:
            stored = json.loads(case.ledger.db.execute("SELECT report_json FROM patch_followup_results").fetchone()[0])
        self.assertTrue(stored["diff_anonymous_captured"])
        self.assertFalse(stored.get("patch_anonymous_captured", False))
        self.assertIn("patch_anonymous_capture_incomplete", stored["pending_reviews"])

    def test_binary_formats_are_not_clean_text_and_svg_retains_visual_gap(self):
        for name, body in (("archive.zip", b"PK\x03\x04" + b"x" * 32),
                           ("report.pdf", b"%PDF-1.7\n" + b"x" * 32),
                           ("data.sqlite", b"SQLite format 3\x00" + b"x" * 32),
                           ("renamed.txt", b"PK\x03\x04" + b"x" * 32),
                           ("unknown.dat", b"abc\x00def")):
            with self.subTest(name=name):
                result = _file_review(body, name, "text/plain", max_seconds=5, max_pixels=25_000_000)
                self.assertEqual("unsupported_binary", result["kind"])
                self.assertFalse(result["text_analysis_complete"])
                self.assertIn("unsupported_binary_format", result["pending_reviews"])
        svg = _file_review(b'<svg xmlns="http://www.w3.org/2000/svg"><text>Hi</text></svg>',
                           "art.svg", "text/plain", max_seconds=5, max_pixels=25_000_000)
        self.assertEqual("svg", svg["kind"])
        self.assertTrue(svg["visual_review_remaining"])
        self.assertIn("svg_visual_review_required", svg["pending_reviews"])

    def test_legacy_complete_and_attempt_limit_do_not_skip_new_analyzer_version(self):
        with Case(self.case_path) as case:
            _setup(case)
            case.ledger.db.execute("INSERT INTO patch_followup_results VALUES(?,?,?,?,?)",
                ("patch-followup:legacy", self.ref, self.manifest["authorization_ref"], 5,
                 json.dumps({"processing_complete": True, "overall_verified": True,
                             "retry_after_epoch": 9999999999})))
            case.ledger.db.commit()
        result = self._run()
        self.assertEqual(1, result["attempted"])
        self.assertEqual(0, result["already_complete"])
        self.assertEqual(1, result["processing_complete"])
        with Case(self.case_path) as case:
            rows = case.ledger.db.execute("SELECT attempt,report_json FROM patch_followup_results ORDER BY attempt").fetchall()
        self.assertEqual([5, 6], [row[0] for row in rows])
        self.assertEqual(ANALYSIS_VERSION, json.loads(rows[1][1])["analyzer_version"])

    def test_real_png_and_jpeg_bytes_reach_image_review_before_binary_guard(self):
        from PIL import Image
        for format_name, suffix in (("PNG", ".png"), ("JPEG", ".jpg")):
            with self.subTest(format=format_name):
                output = BytesIO()
                Image.new("RGB", (2, 2), "white").save(output, format=format_name)
                payload = output.getvalue()
                self.assertIn(b"\x00", payload)
                with patch("sudetect.patch_followup.analyze_image", return_value={
                        "ocr_state": "completed", "signals": [], "content": "NOT_INSPECTED",
                        "image_review_complete": False, "pending_reviews": []}) as reviewed:
                    result = _file_review(payload, "image" + suffix, "application/octet-stream",
                                          max_seconds=5, max_pixels=25_000_000)
                reviewed.assert_called_once()
                self.assertEqual("image", result["kind"])
                self.assertEqual("completed", result["ocr_state"])


if __name__ == "__main__":
    unittest.main()
