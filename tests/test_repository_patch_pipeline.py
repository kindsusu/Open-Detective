"""Offline regression for bounded observed commit patch integration."""
import json
import tempfile
import unittest
from pathlib import Path

from sudetect.github_history import analyze_repository_patch
from sudetect.locators import LocatorStore
from sudetect.repository_history import analyze_history


SHA = "a" * 40
URL = f"https://github.com/fixture/repo/commit/{SHA}.patch"
HISTORY = "https://api.github.com/repos/fixture/repo/commits?sha=main&per_page=5"


def patch(*lines):
    return ("\n".join([f"From {SHA} Mon Sep 17 00:00:00 2001",
        "From: Private Person <private@example.test>", "Subject: [PATCH] fixture", *lines, ""])).encode()


class RepositoryPatchPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = LocatorStore(Path(self.temporary.name) / "locators.sqlite")

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def review(self, body, url=URL):
        return analyze_repository_patch(body, url, self.store, "fixture")

    def test_history_emits_only_observed_revisions_with_explicit_window_gap(self):
        report, refs = analyze_history(json.dumps([{"sha": SHA}, {"sha": "b" * 40}]).encode(), HISTORY)
        self.assertTrue(report["analysis_complete"])
        self.assertEqual(2, report["patches_emitted"])
        self.assertIn("history_window_not_exhaustive", report["pending_reviews"])
        self.assertEqual(4, len(refs))
        self.assertEqual(("repository_patch", URL), refs[1])
        self.assertEqual("repository_snapshot", refs[2][0])
        for body in (b'{"sha":"../bad"}', b'[{"sha":"../bad"}]',
                     json.dumps([{"sha": SHA}] * 6).encode(),
                     json.dumps([{"sha": SHA}, {"sha": SHA}]).encode()):
            with self.subTest(body=body[:20]):
                failed, jobs = analyze_history(body, HISTORY)
                self.assertFalse(failed["analysis_complete"])
                self.assertEqual([], jobs)

    def test_added_removed_and_renamed_categories_are_value_free(self):
        body = patch(
            "diff --git a/data/old.csv b/data/old.csv", "deleted file mode 100644",
            "--- a/data/old.csv", "+++ /dev/null", "@@ -1 +0,0 @@",
            "-https://old.example.test/private",
            "diff --git a/keys/new.pem b/keys/new.pem", "new file mode 100644",
            "--- /dev/null", "+++ b/keys/new.pem", "@@ -0,0 +1 @@",
            "+https://new.example.test/private",
            "diff --git a/docs/before.pdf b/docs/after.pdf", "similarity index 100%",
            "rename from docs/before.pdf", "rename to docs/after.pdf")
        result = self.review(body)
        self.assertTrue(result["analysis_complete"])
        self.assertEqual([("removed", "structured_data_or_config"),
                          ("added", "credential_material_candidate"),
                          ("renamed", "document")],
                         [(item["status"], item["category_hint"]) for item in result["changed_files"]])
        refs = result["literal_url_changes"]
        self.assertEqual("https://old.example.test/private",
                         self.store.get("fixture", refs["removed_locator_refs"][0]))
        self.assertEqual("https://new.example.test/private",
                         self.store.get("fixture", refs["introduced_locator_refs"][0]))
        self.assertNotIn("private@example.test", json.dumps(result))
        self.assertNotIn("new.example.test", json.dumps(result))
        self.assertNotIn("old.csv", json.dumps(result))

    def test_sensitive_patch_holds_lineage_without_literal_urls(self):
        secret = "ghp_" + "x" * 24
        body = patch("diff --git a/src/a.py b/src/a.py", "--- a/src/a.py", "+++ b/src/a.py",
                     "@@ -1 +1 @@", "-safe", "+" + secret + " https://candidate.example.test/")
        result = self.review(body)
        self.assertFalse(result["analysis_complete"])
        self.assertEqual("SENSITIVE_CANDIDATE", result["content"])
        self.assertTrue(result["hold_repository_patch_lineage"])
        self.assertIn("sensitive_candidate_stop", result["pending_reviews"])
        self.assertNotIn("literal_url_changes", result)
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn("candidate.example.test", json.dumps(result))

    def test_confidential_label_alone_does_not_hold_other_commits(self):
        body = patch("diff --git a/notice.txt b/notice.txt", "--- /dev/null", "+++ b/notice.txt",
                     "@@ -0,0 +1 @@", "+confidential")
        result = self.review(body)
        self.assertEqual("SENSITIVE_CANDIDATE", result["content"])
        self.assertTrue(result["analysis_complete"])
        self.assertFalse(result.get("hold_repository_patch_lineage", False))
        self.assertIn("CONFIDENTIAL_MARKER_CANDIDATE", result["signal_codes"])

    def test_binary_gap_and_metadata_only_rename_have_file_hints(self):
        for lines, reason, status in [
            (["diff --git a/data/x.db b/data/x.db", "GIT binary patch", "literal 2", "ab"],
             "binary_patch_not_inspected", "modified"),
            (["diff --git a/old.json b/new.json", "rename from old.json", "rename to new.json"],
             None, "renamed"),
        ]:
            with self.subTest(reason=reason):
                result = self.review(patch(*lines))
                self.assertEqual(reason is None, result["analysis_complete"])
                if reason is not None:
                    self.assertIn(reason, result["pending_reviews"])
                self.assertEqual(status, result["changed_files"][0]["status"])
                self.assertNotIn("literal_url_changes", result)

    def test_malformed_url_or_patch_never_yields_complete_analysis(self):
        valid = patch("diff --git a/x.py b/x.py", "--- a/x.py", "+++ b/x.py",
                      "@@ -1 +1 @@", "-old", "+new")
        for url in (URL + "?raw=1", URL.replace(SHA, "../bad"),
                    URL.replace("github.com", "github.com.evil.test")):
            with self.subTest(url=url):
                result = self.review(valid, url)
                self.assertEqual(["patch_url_invalid"], result["pending_reviews"])
        invalid = self.review(valid.replace(f"From {SHA} ".encode(), b"From " + b"b" * 40 + b" "))
        self.assertIn("patch_provenance_invalid", invalid["pending_reviews"])

    def test_git_c_quoted_utf8_path_and_metadata_only_rename(self):
        quoted = patch(r'diff --git "a/data/\355\225\234.json" "b/data/\355\225\234.json"',
                       r'--- "a/data/\355\225\234.json"',
                       r'+++ "b/data/\355\225\234.json"', '@@ -1 +1 @@', '-old', '+new')
        result = self.review(quoted)
        self.assertTrue(result["analysis_complete"])
        self.assertEqual("structured_data_or_config", result["changed_files"][0]["category_hint"])
        rename = patch(r'diff --git "a/old\040name.json" "b/new\040name.json"',
                       'similarity index 100%', r'rename from "old\040name.json"',
                       r'rename to "new\040name.json"')
        result = self.review(rename)
        self.assertTrue(result["analysis_complete"])
        self.assertEqual("metadata_only", result["content_review"])
        self.assertEqual("renamed", result["changed_files"][0]["status"])

    def test_path_disagreement_and_incomplete_text_marker_remain_gaps(self):
        disagreement = patch('diff --git a/expected.json b/expected.json',
                             '--- a/other.json', '+++ b/expected.json',
                             '@@ -1 +1 @@', '-old', '+new')
        result = self.review(disagreement)
        self.assertFalse(result["analysis_complete"])
        self.assertIn("patch_provenance_invalid", result["pending_reviews"])
        unexamined = patch('diff --git a/x.json b/x.json', '--- a/x.json', '+++ b/x.json')
        result = self.review(unexamined)
        self.assertFalse(result["analysis_complete"])
        self.assertIn("patch_has_no_text_hunks", result["pending_reviews"])

    def test_valid_mail_envelope_without_diff_requires_commit_detail(self):
        body = patch("Date: Tue, 1 Jan 2030 00:00:00 +0000", "", "---")
        result = self.review(body)
        self.assertFalse(result["analysis_complete"])
        self.assertEqual([], result["changed_files"])
        self.assertIn("header_only_patch_requires_commit_detail", result["pending_reviews"])
        no_separator = patch("Date: Tue, 1 Jan 2030 00:00:00 +0000", "")
        self.assertIn("header_only_patch_requires_commit_detail",
                      self.review(no_separator)["pending_reviews"])
        malformed = patch("Date: Tue, 1 Jan 2030 00:00:00 +0000", "", "<html>error</html>")
        self.assertIn("patch_provenance_invalid", self.review(malformed)["pending_reviews"])

    def test_explicit_large_capture_limit_is_validated_without_widening_default(self):
        body = patch('diff --git a/x.txt b/x.txt', '--- a/x.txt', '+++ b/x.txt',
                     '@@ -1 +1 @@', '-old', '+new')
        padded = body + b' ' * (512 * 1024)
        self.assertIn("patch_byte_limit_reached", self.review(padded)["pending_reviews"])
        expanded = analyze_repository_patch(padded, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertNotIn("patch_byte_limit_reached", expanded["pending_reviews"])
        for invalid in (0, True, 128 * 1024 * 1024 + 1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=invalid)

    def test_large_multiline_diff_reviews_late_lines_and_candidate(self):
        lines = ["+const row = '" + str(index).zfill(4) + "-" + "x" * 3500 + "';"
                 for index in range(100)]
        body = patch("diff --git a/x.js b/x.js", "--- /dev/null", "+++ b/x.js",
                     "@@ -0,0 +1,100 @@", *lines)
        reviewed = analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertTrue(reviewed["analysis_complete"], reviewed["pending_reviews"])
        lines[-1] = '+const password = "fixture-only";'
        body = patch("diff --git a/x.js b/x.js", "--- /dev/null", "+++ b/x.js",
                     "@@ -0,0 +1,100 @@", *lines)
        reviewed = analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertEqual("SENSITIVE_CANDIDATE", reviewed["content"],
                         (reviewed.get("pending_reviews"), reviewed.get("signal_codes"), reviewed.get("content_review")))
        self.assertTrue(reviewed["hold_repository_patch_lineage"])
        self.assertNotIn("literal_url_changes", reviewed)

    def test_partial_js_literal_is_structure_gap_not_byte_limit(self):
        body = patch("diff --git a/x.js b/x.js", "--- a/x.js", "+++ b/x.js",
                     "@@ -0,0 +1 @@", "+const rows = [{")
        reviewed = self.review(body)
        self.assertFalse(reviewed["analysis_complete"])
        self.assertEqual("text_reviewed_structure_pending", reviewed["content_review"])
        self.assertIn("patch_structure_parse_incomplete", reviewed["pending_reviews"])
        self.assertNotIn("patch_analysis_limit_reached", reviewed["pending_reviews"])

    def test_oversized_changed_line_remains_actual_analysis_limit(self):
        body = patch("diff --git a/x.txt b/x.txt", "--- a/x.txt", "+++ b/x.txt",
                     "@@ -0,0 +1 @@", "+" + "x" * 330000)
        reviewed = analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertFalse(reviewed["analysis_complete"])
        self.assertIn("patch_analysis_limit_reached", reviewed["pending_reviews"])

    def test_oversized_single_line_scans_late_sensitive_signal_but_remains_partial(self):
        body = patch("diff --git a/x.js b/x.js", "--- /dev/null", "+++ b/x.js",
                     "@@ -0,0 +1 @@", "+const data = '" + "x" * 330000 +
                     "'; const password = 'fixture-only';")
        reviewed = analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertEqual("SENSITIVE_CANDIDATE", reviewed["content"])
        self.assertFalse(reviewed["analysis_complete"])
        self.assertIn("sensitive_candidate_stop", reviewed["pending_reviews"])

    def test_inline_image_projection_preserves_explicit_media_gap(self):
        body = patch("diff --git a/x.html b/x.html", "--- /dev/null", "+++ b/x.html",
                     "@@ -0,0 +1 @@", '+<img src="data:image/png;base64,' + "A" * 350000 + '">')
        reviewed = analyze_repository_patch(body, URL, self.store, "fixture", max_bytes=2 * 1024 * 1024)
        self.assertFalse(reviewed["analysis_complete"])
        self.assertEqual("text_reviewed_media_pending", reviewed["content_review"])
        self.assertIn("inline_image_ocr_unexamined", reviewed["pending_reviews"])

    def test_missing_hunk_in_second_file_and_bad_git_octal_are_not_complete(self):
        body = patch("diff --git a/a.txt b/a.txt", "--- a/a.txt", "+++ b/a.txt",
                     "@@ -1 +1 @@", "-old", "+new",
                     "diff --git a/b.txt b/b.txt", "--- a/b.txt", "+++ b/b.txt")
        reviewed = self.review(body)
        self.assertFalse(reviewed["analysis_complete"])
        self.assertIn("patch_has_no_text_hunks", reviewed["pending_reviews"])
        bad = patch(r'diff --git "a/\777.txt" "b/\777.txt"')
        reviewed = self.review(bad)
        self.assertIn("patch_provenance_invalid", reviewed["pending_reviews"])

    def test_unquoted_git_paths_with_spaces_are_checked_against_file_headers(self):
        body = patch("diff --git a/old name.json b/new name.json",
                     "--- a/old name.json", "+++ b/new name.json",
                     "@@ -1 +1 @@", "-old", "+new")
        self.assertTrue(self.review(body)["analysis_complete"])


if __name__ == "__main__":
    unittest.main()
