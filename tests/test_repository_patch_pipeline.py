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

    def test_binary_and_rename_only_remain_explicit_gaps_with_file_hints(self):
        for lines, reason, status in [
            (["diff --git a/data/x.db b/data/x.db", "GIT binary patch", "literal 2", "ab"],
             "binary_patch_not_inspected", "modified"),
            (["diff --git a/old.json b/new.json", "rename from old.json", "rename to new.json"],
             "patch_has_no_text_hunks", "renamed"),
        ]:
            with self.subTest(reason=reason):
                result = self.review(patch(*lines))
                self.assertFalse(result["analysis_complete"])
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


if __name__ == "__main__":
    unittest.main()
