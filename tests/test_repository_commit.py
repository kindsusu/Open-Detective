"""Offline, synthetic commit-detail fallback checks."""
import json
import unittest

from sudetect.repository_commit import analyze_commit_detail, commit_detail_url

SHA = "a" * 40
PARENT = "b" * 40
PATCH = f"https://github.com/fixture/repo/commit/{SHA}.patch"
DETAIL = f"https://api.github.com/repos/fixture/repo/commits/{SHA}?per_page=100&page=1"


def payload(files, *, sha=SHA, parents=None, stats=None):
    return json.dumps({"sha": sha, "parents": [{"sha": PARENT}] if parents is None else parents,
                       "files": files, **({"stats": stats} if stats is not None else {})}, ensure_ascii=False).encode()


class CommitDetailFallbackTests(unittest.TestCase):
    def test_only_exact_observed_patch_derives_detail_url(self):
        self.assertEqual(DETAIL, commit_detail_url(PATCH))
        for bad in (PATCH + "?raw=1", PATCH.replace("github.com", "github.com.evil.test"),
                    PATCH.replace(SHA, "main")):
            self.assertIsNone(commit_detail_url(bad))

    def test_changed_files_generate_only_canonical_current_and_first_parent_urls(self):
        files = [
            {"status": "modified", "filename": "data/가격 표.json", "patch": "secret raw line",
             "raw_url": "https://evil.test/exfil"},
            {"status": "added", "filename": "new.js"},
            {"status": "removed", "filename": "gone.csv"},
            {"status": "renamed", "filename": "new name.md", "previous_filename": "old name.md"},
            {"status": "copied", "filename": "copy.txt", "previous_filename": "source.txt"},
        ]
        report, refs = analyze_commit_detail(payload(files), DETAIL)
        self.assertFalse(report["analysis_complete"])
        self.assertTrue(report["file_list_page_complete"])
        self.assertEqual(5, report["files_observed"])
        self.assertEqual(8, report["file_urls_emitted"])
        self.assertEqual(8, len(refs))
        self.assertIn(("repository_file", f"https://raw.githubusercontent.com/fixture/repo/{SHA}/data/%EA%B0%80%EA%B2%A9%20%ED%91%9C.json"), refs)
        self.assertIn(("repository_file", f"https://raw.githubusercontent.com/fixture/repo/{PARENT}/old%20name.md"), refs)
        self.assertIn(("repository_file", f"https://raw.githubusercontent.com/fixture/repo/{PARENT}/source.txt"), refs)
        self.assertNotIn("evil.test", repr(refs) + repr(report))
        self.assertNotIn("secret raw line", repr(report))
        self.assertNotIn("가격", repr(report))
        self.assertIn("commit_patch_hunks_not_reviewed", report["pending_reviews"])

    def test_strict_body_sha_url_and_filename_provenance(self):
        valid = [{"status": "modified", "filename": "ok.json"}]
        report, refs = analyze_commit_detail(payload(valid, sha=PARENT), DETAIL)
        self.assertEqual([], refs)
        self.assertIn("commit_detail_provenance_invalid", report["pending_reviews"])
        for url in (DETAIL + "&page=2", DETAIL.replace("api.github.com", "api.github.com.evil.test"),
                    DETAIL.replace("page=1", "page=31")):
            report, refs = analyze_commit_detail(payload(valid), url)
            self.assertEqual([], refs)
            self.assertIn("commit_detail_url_invalid", report["pending_reviews"])
        files = [{"status": "modified", "filename": "ok.json"},
                 {"status": "renamed", "filename": "new.json", "previous_filename": "../escape.json"},
                 {"status": "modified", "filename": "https://evil.test/file"}]
        report, refs = analyze_commit_detail(payload(files), DETAIL)
        self.assertFalse(report["file_list_page_complete"])
        self.assertEqual(2, report["invalid_file_rows"])
        self.assertEqual(2, len(refs))
        self.assertIn("commit_file_metadata_invalid", report["pending_reviews"])

    def test_only_observed_same_commit_next_link_is_returned(self):
        body = payload([{"status": "added", "filename": f"x/{index}.txt"} for index in range(100)])
        page2 = DETAIL.replace("&page=1", "&page=2")
        report, refs = analyze_commit_detail(body, DETAIL, link_header=f'<{page2}>; rel="next"')
        self.assertTrue(report["next_page_observed"])
        self.assertIn(("repository_commit_detail", page2), refs)
        for link in (f'<{page2.replace("fixture/repo", "other/repo")}>; rel="next"',
                     f'<{page2.replace("&page=2", "&page=3")}>; rel="next"',
                     f'<{page2.replace("api.github.com", "evil.test")}>; rel="next"'):
            report, refs = analyze_commit_detail(body, DETAIL, link_header=link)
            self.assertFalse(report["next_page_observed"])
            self.assertIn("commit_pagination_link_invalid", report["pending_reviews"])
            self.assertFalse(any(kind == "repository_commit_detail" for kind, _ in refs))
        report, _ = analyze_commit_detail(body, DETAIL)
        self.assertIn("commit_pagination_unverified", report["pending_reviews"])

    def test_merge_and_missing_parent_are_visible_gaps(self):
        file = [{"status": "modified", "filename": "x.py"}]
        report, refs = analyze_commit_detail(payload(file, parents=[{"sha": PARENT}, {"sha": "c" * 40}]), DETAIL)
        self.assertIn("merge_parent_lineage_unreviewed", report["pending_reviews"])
        self.assertEqual(2, len(refs))
        report, refs = analyze_commit_detail(payload(file, parents=[]), DETAIL)
        self.assertIn("previous_revision_unavailable", report["pending_reviews"])
        self.assertEqual(1, len(refs))
        report, refs = analyze_commit_detail(payload(file, parents=[{"sha": "branch"}]), DETAIL)
        self.assertIn("commit_parent_provenance_invalid", report["pending_reviews"])
        self.assertEqual([], refs)

    def test_bounded_input_and_incomplete_inline_patch(self):
        body = payload([{"status": "modified", "filename": "x.py"}])
        report, refs = analyze_commit_detail(body, DETAIL, max_bytes=len(body) - 1)
        self.assertIn("commit_detail_byte_limit_reached", report["pending_reviews"])
        self.assertEqual([], refs)
        report, refs = analyze_commit_detail(body, DETAIL)
        self.assertEqual(1, report["inline_patch_missing"])
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(2, len(refs))
        for limit in (0, True, 32 * 1024 * 1024 + 1):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                analyze_commit_detail(body, DETAIL, max_bytes=limit)

    def test_zero_file_commit_requires_zero_stats_and_complete_first_page(self):
        zeros = {"total": 0, "additions": 0, "deletions": 0}
        report, refs = analyze_commit_detail(payload([], stats=zeros), DETAIL)
        self.assertTrue(report["empty_diff_verified"])
        self.assertTrue(report["analysis_complete"])
        self.assertEqual("no_changed_files_verified", report["patch_content_review"])
        self.assertEqual([], refs)
        self.assertNotIn("commit_patch_hunks_not_reviewed", report["pending_reviews"])
        self.assertTrue(analyze_commit_detail(payload([]), DETAIL)[0]["empty_diff_verified"])
        for body, link in (
            (payload([], stats={"total": 1, "additions": 0, "deletions": 0}), None),
            (payload([], stats=zeros, parents=[{"sha": PARENT}, {"sha": "c" * 40}]), None),
            (payload([], stats=zeros), f'<{DETAIL.replace("page=1", "page=2")}>; rel="next"'),
        ):
            with self.subTest(body=body[:40], link=link):
                report, _ = analyze_commit_detail(body, DETAIL, link_header=link)
                self.assertFalse(report["empty_diff_verified"])
                self.assertFalse(report["analysis_complete"])


if __name__ == "__main__":
    unittest.main()
