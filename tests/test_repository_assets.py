"""Offline repository tree discovery fixtures with no real assets or network."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sudetect.github_discovery import discover
from sudetect.repository_assets import analyze_tree, tree_url
from sudetect.search_plan import create_plan, run_plan
from tests.test_github_discovery import repo


def blob(path, sha="a" * 40, size=42):
    return {"path": path, "type": "blob", "mode": "100644", "sha": sha, "size": size}


class RepositoryAssetTests(unittest.TestCase):
    def test_actual_branch_and_commit_metadata_drive_tree_url(self):
        branch = repo("fictional-lab", "portal")
        branch["default_branch"] = "feature/report"
        pinned = repo("fictional-lab", "archive")
        pinned["default_branch"] = "main"
        pinned["commit_sha"] = "b" * 40
        def fetch(url, _headers):
            path = urlsplit(url).path
            if path == "/search/repositories":
                return 200, {"items": [branch, pinned], "total_count": 2,
                             "incomplete_results": False}, {}
            if path == "/search/users":
                return 200, {"items": [], "total_count": 0,
                             "incomplete_results": False}, {}
            return 200, [], {}
        result = discover("fictional", seeds=["fictional"], fetch=fetch)
        candidates = {item["slug"]: item for item in result["candidates"]}
        self.assertEqual("branch_mutable", candidates["fictional-lab/portal"]["source_revision"]["kind"])
        self.assertEqual("commit", candidates["fictional-lab/archive"]["source_revision"]["kind"])
        self.assertEqual("https://api.github.com/repos/fictional-lab/portal/git/trees/feature%2Freport?recursive=1",
                         tree_url(candidates["fictional-lab/portal"]))
        self.assertTrue(tree_url(candidates["fictional-lab/archive"]).endswith("/" + "b" * 40 + "?recursive=1"))
        self.assertIsNone(tree_url({"slug": "fictional-lab/portal", "source_revision": None}))
        self.assertIsNone(tree_url({"slug": "fictional-lab/portal", "source_revision":
                                    {"kind": "commit", "value": "main"}}))

    def test_only_explicit_blob_paths_yield_transient_urls_and_safe_report(self):
        tree = "https://api.github.com/repos/fictional-lab/portal/git/trees/feature%2Freport?recursive=1"
        payload = {"truncated": False, "tree": [
            {"path": "docs", "type": "tree", "sha": "c" * 40},
            blob("docs/견적 2026.pdf"), blob("src/calc.py", sha="b" * 40),
            blob("data/unknown.bin", sha="c" * 40),
            blob("docs/견적 2026.pdf"), blob("../adjacent.pdf"),
            {"path": "guessed.pdf", "type": "blob", "sha": "invalid"},
        ]}
        report, urls = analyze_tree(json.dumps(payload).encode("utf-8"), tree)
        self.assertEqual("PARTIAL", report["status"])
        self.assertEqual("RECORDS_REJECTED", report["error_code"])
        self.assertEqual(3, len(urls))
        self.assertEqual(1, report["unsupported_extensions"])
        self.assertEqual(3, report["rejected_blobs"])
        self.assertIn("feature%2Freport/docs/%EA%B2%AC%EC%A0%81%202026.pdf", urls[0])
        self.assertNotIn("견적", json.dumps(report, ensure_ascii=False))
        self.assertNotIn("docs/", json.dumps(report))
        self.assertNotIn("adjacent", json.dumps(report))
        self.assertTrue(all(url.startswith("https://raw.githubusercontent.com/fictional-lab/portal/")
                            for url in urls))

    def test_truncation_limit_and_parse_failures_remain_explicit(self):
        tree = "https://api.github.com/repos/fictional-lab/portal/git/trees/main?recursive=1"
        body = json.dumps({"truncated": True, "tree": [blob("one.pdf"), blob("two.pdf")]}).encode()
        report, urls = analyze_tree(body, tree, max_files=1)
        self.assertEqual("PARTIAL", report["status"])
        self.assertEqual("TREE_TRUNCATED", report["error_code"])
        self.assertTrue(report["file_limit_reached"])
        self.assertEqual(1, len(urls))
        self.assertEqual("branch_mutable", report["revision_reference"])
        limit_only, limited_urls = analyze_tree(
            json.dumps({"truncated": False, "tree": [blob("one.pdf"), blob("two.pdf")]}).encode(),
            tree, max_files=1)
        self.assertEqual("FILE_LIMIT_REACHED", limit_only["error_code"])
        self.assertEqual(1, len(limited_urls))
        for malformed, code in ((b"\xff", "BYTE_PARSE_FAILED"),
                                (b"{" + b"x" * (8 * 1024 * 1024), "BYTE_LIMIT_EXCEEDED"),
                                (b"[]", "RESPONSE_SHAPE_MISMATCH")):
            with self.subTest(code=code):
                report, urls = analyze_tree(malformed, tree)
                self.assertEqual("FAILED", report["status"])
                self.assertEqual(code, report["error_code"])
                self.assertEqual([], urls)

    def test_invalid_tree_url_never_generates_file_urls(self):
        for tree in ("https://elsewhere.example/repos/fictional-lab/portal/git/trees/main?recursive=1",
                     "https://api.github.com/repos/fictional-lab/portal/git/trees/main?recursive=0",
                     "https://api.github.com/repos/fictional-lab/portal/git/trees/../main?recursive=1"):
            with self.subTest(tree=tree):
                report, urls = analyze_tree(b'{"tree":[]}', tree)
                self.assertEqual("TREE_URL_INVALID", report["error_code"])
                self.assertEqual([], urls)

    def test_synthetic_retry_after_can_be_respected_without_health_claim(self):
        plan = create_plan(scope_id="retry-fixture", company_en="Fictional Lab",
                           query_budget=1, account_budget=1)
        for job in plan["jobs"]:
            if job["channel"] == "github" and job["state"] == "planned":
                job["state"] = "failed"
                job["error_code"] = "RATE_LIMITED"
                job["next_eligible_at"] = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        calls = []
        out = run_plan(plan, fetch=lambda *_: calls.append(1), retry_failed=True,
                       respect_retry_after=True)
        self.assertEqual([], calls)
        self.assertEqual(0, out["last_execution"]["requests_used"])
