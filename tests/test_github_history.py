import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from sudetect.github_history import CodeError, discover_history
from sudetect.locators import LocatorStore
from sudetect.policy import Scope


SHA = "a" * 40


def manifest(**changes):
    value = {
        "scope_id": "fixture-history",
        "repository": "fixture/repo",
        "branch": "main",
        "since": "2026-01-01T00:00:00Z",
        "until": "2026-01-02T00:00:00Z",
        "max_commits": 5,
        "expires_at": "2099-01-01T00:00:00Z",
        "owner_ref": "ownership-record-1",
    }
    value.update(changes)
    return value


def scope(owner_ref="ownership-record-1", prefix="/fixture/repo/commit/"):
    return Scope.from_dict({
        "policy_id": "separate-executable-policy",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://github.com", "owner": "owner-record-1",
                     "ownership_evidence": owner_ref, "path_prefixes": [prefix]}],
        "exclude_urls": [], "max_bytes": 600000, "max_requests": 10, "timeout": 10,
    })


def patch_text(*lines):
    return "\n".join([
        f"From {SHA} Mon Sep 17 00:00:00 2001",
        "From: Person <person@example.test>",
        "Subject: [PATCH] synthetic",
        "diff --git a/data/file.json b/data/file.json",
        "--- a/data/file.json",
        "+++ b/data/file.json",
        "@@ -1 +1 @@",
        *lines,
        "",
    ])


class Fake:
    def __init__(self, listing=None, patch=None, patch_headers=None):
        self.listing = [{"sha": SHA}] if listing is None else listing
        self.patch = patch
        self.patch_headers = patch_headers or {"content-type": "text/plain", "content-encoding": "identity"}
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        path = urlsplit(url).path
        if path == "/repos/fixture/repo":
            return 200, {"full_name": "fixture/repo", "private": False, "visibility": "public"}, {}
        if path == "/repos/fixture/repo/commits":
            return 200, self.listing, {}
        if path == f"/fixture/repo/commit/{SHA}.patch":
            return 200, self.patch, self.patch_headers
        raise AssertionError(f"unexpected request: {url}")


class GitHubHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = LocatorStore(self.root / "locators.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_metadata_mode_never_requests_commit_detail_or_patch(self):
        fake = Fake()
        result = discover_history(manifest(), self.store, fetcher=fake)
        self.assertEqual(2, len(fake.calls))
        self.assertEqual("fixture-history", result["scope_id"])
        self.assertEqual("metadata_only", result["inspection_mode"])
        self.assertNotIn("changed_files", result["commits"][0])
        self.assertTrue(all(not url.endswith(SHA) and not url.endswith(".patch") for url, _ in fake.calls))
        self.assertIn("history_control_not_measured", {gap["reason"] for gap in result["coverage_gaps"]})

    def test_patch_requires_explicit_scope_before_any_request(self):
        fake = Fake(patch=patch_text("-old", "+new"))
        with self.assertRaisesRegex(ValueError, "scope_required"):
            discover_history(manifest(), self.store, inspect_patches=True, fetcher=fake)
        self.assertEqual([], fake.calls)

    def test_patch_scope_must_match_the_authorized_target_ownership(self):
        fake = Fake(patch=patch_text("-old", "+new"))
        with self.assertRaisesRegex(ValueError, "owner_reference_mismatch"):
            discover_history(manifest(), self.store, inspect_patches=True, scope=scope("different"), fetcher=fake)
        self.assertEqual([], fake.calls)

    def test_exact_single_commit_scope_is_accepted(self):
        fake = Fake(patch=patch_text("-old", "+new"))
        result = discover_history(manifest(), self.store, inspect_patches=True,
                                  scope=scope(prefix=f"/fixture/repo/commit/{SHA}.patch"), fetcher=fake)
        self.assertEqual("value_free_summary", result["commits"][0]["patch_inspection"])

    def test_manifest_and_broad_scope_rejected_before_requests(self):
        for change in ({"branch": "main//other"}, {"since": 0}, {"max_commits": True}):
            fake = Fake()
            with self.subTest(change=change), self.assertRaises(ValueError):
                discover_history(manifest(**change), self.store, fetcher=fake)
            self.assertEqual([], fake.calls)
        fake = Fake()
        with self.assertRaisesRegex(ValueError, "owner_reference_mismatch"):
            discover_history(manifest(), self.store, inspect_patches=True, scope=scope(prefix="/"), fetcher=fake)
        self.assertEqual([], fake.calls)

    def test_patch_uses_fixed_anonymous_url_and_emits_only_opaque_values(self):
        old_url = "https://old.example.test/removed"
        new_url = "https://new.example.test/added"
        fake = Fake(patch=patch_text("-" + old_url, "+" + new_url))
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        self.assertEqual(f"https://github.com/fixture/repo/commit/{SHA}.patch", fake.calls[-1][0])
        self.assertNotIn("Authorization", fake.calls[-1][1])
        commit = result["commits"][0]
        changes = commit["literal_url_changes"]
        self.assertEqual(new_url, self.store.get("fixture-history", changes["introduced_locator_refs"][0]))
        self.assertEqual(old_url, self.store.get("fixture-history", changes["removed_locator_refs"][0]))
        encoded = json.dumps(result)
        self.assertNotIn("person@example.test", encoded)
        self.assertNotIn(old_url, encoded)
        self.assertNotIn(new_url, encoded)
        self.assertNotIn("data/file.json", encoded)

    def test_sensitive_changed_hunk_stops_before_literal_collection(self):
        secret = "ghp_" + "x" * 24
        fake = Fake(patch=patch_text("-safe", "+" + secret + " https://candidate.example.test"))
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        commit = result["commits"][0]
        self.assertEqual("stopped_sensitive_candidate", commit["content_review"])
        self.assertNotIn("literal_url_changes", commit)
        self.assertNotIn(secret, json.dumps(result))
        self.assertIn("sensitive_candidate_stop", {gap["reason"] for gap in result["coverage_gaps"]})

    def test_client_password_comparison_stops_url_collection(self):
        fake = Fake(patch=patch_text("-old", '+const password = "fixture-only"; https://candidate.example.test'))
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        commit = result["commits"][0]
        self.assertEqual("stopped_sensitive_candidate", commit["content_review"])
        self.assertIn("CLIENT_PASSWORD_CANDIDATE", commit["signal_codes"])
        self.assertNotIn("literal_url_changes", commit)

    def test_sensitive_candidate_stops_remaining_commits(self):
        second = "b" * 40
        fake = Fake(listing=[{"sha": SHA}, {"sha": second}],
                    patch=patch_text("-safe", "+ghp_" + "x" * 24))
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        self.assertEqual(1, len(result["commits"]))
        gap = next(gap for gap in result["coverage_gaps"] if gap["reason"] == "remaining_commits_not_inspected")
        self.assertEqual(1, gap["count"])
        self.assertTrue(result["history_truncated"])
        self.assertEqual(3, len(fake.calls))

    def test_later_scope_denial_retains_earlier_commit(self):
        second = "b" * 40
        fake = Fake(listing=[{"sha": SHA}, {"sha": second}], patch=patch_text("-old", "+new"))
        original = Scope.authorize

        def authorize(target_scope, url):
            if second in url:
                raise ValueError("excluded")
            return original(target_scope, url)

        with patch.object(Scope, "authorize", authorize):
            result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        self.assertEqual(2, len(result["commits"]))
        self.assertEqual("value_free_summary", result["commits"][0]["patch_inspection"])
        self.assertEqual("incomplete", result["commits"][1]["patch_inspection"])
        self.assertIn("patch_scope_authorization_failed", {g["reason"] for g in result["coverage_gaps"]})
        self.assertEqual(3, len(fake.calls))

    def test_hunk_lines_that_look_like_file_headers_are_not_reparsed(self):
        fake = Fake(patch=patch_text("--- synthetic deleted value", "+++ synthetic added value"))
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=fake)
        self.assertEqual("value_free_summary", result["commits"][0]["patch_inspection"])
        self.assertEqual(1, len(result["commits"][0]["changed_files"]))

    def test_zero_count_hunks_and_quoted_space_path(self):
        body = "\n".join([f"From {SHA} Mon Sep 17 00:00:00 2001", "diff --git a/data/old b/data/new",
                          '--- /dev/null', '+++ "b/data/space name.json"',
                          "@@ -0,0 +1 @@", "+https://added.example.test/", ""])
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=Fake(patch=body))
        commit = result["commits"][0]
        self.assertEqual("value_free_summary", commit["patch_inspection"])
        self.assertEqual("added", commit["changed_files"][0]["status"])
        self.assertEqual("https://added.example.test/", self.store.get("fixture-history", commit["literal_url_changes"]["introduced_locator_refs"][0]))

    def test_binary_and_rename_only_are_explicit_gaps(self):
        header = f"From {SHA} Mon Sep 17 00:00:00 2001\n"
        cases = [(header + "diff --git a/a.png b/a.png\nGIT binary patch\nliteral 3\nabc\n", "binary_patch_not_inspected"),
                 (header + "diff --git a/old b/new\nrename from old\nrename to new\n", "patch_has_no_text_hunks"),
                 (patch_text("-old", "+new") + "diff --git a/a.png b/a.png\nBinary files a/a.png and b/a.png differ\n", "binary_patch_not_inspected")]
        for body, expected in cases:
            with self.subTest(expected=expected):
                result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=Fake(patch=body))
                self.assertEqual("incomplete", result["commits"][0]["patch_inspection"])
                self.assertIn(expected, {g["reason"] for g in result["coverage_gaps"]})
                self.assertNotIn("literal_url_changes", result["commits"][0])

    def test_analysis_limit_blocks_urls_after_classifier_window(self):
        body = patch_text("-old", "+" + "x" * 262144 + " https://outside.example.test/")
        result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(), fetcher=Fake(patch=body))
        self.assertEqual("stopped_analysis_limit", result["commits"][0]["content_review"])
        self.assertNotIn("literal_url_changes", result["commits"][0])
        self.assertIn("patch_analysis_limit_reached", {g["reason"] for g in result["coverage_gaps"]})

    def test_plaintext_transport_path_is_bounded_and_anonymous(self):
        calls = []
        payload = patch_text("-old", "+new").encode()

        class Response:
            status = 200
            def __init__(self):
                self.data = payload
            def read1(self, size):
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk
            read = read1
            def getheader(self, name):
                return "text/plain" if name == "Content-Type" else None

        class Connection:
            def request(self, method, target, headers):
                calls.append((method, target, headers))
            def getresponse(self):
                return Response()
            def close(self):
                pass

        with (patch("sudetect.transport._default_resolver", return_value=["8.8.8.8"]),
              patch("sudetect.transport._default_connection", return_value=Connection()),
              patch("sudetect.github_history.HistoryBroker.preflight"),
              patch("sudetect.github_history.HistoryBroker.api", return_value=[{"sha": SHA}])):
            result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope())
        self.assertEqual("value_free_summary", result["commits"][0]["patch_inspection"])
        self.assertEqual(1, len(calls))
        self.assertEqual("GET", calls[0][0])
        self.assertEqual(f"/fixture/repo/commit/{SHA}.patch", calls[0][1])
        self.assertEqual("identity", calls[0][2]["Accept-Encoding"])
        self.assertNotIn("Authorization", calls[0][2])

    def test_duplicate_commit_sha_is_rejected(self):
        fake = Fake(listing=[{"sha": SHA}, {"sha": SHA}])
        with self.assertRaisesRegex(CodeError, "MALFORMED_HISTORY"):
            discover_history(manifest(), self.store, fetcher=fake)

    def test_invalid_provenance_and_truncated_patch_are_gaps(self):
        cases = [
            ("From " + "b" * 40 + " Mon Sep 17 00:00:00 2001\n", "patch_provenance_invalid"),
            (f"From {SHA} " + "x" * (512 * 1024), "patch_byte_limit_reached"),
        ]
        for body, expected in cases:
            with self.subTest(expected=expected):
                result = discover_history(manifest(), self.store, inspect_patches=True, scope=scope(),
                                          fetcher=Fake(patch=body))
                self.assertEqual("incomplete", result["commits"][0]["patch_inspection"])
                self.assertIn(expected, {gap["reason"] for gap in result["coverage_gaps"]})

    def test_commit_cap_and_zero_are_explicit_nonconclusive_gaps(self):
        capped = discover_history(manifest(max_commits=1), self.store, fetcher=Fake())
        self.assertTrue(capped["history_truncated"])
        self.assertIn("commit_cap_reached_possible_more", {gap["reason"] for gap in capped["coverage_gaps"]})
        zero = discover_history(manifest(), self.store, fetcher=Fake(listing=[]))
        self.assertFalse(zero["history_truncated"])
        self.assertIn("zero_history_result_nonconclusive", {gap["reason"] for gap in zero["coverage_gaps"]})

    def test_nonpublic_preflight_blocks_history_listing(self):
        def private(url, headers):
            return 200, {"full_name": "fixture/repo", "private": True, "visibility": "private"}, {}
        with self.assertRaisesRegex(CodeError, "REPOSITORY_NOT_PUBLIC"):
            discover_history(manifest(), self.store, fetcher=private)


if __name__ == "__main__":
    unittest.main()
