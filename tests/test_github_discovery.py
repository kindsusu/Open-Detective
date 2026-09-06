import contextlib
import io
import json
import unittest
import urllib.parse

from sudetect.github_discovery import DiscoveryError, GitHubBroker, discover, main


def repo(owner, name, *, pages=False, homepage=None):
    return {
        "name": name,
        "full_name": f"{owner}/{name}",
        "owner": {"login": owner},
        "private": False,
        "has_pages": pages,
        "homepage": homepage,
    }


class GitHubDiscoveryTests(unittest.TestCase):
    def test_known_detail_runs_before_paginated_search_exhausts_requests(self):
        calls=[]
        def fetch(url,_headers):
            calls.append(url); parsed=urllib.parse.urlsplit(url)
            if parsed.path=="/repos/strong-owner/known-site": return 200,repo("strong-owner","known-site",pages=True),{}
            if parsed.path=="/search/repositories":
                page=int(urllib.parse.parse_qs(parsed.query)["page"][0])
                next_page=page+1
                return 200,{"items":[],"total_count":10,"incomplete_results":False},{"Link":f'<https://api.github.com/search/repositories?q=broad+in%3Aname%2Cdescription%2Creadme&per_page=100&page={next_page}>; rel="next"'}
            self.fail(url)
        result=discover("known-first",seeds=["broad"],known_urls=["https://strong-owner.github.io/known-site/"],
                        max_requests=2,fetch=fetch)
        self.assertEqual("/repos/strong-owner/known-site",urllib.parse.urlsplit(calls[0]).path)
        self.assertIn("strong-owner/known-site",[c["slug"] for c in result["candidates"]])

    def test_repository_search_hit_outranks_user_hits_at_account_cap(self):
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/search/repositories": return 200,{"items":[repo("repo-owner","site",pages=True)],"total_count":1,"incomplete_results":False},{}
            if path=="/search/users": return 200,{"items":[{"login":f"weak-user-{i}"} for i in range(10)],"total_count":10,"incomplete_results":False},{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=discover("repo-priority",seeds=["fictional"],fetch=fetch,max_accounts=3)
        self.assertIn("repo-owner/site",[c["slug"] for c in result["candidates"]])
        self.assertIn("repo-owner",[a["login"] for a in result["accounts"]])
        self.assertLessEqual(len(result["accounts"]),3)

    def test_malformed_known_repository_detail_is_failed_not_complete(self):
        result=discover("detail-invalid",known_urls=["https://github.com/strong-owner/known-site"],
                        fetch=lambda *_:(200,{"unexpected":"row"},{}))
        coverage=result["coverage"]["repository_detail:strong-owner/known-site"]
        self.assertEqual("FAILED",coverage["state"]); self.assertEqual(0,coverage["items"])
        self.assertEqual("MALFORMED_RESPONSE",coverage["error_code"]); self.assertEqual([],result["candidates"])

    def test_github_repository_url_is_accepted_as_known_url(self):
        def fetch(url, _headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/repos/strong-owner/known-site": return 200,repo("strong-owner","known-site",pages=True),{}
            if path=="/users/strong-owner/repos": return 200,[],{}
            self.fail(url)
        result=discover("scope-repo-url",known_urls=["https://github.com/strong-owner/known-site"],fetch=fetch)
        self.assertEqual("COMPLETE",result["status"]); self.assertEqual("strong-owner/known-site",result["candidates"][0]["slug"])

    def test_known_url_candidate_survives_account_cap(self):
        weak=[f"weak-{i}" for i in range(10)]
        def fetch(url,_headers):
            path=urllib.parse.urlsplit(url).path
            if path=="/repos/strong-owner/known-site": return 200,repo("strong-owner","known-site",pages=True),{}
            if path.startswith("/users/"): return 200,[],{}
            self.fail(url)
        result=discover("scope-reserve",accounts=weak,known_urls=["https://strong-owner.github.io/known-site/"],fetch=fetch)
        self.assertIn("strong-owner/known-site",[c["slug"] for c in result["candidates"]])
        self.assertTrue(any(x["reason"]=="not_scheduled_due_to_cap" for x in result["deferred"]))
    def test_native_account_listing_finds_four_pages_candidates_without_web_search(self):
        calls = []

        def fetch(url, headers):
            calls.append((url, dict(headers)))
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/search/users":
                return 200, {"items": [{"login": "northwind-labs"}, {"login": "tailspin-studio"}]}, {}
            if parsed.path == "/search/repositories":
                return 200, {"items": []}, {}
            if parsed.path == "/users/northwind-labs/repos":
                self.assertEqual(["owner"], query["type"])
                return 200, [
                    repo("northwind-labs", "northwind-labs.github.io", pages=True),
                    repo("northwind-labs", "field-notes", pages=True,
                         homepage="https://docs.example.test/field-notes"),
                ], {}
            if parsed.path == "/users/tailspin-studio/repos":
                return 200, [
                    repo("tailspin-studio", "design-handbook", pages=True),
                    repo("tailspin-studio", "release-map", pages=False),
                ], {}
            self.fail(f"unexpected fixed-broker URL: {url}")

        result = discover("fictional-audit", seeds=["fictional cooperative"], fetch=fetch)

        self.assertEqual("COMPLETE", result["status"])
        self.assertEqual(
            [
                "https://northwind-labs.github.io/field-notes/",
                "https://northwind-labs.github.io/",
                "https://tailspin-studio.github.io/design-handbook/",
                "https://tailspin-studio.github.io/release-map/",
            ],
            [item["pages_url_candidate"] for item in result["candidates"]],
        )
        self.assertEqual(4, result["coverage"]["totals"]["unique_repositories"])
        self.assertTrue(all(item["ownership"] == "pending" for item in result["candidates"]))
        self.assertNotIn("web", " ".join(result["methods_executed"]))
        for _, headers in calls:
            lowered = {key.lower() for key in headers}
            self.assertFalse(lowered & {"authorization", "cookie", "proxy-authorization", "referer"})

    def test_known_github_io_url_builds_known_url_account_repo_provenance(self):
        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            if path == "/repos/contoso-archive/public-guide":
                return 200, repo("contoso-archive", "public-guide", pages=True), {}
            if path == "/users/contoso-archive/repos":
                return 200, [repo("contoso-archive", "public-guide", pages=True)], {}
            self.fail(url)

        result = discover(
            "scope-7", known_urls=["https://contoso-archive.github.io/public-guide/start/"], fetch=fetch,
        )
        self.assertEqual("COMPLETE", result["status"])
        edge_tuples = {(edge["source"], edge["target"], edge["relationship"])
                       for edge in result["edges"]}
        known = "known_url:https://contoso-archive.github.io/public-guide/"
        self.assertIn((known, "account:contoso-archive", "identified_account"), edge_tuples)
        self.assertIn(("account:contoso-archive", "repo:contoso-archive/public-guide", "public_repository"), edge_tuples)
        self.assertEqual("https://contoso-archive.github.io/public-guide/",
                         result["candidates"][0]["pages_url_candidate"])

    def test_rate_limit_is_failure_not_zero_complete(self):
        result = discover(
            "scope-8", accounts=["fabrikam-public"],
            fetch=lambda *_: (403, {"message": "do not retain raw detail"}, {}),
        )
        self.assertEqual("FAILED", result["status"])
        self.assertEqual(["RATE_LIMITED"], result["errors"])
        self.assertEqual("FAILED", result["coverage"]["list_public_repositories:fabrikam-public"]["state"])
        self.assertEqual([], result["candidates"])

    def test_broker_rejects_redirects_off_host_paths_and_credentials(self):
        broker = GitHubBroker(fetch=lambda *_: (302, {}, {"location": "https://evil.test/"}))
        valid = "https://api.github.com/search/users?q=sample&per_page=100&page=1"
        with self.assertRaisesRegex(DiscoveryError, "REDIRECT_BLOCKED"):
            broker.get(valid)
        for url in (
            "https://github.com/search/users?q=x&per_page=100&page=1",
            "http://api.github.com/search/users?q=x&per_page=100&page=1",
            "https://token@api.github.com/search/users?q=x&per_page=100&page=1",
            "https://api.github.com/search/code?q=x&per_page=100&page=1",
            "https://api.github.com/search/users?q=x&per_page=nope&page=1",
            "https://api.github.com/users/invalid--account/repos?type=owner&sort=full_name&direction=asc&per_page=100&page=1",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(DiscoveryError, "INPUT_INVALID"):
                broker.get(url)

    def test_malicious_or_skipping_next_link_is_partial_and_not_followed(self):
        calls = []

        def fetch(url, _headers):
            calls.append(url)
            return 200, [repo("adatum-lab", "site", pages=True)], {
                "Link": '<https://api.github.com/users/adatum-lab/repos?type=owner&sort=full_name&direction=asc&per_page=100&page=3>; rel="next"'
            }

        result = discover("scope-9", accounts=["adatum-lab"], fetch=fetch)
        self.assertEqual("PARTIAL", result["status"])
        self.assertIn("PAGINATION_INVALID", result["errors"])
        self.assertEqual(1, len(calls))
        self.assertEqual(1, len(result["candidates"]))

    def test_invalid_known_url_and_dirty_homepage_are_not_emitted(self):
        invalid = discover("scope-10", known_urls=["https://user.github.io/repo/?token=secret"], fetch=lambda *_: [])
        self.assertEqual("FAILED", invalid["status"])
        self.assertEqual(["INPUT_INVALID"], invalid["errors"])

        result = discover(
            "scope-10", accounts=["wingtip-labs"],
            fetch=lambda *_: (200, [repo("wingtip-labs", "docs", homepage="https://docs.example/?key=secret")], {}),
        )
        self.assertIsNone(result["candidates"][0]["homepage"])
        self.assertNotIn("secret", json.dumps(result))

    def test_search_incomplete_and_provider_result_cap_are_partial(self):
        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            if path == "/search/users":
                return 200, {"items": [], "incomplete_results": True, "total_count": 0}, {}
            if path == "/search/repositories":
                return 200, {"items": [], "incomplete_results": False, "total_count": 1001}, {}
            self.fail(url)

        result = discover("scope-search", seeds=["fictional seed"], fetch=fetch)
        self.assertEqual("PARTIAL", result["status"])
        self.assertIn("SEARCH_INCOMPLETE", result["errors"])
        self.assertIn("RESULT_LIMIT_EXCEEDED", result["errors"])
        self.assertEqual("PARTIAL", result["coverage"]["search_users:1"]["state"])

    def test_account_cap_also_bounds_repository_candidates(self):
        rows = [repo(f"fictional-{index}", "docs") for index in range(11)]

        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            if path == "/search/users":
                return 200, {"items": []}, {}
            if path == "/search/repositories":
                return 200, {"items": rows}, {}
            if path.startswith("/users/"):
                return 200, [], {}
            self.fail(url)

        result = discover("scope-cap", seeds=["fictional"], fetch=fetch)
        self.assertEqual(10, len(result["accounts"]))
        self.assertEqual(10, len(result["candidates"]))
        self.assertIn("RESULT_LIMIT_EXCEEDED", result["errors"])
        self.assertEqual("PARTIAL", result["coverage"]["search_repositories:1"]["state"])

    def test_search_missing_link_cannot_claim_complete_before_total(self):
        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            if path == "/search/users":
                return 200, {"items": [], "total_count": 0, "incomplete_results": False}, {}
            if path == "/search/repositories":
                return 200, {"items": [repo("proseware-labs", "docs")],
                             "total_count": 2, "incomplete_results": False}, {}
            if path == "/users/proseware-labs/repos":
                return 200, [], {}
            self.fail(url)

        result = discover("scope-link", seeds=["proseware"], fetch=fetch)
        self.assertEqual("PARTIAL", result["status"])
        self.assertIn("PAGINATION_INVALID", result["errors"])
        self.assertEqual("PARTIAL", result["coverage"]["search_repositories:1"]["state"])

    def test_malformed_row_marks_its_channel_partial(self):
        def fetch(url, _headers):
            path = urllib.parse.urlsplit(url).path
            if path == "/search/users":
                return 200, {"items": [{"unexpected": "row"}], "total_count": 1}, {}
            if path == "/search/repositories":
                return 200, {"items": [], "total_count": 0}, {}
            self.fail(url)

        result = discover("scope-malformed", seeds=["adventure"], fetch=fetch)
        self.assertEqual("PARTIAL", result["status"])
        self.assertIn("MALFORMED_RESPONSE", result["errors"])
        self.assertEqual("PARTIAL", result["coverage"]["search_users:1"]["state"])

    def test_request_cap_is_hard_and_reported(self):
        result = discover(
            "scope-11", accounts=["alpha-labs", "beta-labs"], max_requests=1,
            fetch=lambda *_: (200, [], {}),
        )
        self.assertEqual("PARTIAL", result["status"])
        self.assertIn("REQUEST_LIMIT_EXCEEDED", result["errors"])
        self.assertEqual(1, result["coverage"]["totals"]["requests"])

    def test_standalone_cli_emits_json(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--scope-id", "scope-12", "--max-requests", "0"])
        self.assertEqual(2, code)
        self.assertEqual("FAILED", json.loads(stdout.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
