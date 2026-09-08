import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from sudetect import inventory


def _page(key, items, next_value=None):
    return {key: items, "pagination": {"count": len(items), "next": next_value}}


class InventoryTests(unittest.TestCase):
    def test_import_locator_store_preserves_two_exact_paths_without_report_leak(self):
        from sudetect.locators import LocatorStore
        payload=self._import_payload()
        payload["assets"].append({**payload["assets"][0],"url":"https://x.example/path-b?token=two","source_record_id":"record-2"})
        payload["assets"][0]["url"]="https://x.example/path-a?token=one"
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"locators.db") as store:
            report=inventory.import_inventory("org",payload,locator_store=store)
            refs=[asset["locator_ref"] for asset in report["assets"]]
            self.assertEqual({"ready"},{asset["handoff_state"] for asset in report["assets"]})
            self.assertEqual({"https://x.example/path-a?token=one","https://x.example/path-b?token=two"},
                             {store.get("org",ref) for ref in refs})
            encoded=json.dumps(report)
            self.assertNotIn("path-a",encoded); self.assertNotIn("token=",encoded)

    def test_vercel_deployment_and_alias_are_mapped_and_project_is_not(self):
        from sudetect.locators import LocatorStore
        def fetch(url,_headers):
            parsed=urlsplit(url)
            if parsed.path=="/v10/projects": return _page("projects",[{"id":"p1"}])
            if parsed.path=="/v9/projects/p1": return {}
            if parsed.path=="/v6/deployments": return _page("deployments",[{"uid":"d1","url":"d1.vercel.app","target":"production"}])
            if parsed.path.endswith("/aliases"): return {"aliases":[{"uid":"a1","alias":"alias.example.com","created":1}]}
            if parsed.path.endswith("/domains"): return _page("domains",[])
            raise AssertionError(url)
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"locators.db") as store:
            report=inventory.collect_vercel("team-1","secret",fetch=fetch,locator_store=store)
            assets={asset["kind"]:asset for asset in report["assets"]}
            self.assertEqual("not_applicable",assets["project"]["handoff_state"])
            self.assertEqual("ready",assets["deployment"]["handoff_state"])
            self.assertEqual("https://d1.vercel.app",store.get("team-1",assets["deployment"]["locator_ref"]))
            self.assertEqual("https://alias.example.com",store.get("team-1",assets["deployment_alias"]["locator_ref"]))
            self.assertTrue(any(edge["source_asset_id"]==assets["deployment"]["asset_id"] and
                                edge["target_asset_id"]==assets["deployment_alias"]["asset_id"] for edge in report["edges"]))

    def test_vercel_uses_documented_project_cursor_and_unpaginated_alias_endpoint(self):
        calls = []

        def fetch(url, headers):
            calls.append((url, headers))
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            self.assertNotIn("token", url.lower())
            if parsed.path == "/v10/projects":
                self.assertNotIn("until", query)
                return _page("projects", [{"id": "p1", "passwordProtection": True}], "c2") if "from" not in query else _page("projects", [{"id": "p2"}])
            if parsed.path == "/v6/deployments":
                project_id = query["projectId"][0]
                if project_id == "p1" and "until" not in query:
                    return _page("deployments", [{"uid": "d1", "url": "d1.vercel.app", "target": "production"}], 123)
                if project_id == "p1":
                    return _page("deployments", [{"uid": "d2", "url": "d2.vercel.app"}])
                return _page("deployments", [])
            if parsed.path in {"/v9/projects/p1", "/v9/projects/p2"}:
                return {"deploymentProtection": {"all": True}}
            if parsed.path.endswith("/aliases"):
                self.assertEqual({"teamId": ["team-1"]}, query)
                deployment_id = parsed.path.split("/")[3]
                return {"aliases": [{"uid": f"a-{deployment_id}", "alias": f"{deployment_id}.example.com", "created": 1}]}
            if parsed.path.endswith("/domains"):
                return _page("domains", [])
            raise AssertionError(url)

        report = inventory.collect_vercel("team-1", "secret", fetch=fetch)
        self.assertEqual("COMPLETE", report["status"])
        self.assertEqual(2, report["coverage"]["projects"]["pages"])
        self.assertEqual(2, report["coverage"]["deployments:p1"]["pages"])
        self.assertEqual(2, len([asset for asset in report["assets"] if asset["kind"] == "deployment_alias"]))
        self.assertTrue(all(asset["url"] is None or "?" not in asset["url"] for asset in report["assets"]))

    def test_vercel_array_project_variant_preserves_rows_but_is_partial(self):
        def fetch(url, _headers):
            parsed = urlsplit(url)
            if parsed.path == "/v10/projects":
                return [{"id": "p"}]
            if parsed.path == "/v9/projects/p":
                return {}
            if parsed.path == "/v6/deployments":
                return _page("deployments", [])
            if parsed.path.endswith("/domains"):
                return _page("domains", [])
            raise AssertionError(url)

        report = inventory.collect_vercel("team", "x", fetch=fetch)
        self.assertEqual("PARTIAL", report["status"])
        self.assertIn("PAGINATION_UNCONFIRMED", report["errors"])
        self.assertEqual(1, len([asset for asset in report["assets"] if asset["kind"] == "project"]))

    def test_vercel_missing_keys_and_nonmapping_items_are_partial(self):
        cases = [
            {"pagination": {"count": 0, "next": None}},
            _page("projects", ["not-an-object"]),
            {"projects": [{"id": "p"}]},
        ]
        for response in cases:
            with self.subTest(response=response):
                report = inventory.collect_vercel("team", "x", fetch=lambda *_args, response=response: response)
                self.assertIn("MALFORMED_RESPONSE", report["errors"])
                self.assertNotEqual("COMPLETE", report["status"])

    def test_vercel_malformed_nested_rows_preserve_valid_assets_as_partial(self):
        def fetch(url, _headers):
            parsed = urlsplit(url)
            if parsed.path == "/v10/projects":
                return _page("projects", [{"id": "p"}])
            if parsed.path == "/v9/projects/p":
                return {}
            if parsed.path == "/v6/deployments":
                return _page("deployments", [
                    {"uid": "good", "url": "good.vercel.app"},
                    {"uid": "bad"},
                    "not-an-object",
                ])
            if parsed.path.endswith("/aliases"):
                return {"aliases": [
                    {"uid": "a-good", "alias": "good.example.com", "created": 1},
                    {"alias": "missing-fields.example.com"},
                    "not-an-object",
                ]}
            if parsed.path.endswith("/domains"):
                return _page("domains", [
                    {"name": "valid.example.com", "verified": True},
                    {"name": "missing-verified.example.com"},
                    "not-an-object",
                ])
            raise AssertionError(url)

        report = inventory.collect_vercel("team", "x", fetch=fetch)
        self.assertEqual("PARTIAL", report["status"])
        self.assertIn("MALFORMED_RESPONSE", report["errors"])
        kinds = [asset["kind"] for asset in report["assets"]]
        self.assertEqual(1, kinds.count("deployment"))
        self.assertEqual(1, kinds.count("deployment_alias"))
        self.assertEqual(1, kinds.count("project_domain"))
        self.assertEqual("PARTIAL", report["coverage"]["deployments:p"]["state"])
        self.assertEqual("PARTIAL", report["coverage"]["aliases:good"]["state"])
        self.assertEqual("PARTIAL", report["coverage"]["domains:p"]["state"])

    def test_cursor_loop_is_partial_not_zero(self):
        def fetch(url, _headers):
            parsed = urlsplit(url)
            if parsed.path == "/v10/projects":
                return _page("projects", [{"id": "p"}], "same")
            if parsed.path == "/v9/projects/p":
                return {}
            if parsed.path == "/v6/deployments":
                return _page("deployments", [])
            if parsed.path.endswith("/domains"):
                return _page("domains", [])
            raise AssertionError(url)

        report = inventory.collect_vercel("team", "x", fetch=fetch)
        self.assertEqual("PARTIAL", report["status"])
        self.assertIn("CURSOR_LOOP", report["errors"])

    def test_rate_limit_is_failed_channel(self):
        report = inventory.collect_github("owner", "x", fetch=lambda *_: (429, {"message": "secret raw response"}, {}))
        self.assertEqual("FAILED", report["status"])
        self.assertEqual(["RATE_LIMITED"], report["errors"])
        self.assertNotIn("secret", json.dumps(report))

    def test_github_link_pagination_private_existence_and_tree_truncation(self):
        def fetch(url, _headers):
            parsed = urlsplit(url)
            if parsed.path == "/user":
                return {"login": "someone-else"}
            if parsed.path.startswith("/orgs/"):
                if parse_qs(parsed.query)["page"] == ["1"]:
                    return 200, [{"id": 1, "full_name": "acme/secret", "private": True, "default_branch": "main"}], {"Link": '<https://api.github.com/orgs/acme/repos?type=all&per_page=100&page=2>; rel="next"'}
                return 200, [], {}
            return {"tree": [{"path": "private.txt"}], "truncated": True}

        report = inventory.collect_github("acme", "x", fetch=fetch, include_trees=True)
        self.assertEqual("PARTIAL", report["status"])
        self.assertIn("TREE_TRUNCATED", report["errors"])
        encoded = json.dumps(report)
        self.assertNotIn("private.txt", encoded)
        self.assertNotIn("acme/secret", encoded)
        self.assertEqual("private", report["assets"][0]["visibility"])
        self.assertIn("token_visibility_only", report["coverage"]["repositories"]["coverage_limitations"])
        self.assertIn("zero_items_is_a_bounded_observation", report["coverage"]["repositories"]["coverage_limitations"])

    def test_github_account_scope_uses_authenticated_private_listing(self):
        calls = []

        def fetch(url, _headers):
            calls.append(url)
            parsed = urlsplit(url)
            if parsed.path == "/user":
                return {"login": "alice"}
            if parsed.path == "/user/repos":
                return [{"id": 9, "full_name": "alice/private", "private": True}]
            raise AssertionError(url)

        report = inventory.collect_github("alice", "x", fetch=fetch)
        self.assertEqual("COMPLETE", report["status"])
        self.assertEqual("account", report["coverage"]["repositories"]["scope_kind"])
        self.assertTrue(any("/user/repos" in url for url in calls))

    def test_github_repository_locator_is_ready_with_store_and_masked_in_report(self):
        from sudetect.locators import LocatorStore
        def fetch(url,_headers):
            parsed=urlsplit(url)
            if parsed.path=="/user": return {"login":"someone-else"}
            if parsed.path.startswith("/orgs/"): return [{"id":7,"full_name":"acme/private-repo","private":True}]
            raise AssertionError(url)
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"locators.db") as store:
            report=inventory.collect_github("acme","secret",fetch=fetch,locator_store=store)
            asset=report["assets"][0]
            self.assertEqual("ready",asset["handoff_state"])
            self.assertEqual("https://github.com",asset["url"])
            self.assertEqual("https://github.com/acme/private-repo",store.get("acme",asset["locator_ref"]))
            self.assertNotIn("private-repo",json.dumps(report))

    def _import_payload(self, *, completeness="COMPLETE"):
        return {
            "source": "control-plane:export-1",
            "retrieved_at": "2026-09-06T00:00:00Z",
            "owner_scope": "org",
            "completeness": completeness,
            "assets": [{
                "kind": "custom_share",
                "url": "https://x.example/secret/token?q=abc",
                "owner_evidence": "control-plane:record-1",
                "scope_decision": "approved",
                "source_record_id": "record-1",
                "completeness": completeness,
            }],
        }

    def test_import_preserves_provenance_and_masks_share_path(self):
        report = inventory.import_inventory("org", self._import_payload())
        self.assertEqual("COMPLETE", report["status"])
        self.assertEqual("https://x.example", report["assets"][0]["url"])
        self.assertEqual("control-plane:export-1", report["assets"][0]["source"])
        self.assertEqual("2026-09-06T00:00:00Z", report["assets"][0]["retrieved_at"])
        self.assertEqual("org", report["assets"][0]["owner_scope"])
        self.assertEqual("record-1", report["assets"][0]["source_record_id"])

    def test_import_missing_provenance_does_not_claim_complete(self):
        payload = self._import_payload()
        del payload["source"]
        report = inventory.import_inventory("org", payload)
        self.assertEqual("FAILED", report["status"])
        self.assertIn("IMPORT_PROVENANCE_MISSING", report["errors"])
        self.assertEqual("UNKNOWN", report["coverage"]["normalized_import"]["source_completeness"])

    def test_import_partial_source_or_row_is_partial(self):
        payload = self._import_payload(completeness="PARTIAL")
        report = inventory.import_inventory("org", payload)
        self.assertEqual("PARTIAL", report["status"])
        self.assertIn("IMPORT_SOURCE_INCOMPLETE", report["errors"])
        payload = self._import_payload()
        payload["assets"][0]["completeness"] = "UNKNOWN"
        self.assertEqual("PARTIAL", inventory.import_inventory("org", payload)["status"])

    def test_import_keeps_valid_items_when_later_item_is_invalid(self):
        payload = self._import_payload()
        payload["assets"].append({"kind": "asset"})
        report = inventory.import_inventory("org", payload)
        self.assertEqual("PARTIAL", report["status"])
        self.assertEqual(1, len(report["assets"]))
        self.assertEqual(1, report["coverage"]["normalized_import"]["invalid_items"])
        self.assertIn("IMPORT_INVALID", report["errors"])

    def test_import_rejects_scope_mismatch(self):
        payload = self._import_payload()
        payload["owner_scope"] = "other"
        report = inventory.import_inventory("org", payload)
        self.assertEqual("FAILED", report["status"])
        self.assertIn("IMPORT_PROVENANCE_MISSING", report["errors"])

    def test_collect_uses_only_named_environment_token(self):
        with patch.dict(os.environ, {"SAFE_TOKEN": "value"}, clear=True):
            report = inventory.collect("github", "org", token_env="MISSING", fetch=lambda *_: [])
        self.assertEqual(["TOKEN_MISSING"], report["errors"])

    def test_broker_rejects_same_host_endpoint_scope_and_undocumented_query(self):
        github = inventory.Broker("secret", "github", lambda *_: [], scope_id="acme")
        for url in (
            "https://api.github.com/repos/other/private/git/trees/main?recursive=1",
            "https://api.github.com/orgs/other/repos?type=all&per_page=100&page=1",
            "https://api.github.com:444/user",
        ):
            with self.subTest(url=url), self.assertRaises(inventory.InventoryError):
                github.get(url)
        vercel = inventory.Broker("secret", "vercel", lambda *_: {}, scope_id="team")
        for url in (
            "https://api.vercel.com/v10/projects?teamId=team&limit=100&until=123",
            "https://api.vercel.com/v2/deployments/d/aliases?teamId=team&limit=100",
            "https://api.vercel.com/v2/deployments/d/aliases?teamId=team&until=123",
        ):
            with self.subTest(url=url), self.assertRaises(inventory.InventoryError):
                vercel.get(url)

    def test_github_malicious_link_is_partial_without_following(self):
        calls = []

        def fetch(url, _headers):
            calls.append(url)
            if url.endswith("/user"):
                return {"login": "other"}
            return 200, [], {"link": '<https://api.github.com/user/repos?affiliation=owner&visibility=all&per_page=100&page=2>; rel="next"'}

        report = inventory.collect_github("acme", "x", fetch=fetch)
        self.assertEqual("FAILED", report["status"])
        self.assertIn("MALFORMED_RESPONSE", report["errors"])
        self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
