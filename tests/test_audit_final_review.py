"""Synthetic regression for repository jobs in the common audit ledger."""
import hashlib
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sudetect.audit import Case, init_case, run_case, read_json, write_json
from sudetect.policy import Scope
from sudetect.repository_workflow import bind_repositories
from sudetect.transport import FetchResult


REPO_A = "fixture-alpha/portal"
REPO_B = "fixture-beta/portal"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
OWNER = "fixture:repository-owner"


def repository_scope():
    targets = []
    for repo in (REPO_A, REPO_B):
        targets.extend([
            {"origin": "https://api.github.com", "owner": "fixture", "ownership_evidence": OWNER,
             "path_prefixes": [f"/repos/{repo}/git/trees/", f"/repos/{repo}/commits"]},
            {"origin": "https://raw.githubusercontent.com", "owner": "fixture", "ownership_evidence": OWNER,
             "path_prefixes": [f"/{repo}/"]},
            {"origin": "https://github.com", "owner": "fixture", "ownership_evidence": OWNER,
             "path_prefixes": [f"/{repo}/commit/"]},
        ])
    return Scope.from_dict({"policy_id": "fixture-repository", "expires_at": "2099-01-01T00:00:00Z",
                            "targets": targets})


def manifest(*, ownership="confirmed"):
    return {"schema_version": "1.0", "scope_id": "fixture", "expires_at": "2099-01-01T00:00:00Z",
            "repositories": [{"repository": repo, "branch": "main", "owner_ref": OWNER,
                              "ownership_status": ownership, "pages": [], "deployment_urls": []}
                             for repo in (REPO_A, REPO_B)]}


def patch_body(sha, added):
    return ("\n".join([f"From {sha} Mon Sep 17 00:00:00 2001",
        "From: Private Person <private@example.test>", "Subject: [PATCH] synthetic",
        "diff --git a/src/app.py b/src/app.py", "--- a/src/app.py", "+++ b/src/app.py",
        "@@ -1 +1 @@", "-safe", "+" + added, ""])).encode()


def observed(body, url, scope, *, media="application/json"):
    scope.authorize(url)
    scope.budget.consume()
    return FetchResult({"observation_id": str(uuid.uuid4()),
        "observed_at": datetime.now(timezone.utc).isoformat(), "policy_id": scope.policy_id,
        "access": "BODY_SERVED", "capture_complete": True, "http_status": 200,
        "reason": "response_observed", "sha256": hashlib.sha256(body).hexdigest(), "redirects": []},
        body, {"content-type": media})


class AuditFinalReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "case"
        init_case(self.root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})

    def tearDown(self):
        self.temp.cleanup()

    def test_history_patch_chain_stops_sensitive_repo_only(self):
        secret = "ghp_" + "x" * 24
        urls = []

        def fetch(url, scope):
            urls.append(url)
            parts = urlsplit(url)
            if "/git/trees/" in parts.path:
                body, media = b'{"truncated":false,"tree":[]}', "application/json"
            elif parts.path.endswith("/commits"):
                shas = [SHA_A, SHA_B] if REPO_A in parts.path else [SHA_C]
                body, media = json.dumps([{"sha": sha} for sha in shas]).encode(), "application/json"
            elif parts.path.endswith(".patch"):
                sha = parts.path.rsplit("/", 1)[1][:-6]
                added = secret + " https://sensitive.example.test/private" if sha == SHA_A else (
                    "https://new.example.test/reference" if sha == SHA_C else "safe")
                body, media = patch_body(sha, added), "text/plain"
            else:
                raise AssertionError(f"unexpected fetch: {url}")
            return observed(body, url, scope, media=media)

        with Case(self.root) as case:
            active = repository_scope()
            self.assertTrue(bind_repositories(case, manifest(), active)["ready"])
            execution = run_case(case, {"max_requests": 12, "max_jobs": 20}, scope=active,
                                 fetcher=fetch, inspection_only=True)
            jobs = case.queue.status()["jobs"]
            histories = [job for job in jobs if job["job_type"] == "repository_history"]
            patches = [job for job in jobs if job["job_type"] == "repository_patch"]
            self.assertEqual(2, len(histories))
            self.assertEqual(3, len(patches))
            self.assertTrue(all(job["parent_job_id"] in {h["job_id"] for h in histories} for job in patches))
            self.assertEqual(1, sum(job["state"] == "blocked_input" for job in patches),
                             {"patches": [(job["state"], job["last_error_code"]) for job in patches],
                              "run": execution["run"], "urls": urls})
            self.assertEqual(2, sum(job["state"] == "succeeded" for job in patches))
            self.assertIn(f"https://github.com/{REPO_A}/commit/{SHA_A}.patch", urls)
            self.assertNotIn(f"https://github.com/{REPO_A}/commit/{SHA_B}.patch", urls)
            self.assertIn(f"https://github.com/{REPO_B}/commit/{SHA_C}.patch", urls)
            self.assertEqual(9, len(urls))  # Two current trees, three snapshot trees, two histories, two patches.
            self.assertFalse(any("new.example.test" in url or "sensitive.example.test" in url for url in urls))
            reports = [json.loads(row[0]) for row in case.ledger.db.execute("SELECT report_json FROM audit_results")]
            self.assertEqual([2, 1], sorted((r["patches_emitted"] for r in reports
                                              if r.get("document_type") == "repository_history"), reverse=True))
            sensitive = next(r for r in reports if r.get("hold_repository_patch_lineage"))
            self.assertIn("sensitive_candidate_stop", sensitive["gaps"])
            self.assertNotIn("literal_url_changes", sensitive)
            safe = next(r for r in reports if r.get("document_type") == "repository_patch"
                        and r.get("analysis_complete"))
            self.assertTrue(safe["literal_url_changes"]["introduced_locator_refs"])
            encoded = json.dumps(reports)
            self.assertNotIn(secret, encoded)
            self.assertNotIn("private@example.test", encoded)
            self.assertNotIn("new.example.test", encoded)

    def test_changed_binding_blocks_previously_queued_capture(self):
        for mode in ("expired", "investigation"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "case"
                    init_case(root, {"scope_id": "fixture", "identity": {"company_en": "Fixture", "domains": []}})
                    calls = []
                    with Case(root) as case:
                        active = repository_scope()
                        bind_repositories(case, manifest(), active)
                        binding = read_json(root / "repository-bindings.json")
                        if mode == "expired":
                            binding["expires_at"] = "2000-01-01T00:00:00Z"
                        else:
                            binding["repositories"][0]["ownership_status"] = "investigation"
                        write_json(root / "repository-bindings.json", binding)

                        def fetch(url, scope):
                            calls.append(url)
                            return observed(b'{"truncated":false,"tree":[]}', url, scope)

                        run_case(case, {"max_requests": 2, "max_jobs": 2}, scope=active,
                                 fetcher=fetch, inspection_only=True)
                        guarded = [job for job in case.queue.status()["jobs"]
                                   if job["job_type"] in {"repository_tree", "repository_history"}
                                   and REPO_A in case.locators.get(case.scope_id, job["asset_ref"])]
                        self.assertTrue(guarded)
                        self.assertTrue(any(job["state"] == "blocked_scope" for job in guarded),
                                        [(job["state"], job["last_error_code"]) for job in guarded])
                        self.assertFalse(any(REPO_A in url for url in calls))


if __name__ == "__main__":
    unittest.main()
