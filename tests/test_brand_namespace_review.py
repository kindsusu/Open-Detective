import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sudetect import search_plan
from sudetect.search_plan import brand_namespace_review, create_plan, declare_owned_accounts


def set_account(plan, login, **fields):
    job = next(j for j in plan["jobs"] if j["kind"] == "account_candidate" and j["value"] == login)
    job.update(fields)
    return job


class BrandNamespaceReviewTests(unittest.TestCase):
    def plan(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent", account_budget=10)
        return plan

    def test_existing_unowned_namespace_needs_review(self):
        plan = self.plan()
        set_account(plan, "melodyrent", state="completed", end_condition="page_exhausted", result_count=0,
                    observed_at="2026-01-01T00:00:00Z")
        set_account(plan, "melody-rent", state="completed", end_condition="not_found_observed", result_count=0)
        plan = declare_owned_accounts(plan, ["Melody-Rent-Official"], "asset-register:1")
        report = brand_namespace_review(plan)
        logins = {row["login"]: row for row in report["existing_namespaces"]}
        self.assertEqual("review_required", logins["melodyrent"]["status"])
        self.assertEqual("BRAND_NAMESPACE_CANDIDATE", logins["melodyrent"]["signal"])
        self.assertNotIn("melody-rent", logins)
        self.assertEqual(1, report["review_required"])
        self.assertIn("existence_is_not_ownership", report["limitations"])

    def test_owned_and_excluded_are_not_flagged_and_unobserved_counted(self):
        plan = self.plan()
        set_account(plan, "melodyrent", state="completed", end_condition="page_exhausted", result_count=3)
        plan = declare_owned_accounts(plan, ["melodyrent"], "asset-register:1")
        report = brand_namespace_review(plan)
        row = next(r for r in report["existing_namespaces"] if r["login"] == "melodyrent")
        self.assertEqual("owned", row["status"])
        self.assertIsNone(row["signal"])
        self.assertEqual(0, report["review_required"])
        self.assertGreater(report["unobserved_identity_candidates"], 0)
        set_account(plan, "melody", state="completed", end_condition="page_exhausted", result_count=1)
        plan["excluded_accounts"] = [{"login": "melody", "reason": "different company"}]
        excluded = next(r for r in brand_namespace_review(plan)["existing_namespaces"] if r["login"] == "melody")
        self.assertEqual("excluded", excluded["status"])
        self.assertIsNone(excluded["signal"])

    def test_owned_requires_evidence_and_valid_login(self):
        plan = self.plan()
        with self.assertRaises(ValueError):
            declare_owned_accounts(plan, ["melodyrent"], "")
        with self.assertRaises(ValueError):
            declare_owned_accounts(plan, ["bad/login"], "x")

    def test_cli_own_and_namespaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            plan = self.plan()
            set_account(plan, "melodyrent", state="completed", end_condition="page_exhausted", result_count=0)
            path.write_text(json.dumps(plan), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, search_plan.main(["own", "--plan", str(path), "--account", "melodyrent",
                                                      "--evidence", "asset-register:1"]))
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(0, search_plan.main(["namespaces", "--plan", str(path)]))
            report = json.loads(buffer.getvalue())
            self.assertEqual("owned", report["existing_namespaces"][0]["status"])


if __name__ == "__main__":
    unittest.main()
