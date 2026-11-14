import unittest

from sudetect.search_plan import (IDENTITY_ACCOUNT_LIMIT, create_plan,
                                  reconcile_generated_jobs)


def planned_accounts(plan):
    return [job["value"] for job in plan["jobs"]
            if job["kind"] == "account_candidate" and job["state"] == "planned"]


class IdentityAccountPriorityTests(unittest.TestCase):
    def test_numeric_sibling_of_hyphenated_identity_is_planned(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent Car",
                           aliases=["melodyrent"], industry=["rentcar"])
        planned = planned_accounts(plan)
        for value in ("melodyrentcar", "melody-rentcar", "melodyrent-car",
                      "melody-rent-car", "melodyrent", "melody-rentcar1", "melodyrentcar1"):
            self.assertIn(value, planned)

    def test_identity_core_is_bounded_and_generic_budget_still_applies(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent Car",
                           aliases=["melodyrent"], industry=["rentcar"], account_budget=4)
        core = [job for job in plan["jobs"] if job["kind"] == "account_candidate"
                and job["state"] == "planned"
                and job["value"].startswith(("melodyrent", "melody-rent"))
                and job["generation_rationale"].startswith(("identity-core", "stem"))]
        self.assertLessEqual(len(planned_accounts(plan)), IDENTITY_ACCOUNT_LIMIT + 4)
        self.assertGreater(len(core), 0)
        deferred = [job for job in plan["jobs"] if job["kind"] == "account_candidate"
                    and job["state"] == "deferred"]
        self.assertTrue(all(job["deferred_reason"] == "account_budget_exceeded" for job in deferred))

    def test_no_character_guessing_for_single_word_identity(self):
        plan = create_plan(scope_id="fixture", company_en="Galaxy")
        planned = planned_accounts(plan)
        self.assertIn("galaxy1", planned)
        self.assertFalse(any(value.startswith(("gala-", "gal-")) for value in planned))

    def test_old_plan_promotes_unattempted_identity_core_jobs(self):
        plan = create_plan(scope_id="fixture", company_en="Melody Rent Car",
                           aliases=["melodyrent"], industry=["rentcar"])
        old = dict(plan, generation_version=2)
        old["jobs"] = [dict(job) for job in plan["jobs"]
                       if not job["generation_rationale"].startswith("identity-core")]
        for job in old["jobs"]:
            if job["kind"] == "account_candidate" and job["value"] == "melody-rentcar":
                job["state"] = "deferred"; job["deferred_reason"] = "account_budget_exceeded"
            if job["kind"] == "account_candidate" and job["value"] == "melodyrentcar":
                job["state"] = "deferred"; job["deferred_reason"] = "account_budget_exceeded"
                job["attempts"] = [{"state": "failed"}]
        migrated = reconcile_generated_jobs(old)
        states = {job["value"]: job["state"] for job in migrated["jobs"]
                  if job["kind"] == "account_candidate"}
        self.assertEqual("planned", states["melody-rentcar"])
        self.assertEqual("planned", states["melody-rentcar1"])
        self.assertEqual("deferred", states["melodyrentcar"])
        self.assertGreaterEqual(migrated["generation_migration_promoted"], 1)
        self.assertEqual(3, migrated["generation_version"])


if __name__ == "__main__":
    unittest.main()
