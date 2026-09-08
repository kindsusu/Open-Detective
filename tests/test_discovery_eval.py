import unittest
from sudetect.discovery_eval import evaluate_discovery, load_evaluation


def dataset():
    return {"version":1,"dataset_card":{"dataset_id":"synthetic-1","created_at":"2026-01-01T00:00:00Z","synthetic":True,
        "candidate_ids_fixed_before_runs":True,"test_labels_not_used_for_tuning":True,"split_grouping":"candidate_id","limitations":["synthetic fixture; no Internet optimum claim"]},
        "candidates":[{"candidate_id":"train-a","label":"relevant","families":["identity"]},{"candidate_id":"r","label":"relevant","families":["identity"]},
                      {"candidate_id":"fp","label":"known_false_positive","families":["context"]},{"candidate_id":"u","label":"unlabeled_unknown","families":["identity"]}],
        "splits":{"train":["train-a"],"test":["r","fp","u"]},
        "query_results":[{"query_id":"q1","family":"identity","cost":2,"candidate_ids":["r","u"]},
                         {"query_id":"q2","family":"context","cost":1,"candidate_ids":["fp"]}],
        "schedules":{"baseline":["q2","q1"],"proposed":["q1","q2"]},"budgets":[0,1,2,3]}


class DiscoveryEvalTests(unittest.TestCase):
    def test_same_budget_uses_actual_cost_and_separates_unknown(self):
        out=evaluate_discovery(dataset())
        proposed=out["results"]["proposed"][2]
        self.assertEqual(2,proposed["actual_cost"]); self.assertEqual(1.0,proposed["overall"]["recall_at_budget"])
        self.assertEqual(1,proposed["overall"]["unlabeled_unknown"])
        self.assertEqual(1,proposed["overall"]["known_precision_denominator"])
        self.assertEqual(0,proposed["overall"]["known_false_positive"])
        self.assertTrue(out["input_sha256"].startswith("sha256:")); self.assertFalse(out["reproducibility"]["schedule_optimality_claimed"])
        self.assertFalse(out["reproducibility"]["blind_split_verified"])

    def test_zero_denominators_are_null(self):
        data=dataset(); data["candidates"][1]["label"]="unlabeled_unknown"
        out=evaluate_discovery(data)["results"]["baseline"][0]["overall"]
        self.assertIsNone(out["recall_at_budget"]); self.assertIsNone(out["precision_on_known_labels"])

    def test_rejects_budget_mismatch_duplicate_and_test_leak_declaration(self):
        for mutate in (lambda d:d["schedules"].__setitem__("proposed",["q1"]),
                       lambda d:d["budgets"].__setitem__(slice(None),[2,1]),
                       lambda d:d["dataset_card"].__setitem__("test_labels_not_used_for_tuning",False)):
            data=dataset(); mutate(data)
            with self.assertRaises(ValueError): load_evaluation(data)

    def test_family_metrics_are_bounded_to_declared_family_candidates(self):
        row=evaluate_discovery(dataset())["results"]["proposed"][3]
        self.assertEqual(1.0,row["families"]["identity"]["recall_at_budget"])
        self.assertIsNone(row["families"]["context"]["recall_at_budget"])

    def test_stop_at_first_unaffordable_matches_declared_runtime_policy(self):
        data=dataset(); data["query_results"].append({"query_id":"q3","family":"context","cost":0,"candidate_ids":[]})
        data["schedules"]={"baseline":["q2","q1","q3"],"proposed":["q1","q2","q3"]}
        row=evaluate_discovery(data)["results"]["baseline"][1]
        self.assertEqual(["q2"],row["executed_query_ids"])


if __name__ == "__main__": unittest.main()
