import json
import tempfile
import unittest
from pathlib import Path

from sudetect.discovery import import_candidates, priority_score


class DiscoveryTests(unittest.TestCase):
    def test_error_and_missing_provenance_override_complete(self):
        row={"channel_id":"search","state":"EXECUTED","complete":True,"error_code":"RATE_LIMITED"}
        result=import_candidates({"channels":[row],"candidates":[]},scope_id="acme")
        self.assertEqual("PARTIAL",result["status"])
        self.assertIn("RATE_LIMITED",result["errors"])
        self.assertFalse(result["channels"][0]["provenance_complete"])

    def test_successful_empty_result_requires_end_condition_and_work_id(self):
        row={"channel_id":"search","state":"EXECUTED","complete":True,"observed_at":"2026-01-01T00:00:00Z",
             "source_ref":"fixture:empty","work_id":"work-1","end_condition":"provider_empty","pages":1,"items":0}
        result=import_candidates({"required_channels":["search"],"channels":[row],"candidates":[]},scope_id="acme")
        self.assertEqual("COMPLETE",result["status"])

    def test_missing_required_channel_is_partial(self):
        result=import_candidates({"required_channels":["github","ct"],"channels":[{"channel_id":"github","state":"NOT_APPLICABLE"}],"candidates":[]},scope_id="acme")
        self.assertEqual("PARTIAL",result["status"]); self.assertEqual(["ct"],result["missing_required_channels"])

    def test_locator_store_preserves_exact_paths_with_stable_scoped_refs(self):
        from sudetect.locators import LocatorStore
        with tempfile.TemporaryDirectory() as td, LocatorStore(Path(td)/"locators.db") as store:
            base={"channels":[{"channel_id":"search","state":"NOT_APPLICABLE"}],"candidates":[
                {"url":"https://same.example/path-a?cap=one","channel_id":"search"},
                {"url":"https://same.example/path-b?cap=two","channel_id":"search"}]}
            one=import_candidates(base,scope_id="acme",locator_store=store)
            two=import_candidates(base,scope_id="acme",locator_store=store)
            refs=[c["locator_ref"] for c in one["candidates"]]
            self.assertEqual(refs,[c["locator_ref"] for c in two["candidates"]]); self.assertEqual(2,len(set(refs)))
            self.assertEqual({"https://same.example/path-a?cap=one","https://same.example/path-b?cap=two"},{store.get("acme",r) for r in refs})

    def test_without_store_candidate_handoff_is_blocked(self):
        result=import_candidates({"channels":[{"channel_id":"search","state":"NOT_APPLICABLE"}],"candidates":[{"url":"https://same.example/secret","channel_id":"search"}]},scope_id="acme")
        self.assertEqual("blocked",result["candidates"][0]["handoff_state"]); self.assertIn("HANDOFF_BLOCKED",result["errors"])
    def test_offline_provenance_and_pending_pivot(self):
        data={"channels":[{"channel_id":"search","state":"EXECUTED","complete":True,"pages":2,"items":1,"source_ref":"export:1"}],"candidates":[{"url":"https://candidate.example/path?token=x","channel_id":"search","source_ref":"result:7"}]}
        result=import_candidates(data,scope_id="acme")
        candidate=result["candidates"][0]
        self.assertEqual("ownership_pending",candidate["workflow"])
        self.assertFalse(candidate["pivot"]["network_request_authorized"])
        self.assertEqual("https://candidate.example",candidate["url"])
        self.assertEqual("result:7",candidate["source_ref"])

    def test_failed_channel_is_not_empty_success(self):
        result=import_candidates({"channels":[{"channel_id":"ct","state":"FAILED","items":0}],"candidates":[]},scope_id="acme")
        self.assertEqual("FAILED",result["status"])

    def test_priority_is_bounded_and_cost_sensitive(self):
        cheap=priority_score(1,1,1,1,0,0,0)
        costly=priority_score(1,1,1,1,1,1,1)
        self.assertEqual(1,cheap); self.assertLess(costly,cheap)

    def test_planned_or_incomplete_channel_is_partial(self):
        for channel in ({"channel_id":"search","state":"PLANNED"},{"channel_id":"search","state":"EXECUTED","complete":False}):
            with self.subTest(channel=channel):
                self.assertEqual("PARTIAL",import_candidates({"channels":[channel],"candidates":[]},scope_id="acme")["status"])

    def test_untrusted_provenance_fields_are_not_emitted(self):
        data={"channels":[{"channel_id":"search","state":"EXECUTED","complete":True,"source_ref":"https://evil/?token=x","observed_at":"bad","error_code":"x raw"}],"candidates":[{"url":"https://candidate.example/?token=x","channel_id":"search","source_ref":"https://evil/?token=x","kind":"<script>"}]}
        encoded=json.dumps(import_candidates(data,scope_id="acme"))
        self.assertNotIn("token=x",encoded); self.assertNotIn("<script>",encoded)
        self.assertIn("TIMESTAMP_INVALID",encoded); self.assertIn("SOURCE_REF_INVALID",encoded)

    def test_string_false_cannot_claim_channel_complete(self):
        r = import_candidates({'channels': [{'channel_id': 'ct', 'state': 'EXECUTED', 'complete': 'false'}], 'candidates': []}, scope_id='acme')
        self.assertEqual(r['status'], 'PARTIAL')

    def test_invalid_locator_is_not_accepted_as_candidate(self):
        r = import_candidates({'channels': [{'channel_id': 'ct', 'state': 'EXECUTED', 'complete': True}], 'candidates': [{'channel_id': 'ct', 'url': 'file:///private'}]}, scope_id='acme')
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertEqual(r['candidates'], [])


if __name__ == "__main__": unittest.main()
