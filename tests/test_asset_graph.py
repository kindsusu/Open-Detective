import unittest
from sudetect.asset_graph import build_asset_graph

def row(kind="public_discovery", record="r1", locator="opaque:"+"1"*32, evidence=None, coverage="complete"):
    return {"scope_id":"team","source_kind":kind,"source_id":"source-1","source_record_id":record,
            "retrieved_at":"2026-01-01T00:00:00Z","locator_ref":locator,"asset_id":"asset-1","alias_id":None,
            "relationship":"public_search_result" if kind=="public_discovery" else "deployment",
            "ownership_evidence":evidence,"coverage_state":coverage}

class AssetGraphTests(unittest.TestCase):
    def test_discovery_alone_never_promotes_owner(self):
        out=build_asset_graph([row()])
        self.assertEqual("ownership_pending",out["nodes"][0]["ownership_state"])
        self.assertEqual("candidate_signal",out["links"][0]["ownership_state"])
        self.assertTrue(any(x.get("coverage_state")=="ownership_evidence_missing" for x in out["coverage_gaps"]))

    def test_owner_inventory_evidence_links_same_locator(self):
        owner=row("owner_inventory","r2",evidence="ticket-1"); owner["source_id"]="owner-export"
        out=build_asset_graph([row(),owner])
        self.assertEqual("evidence_linked",out["nodes"][0]["ownership_state"])
        self.assertEqual("candidate_signal",out["links"][0]["ownership_state"])

    def test_dedup_conflict_and_version_diff(self):
        first=build_asset_graph([row()]); changed=row(); changed["asset_id"]="asset-2"
        second=build_asset_graph([row(),changed],previous=first)
        self.assertEqual(1,len(second["conflicts"])); self.assertEqual([],second["diff"]["added_scope_locator_refs"])
        self.assertEqual("disputed",second["nodes"][0]["ownership_state"])
        self.assertEqual(first["snapshot_id"],second["previous_snapshot_id"])

    def test_partial_source_is_explicit_gap_and_bad_exact_url_rejected(self):
        out=build_asset_graph([row(coverage="partial")])
        self.assertTrue(any(x.get("coverage_state")=="partial" for x in out["coverage_gaps"]))
        bad=row(); bad["locator_ref"]="https://company.example/private"
        with self.assertRaises(ValueError): build_asset_graph([bad])

if __name__=="__main__": unittest.main()
