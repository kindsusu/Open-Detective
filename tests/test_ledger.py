import sqlite3
import tempfile
import unittest
from pathlib import Path

from sudetect.ledger import Ledger, LedgerError


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/"ledger.db"; self.ledger=Ledger(self.path)
        self.ledger.register_asset("a1",provider="vercel",scope_id="team",target_id="target-origin",
                                   policy_id="policy-1",required_alias_ids=["alias-1","alias-2"],
                                   alias_bindings={"alias-1":"target-alias-1","alias-2":"target-alias-2"})
        self.finding=self.ledger.open_finding("a1",evidence_ref="e:open")
        self.ledger.record_remediation(self.finding,evidence_ref="e:change",remediated_at="2026-01-01T00:00:00Z")
    def tearDown(self): self.ledger.close(); self.tmp.cleanup()

    def add(self,alias,verdict="ACCESS_DENIED_OBSERVED",**kw):
        return self.ledger.add_observation("a1",alias_id=alias,verdict=verdict,evidence_ref=f"observation:{alias}",observed_at="2026-01-02T00:00:00Z",capture_complete=True,expected_policy=kw.get("expected_policy",True),policy_evidence_ref=f"policy:{alias}",control_healthy=kw.get("control_healthy",True),control_evidence_ref=f"control:{alias}")

    def test_partial_alias_cannot_close(self):
        self.add("alias-1")
        with self.assertRaisesRegex(LedgerError,"alias not rechecked"):
            self.ledger.close_finding(self.finding,evidence_ref="e:close")

    def test_unknown_rate_limit_waf_never_close(self):
        for bad in ("UNKNOWN","RATE_LIMITED","WAF"):
            with self.subTest(bad=bad):
                db=Ledger(":memory:"); db.register_asset("a",provider="x",scope_id="s",target_id="t",policy_id="p"); f=db.open_finding("a",evidence_ref="e:open"); db.record_remediation(f,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
                with self.assertRaisesRegex(LedgerError,"invalid access value"): db.add_observation("a",verdict=bad,evidence_ref="e:observation",observed_at="2026-01-02T00:00:00Z",capture_complete=True,expected_policy=True,policy_evidence_ref="e:policy",control_healthy=True,control_evidence_ref="e:control")
                db.close()

    def test_all_aliases_and_controls_can_close_then_reopen(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.assertEqual("CLOSED",self.ledger.list_findings()[0]["status"])
        self.ledger.add_observation("a1",alias_id="alias-2",access="BODY_SERVED",content="SENSITIVE_CONTENT_CONFIRMED",evidence_ref="e:regression")
        self.assertEqual("REOPENED",self.ledger.list_findings()[0]["status"])

    def test_body_served_reopens_for_review(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.ledger.add_observation("a1",access="BODY_SERVED",content="PUBLIC_UI",evidence_ref="e:public")
        self.assertEqual("REOPENED",self.ledger.list_findings()[0]["status"])

    def test_arbitrary_verdict_cannot_be_marked_healthy_for_close(self):
        with self.assertRaisesRegex(LedgerError,"invalid access value"):
            self.ledger.add_observation("a1",access="EXPOSED",content="NOT_INSPECTED",evidence_ref="obs:bad")

    def test_observation_hash_is_payload_not_event_identity(self):
        one=self.ledger.add_observation("a1",alias_id="alias-1",verdict="INDETERMINATE",evidence_ref="e:e1",observed_at="2026-01-02T00:00:00Z")
        two=self.ledger.add_observation("a1",alias_id="alias-1",verdict="INDETERMINATE",evidence_ref="e:e2",observed_at="2026-01-02T00:00:01Z")
        self.assertNotEqual(one,two)
        hashes=[r[0] for r in self.ledger.db.execute("SELECT payload_hash FROM observations")]
        self.assertEqual(len(hashes),len(set(hashes)))

    def test_due_claim_retry_and_duplicate_completion(self):
        job=self.ledger.enqueue_due(self.finding,"2026-01-01T00:00:00Z",event_id="enqueue-1")
        self.assertEqual(job,self.ledger.enqueue_due(self.finding,"2026-01-01T00:00:00Z",job_id=job,event_id="enqueue-1"))
        claim=self.ledger.claim_due(now="2026-01-02T00:00:00Z")
        self.assertTrue(self.ledger.retry_due(job,claim_token=claim["claim_token"],due_at="2026-01-03T00:00:00Z",error_code="RATE_LIMITED"))
        self.assertFalse(self.ledger.retry_due(job,claim_token=claim["claim_token"],due_at="2026-01-03T00:00:00Z",error_code="RATE_LIMITED"))
        claim2=self.ledger.claim_due(now="2026-01-04T00:00:00Z")
        self.assertTrue(self.ledger.complete_due(job,claim_token=claim2["claim_token"],result_ref="obs:1"))
        self.assertFalse(self.ledger.complete_due(job,claim_token=claim2["claim_token"],result_ref="obs:1"))

    def test_expired_claim_is_fenced_after_reclaim(self):
        job=self.ledger.enqueue_due(self.finding,"2026-01-01T00:00:00Z")
        first=self.ledger.claim_due(now="2026-01-02T00:00:00Z",worker_id="one",lease_seconds=1)
        other=Ledger(self.path)
        second=other.claim_due(now="2026-01-02T00:00:02Z",worker_id="two",lease_seconds=30)
        with self.assertRaises(LedgerError): self.ledger.complete_due(job,claim_token=first["claim_token"],result_ref="obs:old")
        with self.assertRaises(LedgerError): self.ledger.retry_due(job,claim_token=first["claim_token"],due_at="2026-01-03T00:00:00Z",error_code="STALE_CLAIM")
        self.assertTrue(other.complete_due(job,claim_token=second["claim_token"],result_ref="obs:new"))
        other.close()

    def test_events_are_append_only(self):
        with self.assertRaises(sqlite3.DatabaseError): self.ledger.db.execute("DELETE FROM events")

    def test_asset_alias_set_only_grows(self):
        self.ledger.register_asset("a1",provider="vercel",scope_id="team",required_alias_ids=["alias-3"])
        aliases=self.ledger.db.execute("SELECT required_aliases_json FROM assets WHERE asset_id='a1'").fetchone()[0]
        self.assertIn("alias-1",aliases); self.assertIn("alias-2",aliases); self.assertIn("alias-3",aliases)

    def test_new_alias_reopens_closed_finding(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.ledger.register_asset("a1",provider="vercel",scope_id="team",required_alias_ids=["alias-new"])
        self.assertEqual("REOPENED",self.ledger.list_findings()[0]["status"])

    def test_probe_contract_imports_without_reason_text(self):
        payload={"observation_id":"probe-1","observed_at":"2026-01-02T00:00:00Z","target_id":"target-origin","policy_id":"policy-1","access":"INDETERMINATE","content":"NOT_INSPECTED","capture_complete":False,"reason":"URL with secret?token=x"}
        self.ledger.import_observation(payload,asset_id="a1")
        row=self.ledger.db.execute("SELECT reason_code,evidence_ref FROM observations WHERE observation_id='probe-1'").fetchone()
        self.assertEqual("PROBE_INCOMPLETE",row["reason_code"]); self.assertNotIn("token",row["evidence_ref"])

    def test_probe_normal_denials_can_close_but_challenge_cannot(self):
        probes=[]
        for index, alias in enumerate((None,"alias-1","alias-2")):
            target = "target-origin" if alias is None else f"target-{alias}"
            probes.append({"observation_id":f"probe-ok-{index}","observed_at":"2026-01-02T00:00:00Z","target_id":target,"policy_id":"policy-1","access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","capture_complete":True,"reason":"access_denied_status"})
            self.ledger.import_observation(probes[-1],asset_id="a1",alias_id=alias,expected_policy=True,policy_evidence_ref=f"policy:{index}",control_healthy=True,control_evidence_ref=f"control:{index}")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.assertEqual("CLOSED",self.ledger.list_findings()[0]["status"])

        other=Ledger(":memory:"); other.register_asset("a",provider="x",scope_id="s",target_id="t",policy_id="p"); finding=other.open_finding("a",evidence_ref="e:open"); other.record_remediation(finding,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
        payload={"observation_id":"probe-challenge","observed_at":"2026-01-02T00:00:00Z","target_id":"t","policy_id":"p","access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","capture_complete":True,"reason":"access_denied_status","signals":[{"code":"CHALLENGE_PAGE_INDICATOR"}]}
        other.import_observation(payload,asset_id="a",expected_policy=True,policy_evidence_ref="e:policy",control_healthy=True,control_evidence_ref="e:control")
        with self.assertRaises(LedgerError): other.close_finding(finding,evidence_ref="e:close")
        other.close()

    def test_string_false_never_becomes_true(self):
        payload={"observation_id":"probe-bool","observed_at":"2026-01-02T00:00:00Z","target_id":"target-origin","policy_id":"policy-1","access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","capture_complete":"false","reason":"access_denied_status","expected_policy":"false","control_healthy":"false"}
        self.ledger.import_observation(payload,asset_id="a1")
        row=self.ledger.db.execute("SELECT capture_complete,expected_policy,control_healthy FROM observations WHERE observation_id='probe-bool'").fetchone()
        self.assertEqual((0,0,0),tuple(row))

    def test_observation_collision_includes_asset_and_time(self):
        self.ledger.add_observation("a1",observation_id="same",access="BODY_SERVED",evidence_ref="e:obs",observed_at="2026-01-02T00:00:00Z")
        with self.assertRaisesRegex(LedgerError,"collision"):
            self.ledger.add_observation("a1",observation_id="same",access="BODY_SERVED",evidence_ref="e:obs",observed_at="2026-01-03T00:00:00Z")

    def test_unknown_content_and_incomplete_analysis_cannot_close(self):
        db=Ledger(":memory:"); db.register_asset("a",provider="x",scope_id="s",target_id="t",policy_id="p"); finding=db.open_finding("a",evidence_ref="e:open"); db.record_remediation(finding,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
        with self.assertRaisesRegex(LedgerError,"invalid content value"): db.add_observation("a",access="ACCESS_DENIED_OBSERVED",content="UNKNOWN",evidence_ref="e:observation")
        payload={"observation_id":"analysis-bad","observed_at":"2026-01-03T00:00:00Z","target_id":"t","policy_id":"p","access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","capture_complete":True,"analysis_complete":False,"reason":"access_denied_status"}
        db.import_observation(payload,asset_id="a",expected_policy=True,policy_evidence_ref="e:policy2",control_healthy=True,control_evidence_ref="e:control2")
        row=db.db.execute("SELECT reason_code FROM observations WHERE observation_id='analysis-bad'").fetchone()
        self.assertEqual("PROBE_INCOMPLETE",row["reason_code"]); db.close()

    def test_equal_time_conflicts_fail_closed_in_both_orders(self):
        for sensitive_first in (False, True):
            db=Ledger(":memory:")
            db.register_asset("a",provider="x",scope_id="s",target_id="t",policy_id="p")
            finding=db.open_finding("a",evidence_ref="e:open")
            db.record_remediation(finding,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
            rows = [
                dict(access="ACCESS_DENIED_OBSERVED",content="NOT_INSPECTED",evidence_ref="e:healthy",capture_complete=True,expected_policy=True,policy_evidence_ref="e:policy",control_healthy=True,control_evidence_ref="e:control"),
                dict(access="BODY_SERVED",content="SENSITIVE_CONTENT_CONFIRMED",evidence_ref="e:sensitive"),
            ]
            if sensitive_first: rows.reverse()
            for row in rows: db.add_observation("a",observed_at="2026-01-02T00:00:00Z",**row)
            with self.assertRaisesRegex(LedgerError,"conflicting latest observations"):
                db.close_finding(finding,evidence_ref="e:close")
            db.close()

    def test_import_binding_mismatch_is_atomic(self):
        base={"observation_id":"wrong","observed_at":"2026-01-02T00:00:00Z","target_id":"wrong-target",
              "policy_id":"policy-1","access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","capture_complete":True}
        before=self.ledger.db.execute("SELECT count(*) FROM events").fetchone()[0]
        with self.assertRaisesRegex(LedgerError,"target binding mismatch"):
            self.ledger.import_observation(base,asset_id="a1")
        self.assertEqual(before,self.ledger.db.execute("SELECT count(*) FROM events").fetchone()[0])
        base.update(observation_id="wrong-policy",target_id="target-origin",policy_id="wrong-policy")
        with self.assertRaisesRegex(LedgerError,"policy binding mismatch"):
            self.ledger.import_observation(base,asset_id="a1")
        self.assertEqual(0,self.ledger.db.execute("SELECT count(*) FROM observations WHERE observation_id IN ('wrong','wrong-policy')").fetchone()[0])

    def test_unknown_asset_observations_are_rejected_without_event(self):
        before=self.ledger.db.execute("SELECT count(*) FROM events").fetchone()[0]
        with self.assertRaisesRegex(LedgerError,"asset missing"):
            self.ledger.add_observation("missing",access="INDETERMINATE",evidence_ref="e:missing")
        payload={"observation_id":"missing","observed_at":"2026-01-02T00:00:00Z","target_id":"t","policy_id":"p",
                 "access":"INDETERMINATE","content":"NOT_INSPECTED","capture_complete":False}
        with self.assertRaisesRegex(LedgerError,"asset missing"):
            self.ledger.import_observation(payload,asset_id="missing")
        self.assertEqual(before,self.ledger.db.execute("SELECT count(*) FROM events").fetchone()[0])

    def test_legacy_unbound_asset_and_absent_observation_cannot_close(self):
        db=Ledger(":memory:")
        db.register_asset("legacy",provider="x",scope_id="scope")
        finding=db.open_finding("legacy",evidence_ref="e:open")
        db.record_remediation(finding,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
        with self.assertRaisesRegex(LedgerError,"invalid access value"):
            db.add_observation("legacy",access="ABSENT",evidence_ref="e:legacy")
        with self.assertRaisesRegex(LedgerError,"asset target and policy binding required"):
            db.close_finding(finding,evidence_ref="e:close")
        db.close()

    def test_closed_finding_ignores_observation_older_than_closure_baseline_and_normal_denial(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.ledger.add_observation("a1",access="BODY_SERVED",content="SENSITIVE_CONTENT_CONFIRMED",
                                    evidence_ref="e:late",observed_at="2026-01-01T12:00:00Z")
        self.assertEqual("CLOSED",self.ledger.list_findings()[0]["status"])
        self.ledger.add_observation("a1",access="ACCESS_DENIED_OBSERVED",content="NOT_INSPECTED",
                                    evidence_ref="e:normal",expected_policy=True,policy_evidence_ref="e:policy-new",
                                    control_healthy=True,control_evidence_ref="e:control-new")
        self.assertEqual("CLOSED",self.ledger.list_findings()[0]["status"])

    def test_same_time_post_close_conflict_reopens(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.ledger.add_observation("a1",access="BODY_SERVED",content="SENSITIVE_CONTENT_CONFIRMED",
                                    evidence_ref="e:same-time",observed_at="2026-01-02T00:00:00Z")
        self.assertEqual("REOPENED",self.ledger.list_findings()[0]["status"])

    def test_binding_change_reopens_closed_finding(self):
        self.add(None); self.add("alias-1"); self.add("alias-2")
        self.ledger.close_finding(self.finding,evidence_ref="e:close")
        self.ledger.register_asset("a1",provider="vercel",scope_id="team",target_id="target-origin-new")
        self.assertEqual("REOPENED",self.ledger.list_findings()[0]["status"])
        with self.assertRaisesRegex(LedgerError,"alias not rechecked"):
            self.ledger.close_finding(self.finding,evidence_ref="e:stale-close")

    def test_existing_database_migration_quarantines_orphan_and_rechecks_legacy_close(self):
        old_path=Path(self.tmp.name)/"old.sqlite"
        raw=sqlite3.connect(old_path)
        raw.executescript("""
        CREATE TABLE assets(asset_id TEXT PRIMARY KEY,provider TEXT,scope_id TEXT,required_aliases_json TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE observations(observation_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL,alias_id TEXT,observed_at TEXT NOT NULL,access TEXT NOT NULL,content TEXT NOT NULL,capture_complete INTEGER NOT NULL,expected_policy INTEGER NOT NULL,control_healthy INTEGER NOT NULL,evidence_ref TEXT NOT NULL,policy_evidence_ref TEXT,control_evidence_ref TEXT,reason_code TEXT,payload_hash TEXT NOT NULL);
        CREATE TABLE findings(finding_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL,status TEXT NOT NULL,opened_at TEXT NOT NULL,remediation_at TEXT,closed_at TEXT,evidence_ref TEXT,updated_at TEXT NOT NULL);
        INSERT INTO assets VALUES('legacy','x','s','{"aliases":[]}','2026-01-01T00:00:00Z');
        INSERT INTO observations VALUES('legacy-obs','legacy',NULL,'2026-01-02T00:00:00Z','ABSENT','NOT_INSPECTED',1,1,1,'e:obs','e:policy','e:control',NULL,'h1');
        INSERT INTO observations VALUES('orphan-obs','missing',NULL,'2026-01-02T00:00:00Z','INDETERMINATE','NOT_INSPECTED',0,0,0,'e:orphan',NULL,NULL,NULL,'h2');
        INSERT INTO findings VALUES('legacy-finding','legacy','CLOSED','2026-01-01T00:00:00Z','2026-01-01T12:00:00Z','2026-01-03T00:00:00Z','e:close','2026-01-03T00:00:00Z');
        """)
        raw.commit(); raw.close()
        migrated=Ledger(old_path)
        self.assertEqual("RECHECK_PENDING",migrated.list_findings()[0]["status"])
        row=migrated.db.execute("SELECT access,reason_code FROM observations WHERE observation_id='legacy-obs'").fetchone()
        self.assertEqual(("INDETERMINATE","LEGACY_ACCESS_VALUE"),tuple(row))
        self.assertEqual("UNKNOWN_ASSET",migrated.db.execute("SELECT quarantine_reason FROM observations_quarantine WHERE observation_id='orphan-obs'").fetchone()[0])
        self.assertTrue(migrated.db.execute("PRAGMA foreign_key_list(observations)").fetchall())
        self.assertTrue(migrated.db.execute("SELECT 1 FROM events WHERE event_type='FINDING_REOPENED' AND entity_id='legacy-finding'").fetchone())
        migrated.close()

    def browser_payload(self, **changes):
        payload={"mode":"brokered_anonymous_browser","observation_id":"browser-1",
                 "observed_at":"2026-01-02T00:00:00Z","target_id":"target-origin","policy_id":"policy-1",
                 "access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED","complete":True,
                 "capture_complete":True,"analysis_complete":True,"content_review_complete":False,
                 "reason":"bounded_observation_completed","blocked":[],
                 "observations":[{"is_main_document":True,"target_id":"target-origin",
                                  "policy_id":"policy-1",
                                  "access":"ACCESS_DENIED_OBSERVED","content":"NOT_INSPECTED",
                                  "capture_complete":True,"analysis_complete":True,"http_status":403}]}
        payload.update(changes)
        return payload

    def test_complete_browser_aggregate_can_supply_closure_observation(self):
        db=Ledger(":memory:"); db.register_asset("a",provider="x",scope_id="s",target_id="target-origin",policy_id="policy-1")
        finding=db.open_finding("a",evidence_ref="e:open")
        db.record_remediation(finding,evidence_ref="e:remediation",remediated_at="2026-01-01T00:00:00Z")
        db.import_observation(self.browser_payload(),asset_id="a",expected_policy=True,policy_evidence_ref="e:policy",
                              control_healthy=True,control_evidence_ref="e:control")
        db.close_finding(finding,evidence_ref="e:close")
        self.assertEqual("CLOSED",db.list_findings()[0]["status"]); db.close()

    def test_incomplete_or_blocked_browser_aggregate_never_closes(self):
        for change in ({"analysis_complete":False}, {"blocked":[{"reason":"scope_rejected"}]},
                       {"reason":"sensitive_candidate_stop"}):
            payload=self.browser_payload(**change)
            payload["observation_id"]="browser-"+str(len(str(change)))
            self.ledger.import_observation(payload,asset_id="a1")
            row=self.ledger.db.execute("SELECT capture_complete,reason_code FROM observations WHERE observation_id=?",(payload["observation_id"],)).fetchone()
            self.assertEqual((0,"PROBE_INCOMPLETE"),tuple(row))

    def test_browser_child_sensitive_content_is_not_ignored(self):
        payload=self.browser_payload(observation_id="browser-sensitive")
        payload["observations"].append({"target_id":"child","policy_id":"policy-1","content":"SENSITIVE_CANDIDATE","capture_complete":True,"analysis_complete":True})
        self.ledger.import_observation(payload,asset_id="a1")
        row=self.ledger.db.execute("SELECT content FROM observations WHERE observation_id='browser-sensitive'").fetchone()
        self.assertEqual("SENSITIVE_CANDIDATE",row[0])

    def test_browser_main_target_mismatch_is_rejected(self):
        payload=self.browser_payload(observation_id="browser-mismatch")
        payload["target_id"]="other-target"
        payload["observations"][0]["target_id"]="other-target"
        with self.assertRaisesRegex(LedgerError,"target binding mismatch"):
            self.ledger.import_observation(payload,asset_id="a1")
        self.assertFalse(self.ledger.db.execute("SELECT 1 FROM observations WHERE observation_id='browser-mismatch'").fetchone())


if __name__ == "__main__": unittest.main()
