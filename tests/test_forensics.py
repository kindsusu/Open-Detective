import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sudetect.forensics import (ForensicError, acquire_local_export, append_custody_event,
    build_timeline, load_case, load_strict_json, verify_custody_chain, verify_manifest, verify_timeline)

NOW = datetime(2026, 9, 8, tzinfo=timezone.utc)


def opaque(value): return f"opaque:{value:032x}"
def case():
    return {"schema_version":"1.0","case_id":"case_"+"1"*32,"purpose_ref":opaque(2),
        "retention_until":"2027-01-01T00:00:00Z","authorization":{"authorization_ref":opaque(3),
        "valid_from":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","revoked":False},
        "collectors":[{"collector_id":"col_"+"4"*32,"tool":"fixture-export","version":"1","read_only":True}],
        "allowed_sources":[{"source_id":"src_"+"5"*32,"source_type":"normalized_event_jsonl",
        "collector_id":"col_"+"4"*32,"source_provenance_ref":opaque(6),"authorization_ref":opaque(3)}]}


def record():
    return {"event_id":"evt_"+"7"*32,"event_time":"2026-09-08T01:00:00+01:00",
        "ingest_time":"2026-09-08T00:01:00Z","clock_uncertainty_ms":1000,
        "actor_ref":opaque(8),"asset_ref":opaque(9),"activity":"object_read"}


class ForensicTests(unittest.TestCase):
    def test_case_requires_active_unrevoked_authority_and_opaque_ids(self):
        self.assertEqual(case()["case_id"],load_case(case(),now=NOW)["case_id"])
        for mutate, code in ((lambda c:c["authorization"].update(revoked=True),"AUTHORIZATION_REVOKED"),
                             (lambda c:c.update(retention_until="2025-01-01T00:00:00Z"),"RETENTION_EXPIRED"),
                             (lambda c:c.update(case_id="customer-name"),"CASE_INVALID")):
            value=case(); mutate(value)
            with self.assertRaisesRegex(ForensicError,code): load_case(value,now=NOW)
        with self.assertRaisesRegex(ForensicError,"TIME_INVALID"): load_case(case(),now=datetime(2026,9,8))

    def test_strict_json_rejects_duplicate_nonfinite_and_depth(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"value.json"
            for text,code in ((r'{"a":1,"a":2}',"JSON_DUPLICATE_KEY"),(r'{"a":NaN}',"JSON_NONFINITE"),
                              ('{"a":'*40+'0'+'}'*40,"JSON_TOO_DEEP")):
                path.write_text(text,encoding="utf-8")
                with self.assertRaisesRegex(ForensicError,code): load_strict_json(path)

    def test_stable_read_rejects_path_identity_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"value.json"; path.write_text('{"a":1}',encoding="utf-8")
            before=path.stat(); changed=list(before); changed[1]=before.st_ino+1; replacement=os.stat_result(changed)
            with patch("sudetect.forensics._safe_existing_file",side_effect=[before,replacement]):
                with self.assertRaisesRegex(ForensicError,"JSON_INVALID"): load_strict_json(path)

    def test_atomic_acquire_verifies_hash_size_and_never_changes_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); evidence=root/"evidence"; evidence.mkdir(); source=root/"export.jsonl"
            original=(json.dumps(record(),sort_keys=True,separators=(",",":"))+"\n").encode(); source.write_bytes(original)
            result=acquire_local_export(case(),case()["allowed_sources"][0]["source_id"],source,evidence,now=NOW)
            self.assertEqual(original,source.read_bytes()); self.assertEqual("ACQUIRED",result["status"])
            manifest=evidence/result["manifest_ref"]
            self.assertEqual("VERIFIED",verify_manifest(manifest,evidence_dir=evidence)["status"])
            artifact=evidence/result["evidence_id"]/"artifact.bin"; artifact.write_bytes(original+b"x")
            with self.assertRaisesRegex(ForensicError,"ARTIFACT_SIZE_MISMATCH"): verify_manifest(manifest,evidence_dir=evidence)
            artifact.write_bytes(b"x"*len(original))
            with self.assertRaisesRegex(ForensicError,"ARTIFACT_HASH_MISMATCH"): verify_manifest(manifest,evidence_dir=evidence)
            artifact.unlink()
            with self.assertRaisesRegex(ForensicError,"ARTIFACT_MISSING"): verify_manifest(manifest,evidence_dir=evidence)
            self.assertEqual(original,source.read_bytes())
            second=acquire_local_export(case(),case()["allowed_sources"][0]["source_id"],source,evidence,now=NOW)
            self.assertNotEqual(result["evidence_id"],second["evidence_id"])

    def test_limits_symlinks_and_partial_failure_leave_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"source"; source.write_bytes(b"1234"); evidence=root/"evidence"; evidence.mkdir()
            with self.assertRaisesRegex(ForensicError,"FILE_LIMIT_EXCEEDED"):
                acquire_local_export(case(),case()["allowed_sources"][0]["source_id"],source,evidence,now=NOW,max_bytes=3)
            self.assertEqual(b"1234",source.read_bytes()); self.assertEqual([],list(evidence.iterdir()))
            link=root/"link"
            try: link.symlink_to(source)
            except OSError: self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ForensicError,"SOURCE_UNSAFE"):
                acquire_local_export(case(),case()["allowed_sources"][0]["source_id"],link,evidence,now=NOW)

    def test_custody_chain_detects_tamper_sequence_duplicate_and_anchor_truncation(self):
        with tempfile.TemporaryDirectory() as td:
            chain=Path(td)/"custody.jsonl"
            event={"event_id":"evt_"+"a"*32,"event_type":"collected","actor_ref":opaque(10),
                   "evidence_id":"evd_"+"b"*32,"occurred_at":"2026-09-08T00:00:00Z","action_ref":opaque(11)}
            first=append_custody_event(case(),chain,event,now=NOW)
            self.assertEqual(first["head_hash"],verify_custody_chain(chain,expected_head=first["head_hash"])["head_hash"])
            other={**event,"event_id":"evt_"+"c"*32}
            with self.assertRaisesRegex(ForensicError,"CUSTODY_HEAD_MISMATCH"):
                append_custody_event(case(),chain,other,now=NOW,expected_head="0"*64)
            self.assertEqual(1,verify_custody_chain(chain)["events"])
            lock=chain.with_name(chain.name+".lock"); lock.write_text("held")
            with self.assertRaisesRegex(ForensicError,"CUSTODY_LOCKED"):
                append_custody_event(case(),chain,other,now=NOW)
            lock.unlink(); self.assertEqual(1,verify_custody_chain(chain)["events"])
            with self.assertRaisesRegex(ForensicError,"CUSTODY_DUPLICATE_EVENT"):
                append_custody_event(case(),chain,event,now=NOW)
            raw=chain.read_text(); chain.write_text(raw.replace("collected","altered"),encoding="utf-8")
            with self.assertRaisesRegex(ForensicError,"CUSTODY_HASH_INVALID"): verify_custody_chain(chain)
            row=json.loads(raw); row["sequence"]=2; body=dict(row); body.pop("event_hash"); row["event_hash"]=hashlib.sha256(json.dumps(body,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            chain.write_text(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
            with self.assertRaisesRegex(ForensicError,"CUSTODY_SEQUENCE_INVALID"): verify_custody_chain(chain)
            chain.write_text("",encoding="utf-8")
            with self.assertRaisesRegex(ForensicError,"CUSTODY_HEAD_MISMATCH"):
                verify_custody_chain(chain,expected_head=first["head_hash"])

    def test_concurrent_custody_writers_allow_one_append_without_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            chain=Path(td)/"custody.jsonl"
            base={"event_id":"evt_"+"a"*32,"event_type":"collected","actor_ref":opaque(10),
                  "evidence_id":"evd_"+"b"*32,"occurred_at":"2026-09-08T00:00:00Z","action_ref":opaque(11)}
            first=append_custody_event(case(),chain,base,now=NOW)
            barrier=threading.Barrier(3); outcomes=[]
            def writer(suffix):
                event={**base,"event_id":"evt_"+suffix*32}; barrier.wait()
                try: outcomes.append(("ok",append_custody_event(case(),chain,event,now=NOW,expected_head=first["head_hash"])))
                except ForensicError as exc: outcomes.append(("error",exc.code))
            threads=[threading.Thread(target=writer,args=(suffix,)) for suffix in ("c","d")]
            for thread in threads: thread.start()
            barrier.wait()
            for thread in threads: thread.join(5); self.assertFalse(thread.is_alive())
            self.assertEqual(1,sum(kind=="ok" for kind,_ in outcomes))
            self.assertEqual(1,sum(kind=="error" and value in {"CUSTODY_LOCKED","CUSTODY_HEAD_MISMATCH"} for kind,value in outcomes))
            self.assertEqual(2,verify_custody_chain(chain)["events"])

    def test_timeline_binds_every_claimed_field_to_verified_source_record(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); evidence=root/"evidence"; evidence.mkdir(); source=root/"source.jsonl"
            source_record=record(); source_record["ingest_time"]="2026-09-08T00:00:00Z"; source.write_text(json.dumps(source_record)+"\n",encoding="utf-8")
            acquired=acquire_local_export(case(),case()["allowed_sources"][0]["source_id"],source,evidence,now=NOW)
            ref="sha256:"+hashlib.sha256(json.dumps(source_record,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            normalized={**source_record,"source_id":case()["allowed_sources"][0]["source_id"],
                        "evidence_id":acquired["evidence_id"],"source_record_ref":ref,
                        "event_time":"2026-09-08T00:00:00Z"}
            event_input=root/"events.jsonl"; event_input.write_text(json.dumps(normalized)+"\n",encoding="utf-8")
            timeline=root/"timeline.json"
            made=build_timeline(case(),event_input,evidence,timeline,now=NOW)
            self.assertEqual(1,made["events"]); self.assertEqual("VERIFIED",verify_timeline(timeline,evidence)["status"])
            rewritten=json.loads(timeline.read_text()); rewritten["events"][0]["activity"]="forged"
            rewritten["events_sha256"]=hashlib.sha256(json.dumps(rewritten["events"],ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            timeline.write_text(json.dumps(rewritten),encoding="utf-8")
            with self.assertRaisesRegex(ForensicError,"SOURCE_RECORD_MISMATCH"):
                verify_timeline(timeline,evidence)
            forged=copy.deepcopy(normalized); forged["actor_ref"]=opaque(99)
            event_input.write_text(json.dumps(forged)+"\n",encoding="utf-8")
            with self.assertRaisesRegex(ForensicError,"SOURCE_RECORD_MISMATCH"):
                build_timeline(case(),event_input,evidence,root/"forged.json",now=NOW)
            self.assertFalse((root/"forged.json").exists())


if __name__ == "__main__": unittest.main()
