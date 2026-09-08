# Authorized local forensic evidence

Forensics is separate from anonymous measurement and from the operational SQLite ledger. It works only on an approved local case file and owner-authorized, read-only local exports. A measurement `--scope` authorizes bounded anonymous HTTP observation; it does not authorize case creation, export acquisition, evidence retention, or forensic analysis.

Keep case files, source exports, acquired artifacts, manifests, custody chains, and timelines in an owner-controlled local directory. Do not commit them. A case declares its purpose and retention reference, time-bounded authorization references, approved read-only collectors, and exact allowed sources. Do not use this workflow to log in, reuse credentials, bypass controls, enumerate adjacent records, or acquire RAM/disk images. This implementation accepts only owner-provided `normalized_event_jsonl` exports; disk/RAM images and vendor-format imports are out of scope.

```bash
python -m sudetect forensics acquire --case _local/case.json --source-id audit-export --export _local/export.jsonl --evidence-dir _local/evidence
python -m sudetect forensics verify --manifest _local/evidence/<evidence-id>/manifest.json --evidence-dir _local/evidence
python -m sudetect forensics custody-add --case _local/case.json --chain _local/evidence/custody.jsonl --event _local/event.json --evidence-dir _local/evidence
python -m sudetect forensics custody-verify --chain _local/evidence/custody.jsonl --expected-head "<approved saved head hash>"
python -m sudetect forensics timeline --case _local/case.json --events _local/events.jsonl --evidence-dir _local/evidence --output _local/timeline.json
python -m sudetect forensics timeline-verify --timeline _local/timeline.json --evidence-dir _local/evidence
```

The commands emit safe JSON summaries and should not copy source content to stdout. Hashes detect later changes to an acquired byte stream; they do not establish an artifact's authenticity, ownership, legal admissibility, or a complete chain of custody. Supply `--evidence-dir` to custody-add to verify the referenced manifest/artifact and case; without it, the custody reference is self-reported. A custody-chain check without an externally retained `--expected-head` can verify its internal links but cannot detect every tail truncation or full rehash. Record source-provided provenance, collector identity, authorization reference, event time, ingest time, clock uncertainty, retention gaps, and collection side effects separately. Preserve originals and share only a controlled redacted derivative when required. Timeline input is only an acquired allowed source whose type is `normalized_event_jsonl`; each row must retain the matching source, evidence, event time, and canonical raw-line hash reference.

`verify`, `timeline-verify`, and custody verification check historical artifact integrity only. They do not renew current collection authority or retention approval. Do not remove a stale custody lock automatically: have the case owner review and release it. Local hashes and linked records do not claim protection against a person who can rewrite the entire local case directory.

An absent, expired, inaccessible, or unknown log is a coverage gap. It is not evidence that an event, actor, or exfiltration did not occur. A public-access observation and proof of exfiltration are separate claims. Timeline joins must retain their evidence references and uncertainty; do not invent a continuous sequence or actor attribution.

Live SaaS, mail, EDR, cloud-IAM, storage, application-access, deployment, DLP, and endpoint collectors; vendor parsers; and backend authorization-policy tests are not implemented here. Obtain approved exports through the owner-controlled collection process, then use this local normalized-input workflow.

This workflow follows the collection, examination, analysis, and reporting structure described in [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final), and should be coordinated with the preparation, detection, response, and recovery practices in [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). These references do not grant authority or guarantee legal admissibility.
