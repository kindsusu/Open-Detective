"""Safe CLI adapter for approved local forensic artifacts."""
from __future__ import annotations

import argparse
import json


def main(argv=None):
    parser=argparse.ArgumentParser(description="Operate on approved local forensic exports")
    commands=parser.add_subparsers(dest="command",required=True)
    acquire=commands.add_parser("acquire"); acquire.add_argument("--case",required=True); acquire.add_argument("--source-id",required=True); acquire.add_argument("--export",required=True); acquire.add_argument("--evidence-dir",required=True); acquire.add_argument("--max-bytes",type=int,default=67108864)
    verify=commands.add_parser("verify"); verify.add_argument("--manifest",required=True); verify.add_argument("--evidence-dir")
    custody_add=commands.add_parser("custody-add"); custody_add.add_argument("--case",required=True); custody_add.add_argument("--chain",required=True); custody_add.add_argument("--event",required=True); custody_add.add_argument("--expected-head"); custody_add.add_argument("--evidence-dir")
    custody_verify=commands.add_parser("custody-verify"); custody_verify.add_argument("--chain",required=True); custody_verify.add_argument("--expected-head")
    timeline=commands.add_parser("timeline"); timeline.add_argument("--case",required=True); timeline.add_argument("--events",required=True); timeline.add_argument("--evidence-dir",required=True); timeline.add_argument("--output",required=True); timeline.add_argument("--max-events",type=int,default=100000)
    timeline_verify=commands.add_parser("timeline-verify"); timeline_verify.add_argument("--timeline",required=True); timeline_verify.add_argument("--evidence-dir",required=True)
    args=parser.parse_args(argv)
    try:
        from . import forensics
        if args.command=="acquire":
            result=forensics.acquire_local_export(forensics.load_case(args.case),args.source_id,args.export,args.evidence_dir,max_bytes=args.max_bytes)
        elif args.command=="verify": result=forensics.verify_manifest(args.manifest,evidence_dir=args.evidence_dir)
        elif args.command=="custody-add": result=forensics.append_custody_event(forensics.load_case(args.case),args.chain,forensics.load_strict_json(args.event),expected_head=args.expected_head,evidence_dir=args.evidence_dir)
        elif args.command=="custody-verify": result=forensics.verify_custody_chain(args.chain,expected_head=args.expected_head)
        elif args.command=="timeline": result=forensics.build_timeline(forensics.load_case(args.case),args.events,args.evidence_dir,args.output,max_events=args.max_events)
        else: result=forensics.verify_timeline(args.timeline,args.evidence_dir)
        print(json.dumps(result,ensure_ascii=False,sort_keys=True)); return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        code=getattr(exc,"code","FORENSICS_FAILED")
        print(json.dumps({"status":"FAILED","error":code})); return 2
