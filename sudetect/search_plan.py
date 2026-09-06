"""Persistent, bounded multi-channel discovery plan runner."""
from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .github_discovery import discover as github_discover
from .identifiers import generate_identifiers, generate_search_queries, validate_target_candidate

_NS = uuid.UUID("a63cb58e-29d3-450c-8a71-1e4ad86dbe38")
CHANNELS = ("github", "web", "certificate_transparency", "documents")

def _now(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def _id(prefix, *parts): return prefix + "_" + uuid.uuid5(_NS, "\x1f".join(map(str, parts))).hex
def _write(path, value):
    target=Path(path); target.parent.mkdir(parents=True, exist_ok=True)
    temporary=target.with_suffix(target.suffix+".tmp")
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    temporary.replace(target)

def create_plan(*, scope_id: str, company_ko: str="", company_en: str="", aliases: Iterable[str]=(),
                industry: Iterable[str]=(), functions: Iterable[str]=(), known_urls: Iterable[str]=(),
                domains: Iterable[str]=(), query_budget: int=4, account_budget: int=4) -> dict[str,Any]:
    aliases=list(aliases); industry=list(industry); functions=list(functions); known_urls=list(known_urls); domains=list(domains)
    if not scope_id or not (company_ko or company_en or aliases): raise ValueError("company identity required")
    if not 1 <= query_budget <= 10 or not 1 <= account_budget <= 10: raise ValueError("invalid budget")
    if any(not isinstance(domain,str) or not re.fullmatch(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",domain)
           for domain in domains): raise ValueError("invalid domain seed")
    identity={"company_ko":company_ko,"company_en":company_en,"aliases":aliases,"industry":industry,"functions":functions,
              "known_urls":known_urls,"domains":domains}
    plan_id=_id("plan",scope_id,json.dumps(identity,ensure_ascii=False,sort_keys=True))
    queries=generate_search_queries(ko=company_ko,en=company_en,aliases=aliases,industry=industry,functions=functions)
    identifiers=[row for row in generate_identifiers(ko=company_ko,en=company_en,aliases=aliases,
                 industry=industry,functions=functions) if validate_target_candidate("github",str(row["identifier"]))]
    jobs=[]
    def job(channel,kind,value,rationale,state,budget=1,reason=None,not_applicable_reason=None):
        jid=_id("wrk",plan_id,channel,kind,value)
        item={"work_id":jid,"channel":channel,"kind":kind,"value":value,"generation_rationale":rationale,
              "state":state,"request_budget":budget,"result_count":None,"pages":None,"end_condition":None,"error_code":None}
        if reason:item["deferred_reason"]=reason
        if not_applicable_reason:item["not_applicable_reason"]=not_applicable_reason
        jobs.append(item)
    for index,row in enumerate(queries):
        job("github","search_query",row["query"],row["rationale"],"planned" if index<query_budget else "deferred",2,
            None if index<query_budget else "query_budget_exceeded")
    for index,row in enumerate(identifiers):
        job("github","account_candidate",row["identifier"],row["rationale"],"planned" if index<account_budget else "deferred",1,
            None if index<account_budget else "account_budget_exceeded")
    for value in known_urls: job("github","known_url",value,"operator-known-url","planned",2)
    # These channels have an honest handoff contract; this package does not pretend
    # to collect them. Operator exports can later be imported into the same jobs.
    for row in queries[:query_budget]:
        job("web","search_query",row["query"],row["rationale"],"deferred",0,"import_required")
        job("documents","search_query",row["query"],row["rationale"],"deferred",0,"import_required")
    if domains:
        for domain in domains:
            job("certificate_transparency","domain_seed",domain,"operator-domain-seed","deferred",0,"import_required")
    else:
        job("certificate_transparency","domain_seed_missing","","no-approved-domain-seed","not_applicable",0,
            not_applicable_reason="no_approved_domain_seed")
    return {"schema_version":"1.0","plan_id":plan_id,"scope_id":scope_id,"created_at":_now(),
            "identity":identity,"required_channels":list(CHANNELS),"budgets":{"github_queries":query_budget,
            "github_accounts":account_budget},"jobs":jobs,"runs":[],"status":"PLANNED"}

def _status(plan):
    jobs=plan["jobs"]; required=set(plan.get("required_channels",CHANNELS))
    states={c:[j["state"] for j in jobs if j["channel"]==c] for c in required}
    if any(run.get("status") != "COMPLETE" for run in plan.get("runs",[]) if isinstance(run,Mapping)):
        return "PARTIAL"
    if any(not values or any(v in {"planned","deferred","failed"} for v in values) for values in states.values()): return "PARTIAL"
    return "COMPLETE" if all(all(v in {"completed","not_applicable"} for v in values) for values in states.values()) else "PARTIAL"

def _promote(jobs: list[dict[str,Any]], kind: str, budget: int) -> None:
    if not isinstance(budget,int) or isinstance(budget,bool) or not 0 <= budget <= 10: raise ValueError("invalid resume budget")
    for job in [j for j in jobs if j.get("kind")==kind and j.get("state")=="deferred" and j.get("channel")=="github"][:budget]:
        job["state"]="planned"; job.pop("deferred_reason",None)

def _apply_coverage(job: dict[str,Any], rows: list[Mapping[str,Any]], observed_at: str) -> None:
    if not rows:
        job.update(state="failed",error_code="COVERAGE_MISSING",result_count=0,pages=0,end_condition=None,
                   observed_at=observed_at,source_ref="github_api:anonymous")
        return
    errors=[str(row.get("error_code")) for row in rows if row.get("error_code")]
    states={row.get("state") for row in rows}
    complete=states=={"COMPLETE"} and not errors and all(row.get("end_condition") for row in rows)
    job.update(state="completed" if complete else "failed",error_code=errors[0] if errors else (None if complete else "CHANNEL_PARTIAL"),
               result_count=sum(int(row.get("items",0)) for row in rows),pages=sum(int(row.get("pages",0)) for row in rows),
               end_condition="page_exhausted" if complete else None,observed_at=observed_at,source_ref="github_api:anonymous")

def run_plan(plan: Mapping[str,Any], *, fetch=None, locator_store=None,
             resume_query_budget: int=0, resume_account_budget: int=0) -> dict[str,Any]:
    out=json.loads(json.dumps(plan)); jobs=out.get("jobs",[])
    _promote(jobs,"search_query",resume_query_budget); _promote(jobs,"account_candidate",resume_account_budget)
    eligible=[j for j in jobs if j.get("channel")=="github" and j.get("state")=="planned"]
    order={"known_url":0,"search_query":1,"account_candidate":2}
    eligible.sort(key=lambda job: order.get(str(job.get("kind")),99))
    selected=[]; query_count=account_count=estimated_requests=0
    for job in eligible:
        next_queries=query_count+(job.get("kind")=="search_query")
        next_accounts=account_count+(job.get("kind")=="account_candidate")
        cost=max(1,int(job.get("request_budget",1)))
        if next_queries>10 or next_accounts>10 or estimated_requests+cost>20:
            job["state"]="deferred"; job["deferred_reason"]="run_budget_exceeded"; continue
        selected.append(job); query_count=next_queries; account_count=next_accounts; estimated_requests+=cost
    queries=[j["value"] for j in selected if j["kind"]=="search_query"]
    accounts=[j["value"] for j in selected if j["kind"]=="account_candidate"]
    known=[j["value"] for j in selected if j["kind"]=="known_url"]
    if selected:
        max_requests=min(30,max(1,estimated_requests+10))
        result=github_discover(out["scope_id"],seeds=queries,accounts=accounts,known_urls=known,
                               max_requests=max_requests,fetch=fetch,max_accounts=10)
        query_index=account_index=known_index=0
        for job in selected:
            if job["kind"]=="search_query":
                query_index+=1; keys=(f"search_users:{query_index}",f"search_repositories:{query_index}")
            elif job["kind"]=="account_candidate":
                keys=(f"list_public_repositories:{job['value']}",)
            else:
                from .github_discovery import _known_pages_url
                parsed=_known_pages_url(job["value"])
                keys=(f"repository_detail:{parsed[0]}/{parsed[1]}",) if parsed else ()
            _apply_coverage(job,[result["coverage"][key] for key in keys if key in result["coverage"]],result["observed_at"])
        for candidate in result.get("candidates",[]):
            exact=candidate.get("pages_url_candidate")
            if locator_store is not None and exact:
                candidate["locator_ref"]=locator_store.put(out["scope_id"],exact); candidate["handoff_state"]="ready"
                from urllib.parse import urlsplit
                candidate["pages_url_candidate"]="https://"+str(urlsplit(exact).hostname)
            else:
                candidate["handoff_state"]="blocked"
        out.setdefault("runs",[]).append({"run_id":_id("run",out["plan_id"],_now()),"channel":"github",
                                           "observed_at":result["observed_at"],"status":result["status"],"result":result})
    out["status"]=_status(out); out["updated_at"]=_now(); return out

def import_results(plan: Mapping[str,Any], payload: Mapping[str,Any]) -> dict[str,Any]:
    out=json.loads(json.dumps(plan)); by_id={j["work_id"]:j for j in out["jobs"]}
    for row in payload.get("jobs",[]):
        if not isinstance(row,Mapping) or row.get("work_id") not in by_id: raise ValueError("unknown work id")
        state=row.get("state")
        if state not in {"completed","failed","not_applicable"}: raise ValueError("invalid import state")
        job=by_id[row["work_id"]]; job["state"]=state
        for key in ("result_count","pages","end_condition","error_code","observed_at","source_ref"):
            job[key]=row.get(key)
        try:
            parsed_time=datetime.fromisoformat(str(job.get("observed_at","")).replace("Z","+00:00"))
            time_valid=(parsed_time.tzinfo is not None and
                        parsed_time.astimezone(timezone.utc) <= datetime.now(timezone.utc))
        except ValueError:
            time_valid=False
        source_valid=isinstance(job.get("source_ref"),str) and 1<=len(job["source_ref"])<=256
        if state=="completed" and (job.get("error_code") is not None or not time_valid or not source_valid or
                not all(job.get(k) is not None for k in ("result_count","pages","end_condition","observed_at","source_ref")) or
                not isinstance(job.get("result_count"),int) or isinstance(job.get("result_count"),bool) or job["result_count"]<0 or
                not isinstance(job.get("pages"),int) or isinstance(job.get("pages"),bool) or job["pages"]<0 or
                job.get("end_condition") not in {"cursor_exhausted","page_exhausted","provider_empty","import_verified"}):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
        if state=="not_applicable" and not row.get("not_applicable_reason"):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
        elif state=="not_applicable":
            job["not_applicable_reason"]=str(row["not_applicable_reason"])[:256]
        counts_valid=(isinstance(job.get("result_count"),int) and not isinstance(job.get("result_count"),bool) and job["result_count"]>=0 and
                      isinstance(job.get("pages"),int) and not isinstance(job.get("pages"),bool) and job["pages"]>=0)
        if state=="failed" and (not job.get("error_code") or not time_valid or not source_valid or not counts_valid):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
    out["status"]=_status(out); out["updated_at"]=_now(); return out

def plan_status(plan):
    counts={}
    for job in plan.get("jobs",[]): counts[job["state"]]=counts.get(job["state"],0)+1
    return {"plan_id":plan["plan_id"],"status":_status(plan),"job_counts":counts,
            "required_channels":plan.get("required_channels",[])}

def main(argv=None):
    p=argparse.ArgumentParser(description="Create and run bounded discovery manifests")
    sub=p.add_subparsers(dest="command",required=True)
    create=sub.add_parser("plan"); create.add_argument("--output",required=True); create.add_argument("--scope-id",required=True)
    create.add_argument("--company-ko",default=""); create.add_argument("--company-en",default=""); create.add_argument("--alias",action="append",default=[])
    create.add_argument("--industry",action="append",default=[]); create.add_argument("--function",action="append",default=[]); create.add_argument("--known-url",action="append",default=[]); create.add_argument("--domain",action="append",default=[])
    create.add_argument("--query-budget",type=int,default=4); create.add_argument("--account-budget",type=int,default=4)
    for name in ("run","status"):
        cmd=sub.add_parser(name); cmd.add_argument("--plan",required=True)
        if name=="run": cmd.add_argument("--locator-store"); cmd.add_argument("--resume-query-budget",type=int,default=0); cmd.add_argument("--resume-account-budget",type=int,default=0)
    imp=sub.add_parser("import"); imp.add_argument("--plan",required=True); imp.add_argument("--input",required=True)
    args=p.parse_args(argv)
    try:
        if args.command=="plan":
            plan=create_plan(scope_id=args.scope_id,company_ko=args.company_ko,company_en=args.company_en,aliases=args.alias,
                 industry=args.industry,functions=args.function,known_urls=args.known_url,domains=args.domain,query_budget=args.query_budget,account_budget=args.account_budget); _write(args.output,plan)
        else:
            path=Path(args.plan); plan=json.loads(path.read_text(encoding="utf-8"))
            if args.command=="run":
                if args.locator_store:
                    from .locators import LocatorStore
                    with LocatorStore(args.locator_store) as store: plan=run_plan(plan,locator_store=store,resume_query_budget=args.resume_query_budget,resume_account_budget=args.resume_account_budget)
                else: plan=run_plan(plan,resume_query_budget=args.resume_query_budget,resume_account_budget=args.resume_account_budget)
                _write(path,plan)
            elif args.command=="import": plan=import_results(plan,json.loads(Path(args.input).read_text(encoding="utf-8"))); _write(path,plan)
        print(json.dumps(plan_status(plan),ensure_ascii=False,sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,json.JSONDecodeError):
        print(json.dumps({"status":"FAILED","error":"search_plan_failed"})); return 2

if __name__=="__main__": raise SystemExit(main())
