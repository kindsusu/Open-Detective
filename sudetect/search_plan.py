"""Persistent, bounded multi-channel discovery plan runner."""
from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

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
    return {"schema_version":"1.0","coverage_version":2,"legacy_coverage_gap":False,
            "plan_id":plan_id,"scope_id":scope_id,"created_at":_now(),
            "identity":identity,"required_channels":list(CHANNELS),"budgets":{"github_queries":query_budget,
            "github_accounts":account_budget},"jobs":jobs,"runs":[],"status":"PLANNED"}

def _status(plan):
    jobs=plan["jobs"]; required=set(plan.get("required_channels",CHANNELS))
    if (any(run.get("status") != "COMPLETE" for run in plan.get("runs",[]) if isinstance(run,Mapping))
            and plan.get("legacy_coverage_gap") is not False):
        # Legacy plans did not retain per-job attempts, so a partial run cannot
        # safely be superseded until a fresh run/import records current evidence.
        return "PARTIAL"
    states={c:[j["state"] for j in jobs if j["channel"]==c] for c in required}
    if any(not values or any(v in {"planned","deferred","failed"} for v in values) for values in states.values()): return "PARTIAL"
    for job in jobs:
        if job.get("state")=="not_applicable" and not job.get("not_applicable_reason"):
            return "PARTIAL"
        if job.get("state")=="completed" and (job.get("error_code") is not None or
                not all(job.get(key) is not None for key in ("result_count","pages","end_condition","observed_at","source_ref"))):
            return "PARTIAL"
    return "COMPLETE" if all(all(v in {"completed","not_applicable"} for v in values) for values in states.values()) else "PARTIAL"

def _promote(jobs: list[dict[str,Any]], kind: str, budget: int) -> None:
    if not isinstance(budget,int) or isinstance(budget,bool) or not 0 <= budget <= 10: raise ValueError("invalid resume budget")
    for job in [j for j in jobs if j.get("kind")==kind and j.get("state")=="deferred" and j.get("channel")=="github"][:budget]:
        job["state"]="planned"; job.pop("deferred_reason",None)

def _apply_coverage(job: dict[str,Any], rows: list[Mapping[str,Any]], observed_at: str,
                    expected_rows: int=1) -> dict[str,Any]:
    if len(rows) != expected_rows:
        job.update(state="failed",error_code="COVERAGE_MISSING",result_count=0,pages=0,end_condition=None,
                   observed_at=observed_at,source_ref="github_api:anonymous")
        attempt={"attempted_at":observed_at,"state":"failed","error_code":"COVERAGE_MISSING",
                 "result_count":sum(int(row.get("items",0)) for row in rows),
                 "pages":sum(int(row.get("pages",0)) for row in rows),"end_condition":None,
                 "source_ref":"github_api:anonymous","coverage":[dict(row) for row in rows]}
        job.setdefault("attempts",[]).append(attempt)
        return attempt
    errors=[str(row.get("error_code")) for row in rows if row.get("error_code")]
    states={row.get("state") for row in rows}
    complete=states=={"COMPLETE"} and not errors and all(row.get("end_condition") for row in rows)
    end_conditions={str(row.get("end_condition")) for row in rows}
    end_condition=end_conditions.pop() if complete and len(end_conditions)==1 else ("page_exhausted" if complete else None)
    job.update(state="completed" if complete else "failed",error_code=errors[0] if errors else (None if complete else "CHANNEL_PARTIAL"),
               result_count=sum(int(row.get("items",0)) for row in rows),pages=sum(int(row.get("pages",0)) for row in rows),
               end_condition=end_condition,observed_at=observed_at,source_ref="github_api:anonymous")
    attempt={"attempted_at":observed_at,"state":job["state"],"error_code":job["error_code"],
             "result_count":job["result_count"],"pages":job["pages"],"end_condition":job["end_condition"],
             "source_ref":job["source_ref"],"coverage":[dict(row) for row in rows]}
    job.setdefault("attempts",[]).append(attempt)
    return attempt

def _dynamic_account_job(plan: dict[str,Any], account: str, rationale: str) -> dict[str,Any]:
    for job in plan["jobs"]:
        if (job.get("channel")=="github" and job.get("kind")=="account_candidate"
                and str(job.get("value","")).casefold()==account.casefold()):
            return job
    work_id=_id("wrk",plan["plan_id"],"github","account_candidate",account.casefold())
    job={"work_id":work_id,"channel":"github","kind":"account_candidate","value":account,
         "generation_rationale":rationale,"state":"deferred","deferred_reason":"discovered_account_pending",
         "request_budget":1,"result_count":None,"pages":None,"end_condition":None,"error_code":None}
    plan["jobs"].append(job)
    return job

def _record_discovered_accounts(plan: dict[str,Any], result: Mapping[str,Any]) -> None:
    coverage=result.get("coverage",{})
    observed_at=str(result.get("observed_at") or _now())
    for row in result.get("accounts",[]):
        if not isinstance(row,Mapping) or not isinstance(row.get("login"),str):
            continue
        account=row["login"]
        job=_dynamic_account_job(plan,account,"github-search-discovered-account")
        key=next((value for value in coverage if value.casefold()==f"list_public_repositories:{account}".casefold()),None)
        if key is not None:
            # One discover batch can mention an account through several edges.
            latest=(job.get("attempts") or [{}])[-1]
            if latest.get("attempted_at") != observed_at:
                _apply_coverage(job,[coverage[key]],observed_at)
    for row in result.get("deferred",[]):
        if (isinstance(row,Mapping) and row.get("kind")=="account_expansion"
                and isinstance(row.get("value"),str)):
            _dynamic_account_job(plan,row["value"],"github-search-deferred-account")

def _next_work(plan: Mapping[str,Any]) -> dict[str,Any]:
    pending=[j for j in plan.get("jobs",[]) if j.get("state") in {"planned","deferred","failed"}]
    next_job=next((j for state in ("planned","failed","deferred") for j in pending if j.get("state")==state),None)
    counts={state:sum(j.get("state")==state for j in pending) for state in ("planned","failed","deferred")}
    answer={"remaining":sum(counts.values()),"by_state":counts}
    if next_job:
        answer["next"]={"work_id":next_job.get("work_id"),"channel":next_job.get("channel"),
                        "kind":next_job.get("kind"),"state":next_job.get("state"),
                        "reason":next_job.get("error_code") or next_job.get("deferred_reason") or "ready"}
    return answer

def run_plan(plan: Mapping[str,Any], *, fetch=None, locator_store=None,
             resume_query_budget: int=0, resume_account_budget: int=0,
             retry_failed: bool=False, request_budget: int=20, max_batches: int=100,
             resume_all_deferred: bool=False, per_job_request_budget: int=6,
             persist: Callable[[Mapping[str,Any]],None] | None=None) -> dict[str,Any]:
    out=json.loads(json.dumps(plan)); jobs=out.get("jobs",[])
    if (out.get("coverage_version",1)<2 and
            any(run.get("status") != "COMPLETE" for run in out.get("runs",[]) if isinstance(run,Mapping))):
        out["legacy_coverage_gap"]=True
    if (not isinstance(request_budget,int) or isinstance(request_budget,bool) or not 1<=request_budget<=1000 or
            not isinstance(max_batches,int) or isinstance(max_batches,bool) or not 1<=max_batches<=100 or
            not isinstance(per_job_request_budget,int) or isinstance(per_job_request_budget,bool) or
            not 1<=per_job_request_budget<=30):
        raise ValueError("invalid run budget")
    _promote(jobs,"search_query",resume_query_budget); _promote(jobs,"account_candidate",resume_account_budget)
    if retry_failed:
        for job in jobs:
            if job.get("channel")=="github" and job.get("state")=="failed":
                job["state"]="planned"; job["retry_of_error"]=job.get("error_code")
    eligible=[j for j in jobs if j.get("channel")=="github" and
              (j.get("state")=="planned" or (resume_all_deferred and j.get("state")=="deferred"))]
    # Exact URLs and supplied/generated identity candidates are cheap and strong.
    # Run them before broad searches so a paginated search cannot starve them.
    def priority(job: Mapping[str,Any]) -> int:
        if job.get("kind")=="known_url": return 0
        if job.get("kind")=="search_query" and not str(job.get("generation_rationale","")).startswith("broad:"): return 1
        if job.get("kind")=="account_candidate": return 2
        if job.get("kind")=="search_query": return 3
        return 99
    known=sorted((j for j in eligible if priority(j)==0),key=priority)
    queries=[j for j in eligible if priority(j)==1]
    accounts=[j for j in eligible if priority(j)==2 and j.get("generation_rationale")!="github-search-discovered-account"]
    interleaved=[]
    for index in range(max(len(queries),len(accounts))):
        if index<len(queries): interleaved.append(queries[index])
        if index<len(accounts): interleaved.append(accounts[index])
    eligible=known+interleaved+[j for j in eligible if j not in known and j not in interleaved]
    requests_used=0; batches=0; stop_reason="no_runnable_work" if not eligible else None
    execution_run: dict[str,Any] | None=None
    queued={job["work_id"] for job in eligible}
    position=0
    while position<len(eligible):
        job=eligible[position]; position+=1
        if batches>=max_batches or requests_used>=request_budget:
            stop_reason="batch_limit_reached" if batches>=max_batches else "request_budget_exhausted"; break
        remaining=request_budget-requests_used
        minimum=2 if job.get("kind")=="search_query" else 1
        if remaining<minimum:
            stop_reason="request_budget_exhausted"; break
        if job.get("state")=="deferred":
            job["resumed_from_deferred_reason"]=job.get("deferred_reason")
            job["state"]="planned"; job.pop("deferred_reason",None)
        kwargs={"seeds":[],"accounts":[],"known_urls":[]}
        if job["kind"]=="search_query": kwargs["seeds"]=[job["value"]]
        elif job["kind"]=="account_candidate": kwargs["accounts"]=[job["value"]]
        else: kwargs["known_urls"]=[job["value"]]
        result=github_discover(out["scope_id"],max_requests=min(per_job_request_budget,remaining),fetch=fetch,max_accounts=10,**kwargs)
        used=int(result.get("coverage",{}).get("totals",{}).get("requests",0))
        requests_used+=min(remaining,max(0,used)); batches+=1
        if job["kind"]=="search_query": keys=("search_users:1","search_repositories:1")
        elif job["kind"]=="account_candidate": keys=(f"list_public_repositories:{job['value']}",)
        else:
            from .github_discovery import _known_pages_url
            parsed=_known_pages_url(job["value"]); keys=(f"repository_detail:{parsed[0]}/{parsed[1]}",) if parsed else ()
        _apply_coverage(job,[result["coverage"][key] for key in keys if key in result.get("coverage",{})],
                        result["observed_at"],len(keys))
        _record_discovered_accounts(out,result)
        if resume_all_deferred:
            additions=[candidate for candidate in jobs if candidate.get("channel")=="github"
                       and candidate.get("state") in {"planned","deferred"} and candidate.get("work_id") not in queued]
            additions.sort(key=priority)
            eligible.extend(additions); queued.update(candidate["work_id"] for candidate in additions)
        for candidate in result.get("candidates",[]):
            exact=candidate.get("pages_url_candidate")
            if locator_store is not None and exact:
                candidate["locator_ref"]=locator_store.put(out["scope_id"],exact); candidate["handoff_state"]="ready"
                from urllib.parse import urlsplit
                candidate["pages_url_candidate"]="https://"+str(urlsplit(exact).hostname)
            else:
                candidate["handoff_state"]="blocked"
        if execution_run is None:
            execution_run={"run_id":_id("run",out["plan_id"],job["work_id"],_now()),"channel":"github",
                           "work_ids":[],"observed_at":result["observed_at"],"status":result["status"],
                           "requests_used":0,"result":{"schema_version":"1.0","provider":"github_public",
                           "scope_id":out["scope_id"],"status":"COMPLETE","candidates":[],"accounts":[],
                           "errors":[],"coverage":{},"totals":{"requests":0,"batches":0}},"batches":[]}
            out.setdefault("runs",[]).append(execution_run)
        execution_run["work_ids"].append(job["work_id"])
        execution_run["requests_used"]+=used
        execution_run["batches"].append({"work_id":job["work_id"],"observed_at":result["observed_at"],
                                          "status":result["status"],"requests_used":used,"result":result})
        aggregate=execution_run["result"]
        candidate_index={row["slug"].casefold():row for row in aggregate["candidates"]}
        candidate_index.update({row["slug"].casefold():row for row in result.get("candidates",[])})
        aggregate["candidates"]=sorted(candidate_index.values(),key=lambda row:row["slug"].casefold())
        account_index={row["login"].casefold():row for row in aggregate["accounts"]}
        account_index.update({row["login"].casefold():row for row in result.get("accounts",[])})
        aggregate["accounts"]=sorted(account_index.values(),key=lambda row:row["login"].casefold())
        aggregate["errors"]=sorted(set(aggregate["errors"]) | set(result.get("errors",[])))
        aggregate["coverage"].update({f"{job['work_id']}:{key}":value for key,value in result.get("coverage",{}).items()
                                      if key!="totals"})
        aggregate["totals"]={"requests":execution_run["requests_used"],"batches":len(execution_run["batches"]),
                             "candidates":len(aggregate["candidates"]),"accounts":len(aggregate["accounts"])}
        aggregate["status"]="COMPLETE" if not aggregate["errors"] else "PARTIAL"
        execution_run["status"]=aggregate["status"]
        if "RATE_LIMITED" in result.get("errors",[]):
            stop_reason="provider_rate_limited"
        elif requests_used>=request_budget:
            stop_reason="request_budget_exhausted"
        out["last_execution"]={"requests_used":requests_used,"request_budget":request_budget,"batches":batches,
                               "max_batches":max_batches,"stop_reason":stop_reason,"next_work":_next_work(out)}
        out["status"]=_status(out); out["updated_at"]=_now()
        if persist: persist(out)
        if stop_reason in {"provider_rate_limited","request_budget_exhausted"}: break
    if stop_reason is None and batches>=max_batches and any(j.get("state")=="planned" for j in jobs): stop_reason="batch_limit_reached"
    out["last_execution"]={"requests_used":requests_used,"request_budget":request_budget,"batches":batches,
                           "max_batches":max_batches,"stop_reason":stop_reason or "completed_runnable_work",
                           "next_work":_next_work(out)}
    out["status"]=_status(out); out["updated_at"]=_now()
    if persist: persist(out)
    return out

def import_results(plan: Mapping[str,Any], payload: Mapping[str,Any]) -> dict[str,Any]:
    out=json.loads(json.dumps(plan)); by_id={j["work_id"]:j for j in out["jobs"]}
    if (out.get("coverage_version",1)<2 and
            any(run.get("status") != "COMPLETE" for run in out.get("runs",[]) if isinstance(run,Mapping))):
        out["legacy_coverage_gap"]=True
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
                job.get("end_condition") not in {"cursor_exhausted","page_exhausted","provider_empty","import_verified",
                                                  "not_found_observed"}):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
        if state=="not_applicable" and not row.get("not_applicable_reason"):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
        elif state=="not_applicable":
            job["not_applicable_reason"]=str(row["not_applicable_reason"])[:256]
        counts_valid=(isinstance(job.get("result_count"),int) and not isinstance(job.get("result_count"),bool) and job["result_count"]>=0 and
                      isinstance(job.get("pages"),int) and not isinstance(job.get("pages"),bool) and job["pages"]>=0)
        if state=="failed" and (not job.get("error_code") or not time_valid or not source_valid or not counts_valid):
            job["state"]="failed"; job["error_code"]="PROVENANCE_INCOMPLETE"
        job.setdefault("attempts",[]).append({"attempted_at":job.get("observed_at"),"state":job["state"],
            "error_code":job.get("error_code"),"result_count":job.get("result_count"),"pages":job.get("pages"),
            "end_condition":job.get("end_condition"),"source_ref":job.get("source_ref"),"method":"import"})
    out["status"]=_status(out); out["updated_at"]=_now(); return out

def plan_status(plan):
    counts={}
    for job in plan.get("jobs",[]): counts[job["state"]]=counts.get(job["state"],0)+1
    answer={"plan_id":plan["plan_id"],"status":_status(plan),"job_counts":counts,
            "required_channels":plan.get("required_channels",[]),"next_work":_next_work(plan)}
    if plan.get("last_execution"): answer["last_execution"]={k:v for k,v in plan["last_execution"].items() if k!="next_work"}
    return answer

def main(argv=None):
    p=argparse.ArgumentParser(description="Create and run bounded discovery manifests")
    sub=p.add_subparsers(dest="command",required=True)
    create=sub.add_parser("plan"); create.add_argument("--output",required=True); create.add_argument("--scope-id",required=True)
    create.add_argument("--company-ko",default=""); create.add_argument("--company-en",default=""); create.add_argument("--alias",action="append",default=[])
    create.add_argument("--industry",action="append",default=[]); create.add_argument("--function",action="append",default=[]); create.add_argument("--known-url",action="append",default=[]); create.add_argument("--domain",action="append",default=[])
    create.add_argument("--query-budget",type=int,default=4); create.add_argument("--account-budget",type=int,default=4)
    for name in ("run","run-until-budget","status"):
        cmd=sub.add_parser(name); cmd.add_argument("--plan",required=True)
        if name in {"run","run-until-budget"}:
            cmd.add_argument("--locator-store"); cmd.add_argument("--resume-query-budget",type=int,default=0); cmd.add_argument("--resume-account-budget",type=int,default=0)
            cmd.add_argument("--retry-failed",action="store_true")
            cmd.add_argument("--request-budget",type=int,default=20 if name=="run" else None,
                             required=name=="run-until-budget")
            cmd.add_argument("--max-batches",type=int,default=100)
            cmd.add_argument("--per-job-request-budget",type=int,default=6)
    imp=sub.add_parser("import"); imp.add_argument("--plan",required=True); imp.add_argument("--input",required=True)
    args=p.parse_args(argv)
    try:
        if args.command=="plan":
            plan=create_plan(scope_id=args.scope_id,company_ko=args.company_ko,company_en=args.company_en,aliases=args.alias,
                 industry=args.industry,functions=args.function,known_urls=args.known_url,domains=args.domain,query_budget=args.query_budget,account_budget=args.account_budget); _write(args.output,plan)
        else:
            path=Path(args.plan); plan=json.loads(path.read_text(encoding="utf-8"))
            if args.command in {"run","run-until-budget"}:
                options={"resume_query_budget":args.resume_query_budget,"resume_account_budget":args.resume_account_budget,
                         "retry_failed":args.retry_failed,"request_budget":args.request_budget,"max_batches":args.max_batches,
                         "resume_all_deferred":args.command=="run-until-budget",
                         "per_job_request_budget":args.per_job_request_budget,
                         "persist":lambda value:_write(path,value)}
                if args.locator_store:
                    from .locators import LocatorStore
                    with LocatorStore(args.locator_store) as store: plan=run_plan(plan,locator_store=store,**options)
                else: plan=run_plan(plan,**options)
                _write(path,plan)
            elif args.command=="import": plan=import_results(plan,json.loads(Path(args.input).read_text(encoding="utf-8"))); _write(path,plan)
        print(json.dumps(plan_status(plan),ensure_ascii=False,sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,json.JSONDecodeError):
        print(json.dumps({"status":"FAILED","error":"search_plan_failed"})); return 2

if __name__=="__main__": raise SystemExit(main())
