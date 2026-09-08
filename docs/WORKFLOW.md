# Open-Detective operating workflow

This guide connects an exposure investigation to the commands that Open-Detective actually implements. There is no single command that runs the whole workflow. An operator reviews the evidence at every gate, then explicitly supplies the next authority, input, and command.

It describes source revision [`e387e1ba454efe175fca0afffa78e4aa158a589e`](https://github.com/kindsusu/Open-Detective/tree/e387e1ba454efe175fca0afffa78e4aa158a589e). Confirm the installed runtime against this reviewed source with `doctor`; editing or pushing the repository does not update an installed runtime.

Open [the interactive Archify workflow](workflow/open-detective.workflow.html) in a browser after cloning or downloading this repository. GitHub's file viewer does not execute its interactive content.

## Stages and gates

| Stage | Inputs | Actions | Outputs | Gate to continue |
|---|---|---|---|---|
| 1. Intake | Korean/English organization identity, aliases, industry/functions, known URLs, exclusions, affiliate and third-party boundary, owner/escalation references | Create and validate local audit intake; request administrator asset, contract, processor, and outsourcer exports. Intake is not network authority. | Local intake and unresolved-gap list | Boundaries, exclusions, ownership/escalation references, and requested exports are recorded; offline planning may begin. |
| 2. Identifiers and plan | Official name, operator aliases, industry/function terms, known URLs | Create offline candidate variants and a bounded search plan. Similarity is never ownership evidence. | Private plan and deferred work | Budgets, channels, and explicit resume rules are recorded. |
| 3. Runtime and controls | Reviewed source, executable control scope, local control config | Run `doctor`; take fresh positive-control observations with `channels-doctor`. | Runtime parity and channel-health report | Controls required by the channel are fresh and valid. |
| 4. Discovery and owner inventory | Explicitly authorized owner credentials or exports, scope ID, plan | Run credential-separated owner inventory and anonymous public metadata discovery. Keep cursor, permission, rate-limit, truncation, and time-window gaps. | Provenance candidates, private locator store, coverage gaps | Owner record, DNS/control-plane relation, deployment metadata, or another accountable record is reviewed. |
| 5. Ownership and exact scope | Administrator exports, ownership evidence, exact HTTPS origin/path, expiry, budgets | Review the exports, bind locator to asset and `target_id`/`policy_id`, then approve executable scope. | Current local scope and locator binding | Owner, evidence, exact origin, and path boundary match. |
| 6. Anonymous observation | Scope and locator reference or exact URL | Use bounded `probe`; use a fresh brokered browser only if static observation cannot answer the content question. | Sanitized observation | Access and content are separate. Partial/unsupported capture is never safe or complete, even when an actual HTTP access status was observed. |
| 7. Human classification | Observation ID, masked proof reference, ownership evidence | Stop at minimum proof. A human records a confirmed result; automation remains provisional. | Severity, workflow state, evidence reference | Confirmed cases receive owner containment review; candidates and unknowns retain resolution conditions. |
| 8. Containment and ledger | Confirmed evidence, service impact, owner action evidence | Owner decides isolation, log preservation, rotation, and continuity; record actions and due work in the append-only ledger. | Remediation event and recheck work | Recheck scope declares the original locator, aliases/deployments, and permitted cache/archive channels. |
| 9. Fresh recheck | Fresh scope/control and every known locator/alias | Take a new anonymous observation and import it to the ledger. | Fresh evidence and closed/partially_closed/reopened state | `closed` needs every declared residue covered; unknown residue is `partially_closed`. |

## Operating sequence

Keep organization values, tokens, and exact locators in access-controlled `_local/` files, not in the repository. Replace `TEAM` and paths with approved values.

```bash
# 1–2: intake first, then offline identifiers and plan
python tools/idgen.py --ko "<organization>" --en "<official English name>" --industry "<industry>" --function "<function>"
open-detective search-plan plan --output _local/plan.json --scope-id TEAM --company-en "<official English name>"

# 3: runtime/source parity and fresh channel controls
open-detective doctor --reference .
open-detective channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json

# 4: owner-credential inventory and anonymous public discovery are separate paths
open-detective inventory --provider vercel --scope-id TEAM --token-env VERCEL_TOKEN
open-detective inventory --provider import --scope-id TEAM --input _local/owner-export.json
open-detective github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json
open-detective search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --channel-health _local/channel-health.json

# 5–6: bind only after ownership review, then observe anonymously
open-detective locators --store _local/locators.sqlite bind --scope-id TEAM --locator-ref "opaque:OPAQUE_ID" --scope _local/scope.json --db _local/audit.sqlite --asset-id asset-1 --provider import
open-detective probe --scope _local/scope.json --locator-store _local/locators.sqlite --locator-scope TEAM --locator-ref "opaque:OPAQUE_ID"
open-detective browser --scope _local/scope.json --locator-store _local/locators.sqlite --locator-scope TEAM --locator-ref "opaque:OPAQUE_ID" --duration 3
```

`search-plan` keeps operator aliases distinct from generated variants. It alternates full-identity, industry-context, and function-context work under a fixed budget. That is a bounded scheduling heuristic, not an optimal or exhaustive search engine. Unrun work stays `deferred`; status stays `PARTIAL` until every required channel completes or is `not_applicable` with a reason. A zero is only bounded non-observation for the recorded channel, pages, permissions, and time; it never proves no exposure or no organizational assets.

## Boundaries and decisions

- Owner inventory may use explicitly approved read credentials, but its process, browser profile, credentials, and output remain separate from anonymous measurement. No credentials, cookies, authorization, or referrer are sent to a target.
- Discovery output is a candidate. A public deployment may outlive a private repository; repository visibility does not prove deployment ownership or public access.
- `--scope` requires an exact HTTPS origin, owner, ownership evidence, path prefix, expiry, and budgets. Finding or resolving a locator does not authorize a request.
- `probe` and browser use GET and stop at minimum evidence. When personal data or a usable secret appears, stop content collection and do not test its validity.
- `BODY_SERVED` is only an access observation. `SENSITIVE_CONTENT_CONFIRMED` requires anonymous observation, ownership evidence, minimal actual evidence, and human review.

Automation records provisional content states such as `SENSITIVE_CANDIDATE` and `NOT_INSPECTED`, plus access and capture completeness. A human links the observation ID, reviewer/time, masked proof reference, ownership evidence, and anonymous condition before recording a confirmed finding. Keep raw locators and artifacts in an access-controlled owner system; share masked location/type/approximate count and evidence IDs only.

Containment is not automated. For urgent exposure, the accountable owner may choose immediate isolation of the exact deployment/share/object/alias and log preservation before continuity work; harm-based urgent containment does not need to wait for final classification. Secret rotation and owner-side validity checks are separate owner actions. The ledger is an append-only record of remediation, observations, aliases, controls, proof, and due/recheck work; it is not an orchestration system.

```bash
open-detective ledger --db _local/audit.sqlite open asset-1 --evidence-ref "evidence:opening"
open-detective ledger --db _local/audit.sqlite remediate FINDING_ID --evidence-ref "evidence:owner-action"
open-detective ledger --db _local/audit.sqlite schedule FINDING_ID --due-at "UTC_TIMESTAMP"
open-detective ledger --db _local/audit.sqlite due

# Import a fresh recheck before considering closure.
open-detective ledger --db _local/audit.sqlite import-observation --input _local/recheck.json --asset-id asset-1 --expected-policy --policy-evidence-ref "evidence:scope" --control-healthy --control-evidence-ref "evidence:control"
open-detective ledger --db _local/audit.sqlite close FINDING_ID --evidence-ref "evidence:fresh-recheck"
```

A recheck covers the original locator, every known alias/deployment, and separately authorized cache/archive channels in a fresh anonymous context. A current `BODY_SERVED`, unknown/incomplete observation, or equal-time conflict sends a closed finding back for review or reopening.

## Separate authorized local forensics

Forensics is private-local work separate from anonymous measurement and the operational SQLite ledger. It can run alongside urgent containment, but an approved `--case` is not a measurement `--scope`. It accepts owner-authorized read-only exports only, and the implemented timeline input type is `normalized_event_jsonl`.

```bash
open-detective forensics acquire --case _local/case.json --source-id src_00000000000000000000000000000005 --export _local/export.jsonl --evidence-dir _local/evidence
open-detective forensics verify --manifest _local/evidence/EVIDENCE_ID/manifest.json --evidence-dir _local/evidence
open-detective forensics custody-add --case _local/case.json --chain _local/evidence/custody.jsonl --event _local/event.json --evidence-dir _local/evidence
open-detective forensics timeline --case _local/case.json --events _local/events.jsonl --evidence-dir _local/evidence --output _local/timeline.json
```

It does not implement live SaaS/mail/EDR/cloud-IAM/storage/endpoint collectors, vendor parsers, RAM or disk acquisition, or backend authorization-policy tests. A missing, expired, inaccessible, or unknown log is a coverage gap; it does not establish that an event, actor, or exfiltration did not occur. Hash, custody, and timeline checks detect later changes to retained artifacts but do not prove authenticity, legal admissibility, or a complete chain.

## References

- [Scope rules and scope format](../ops/scope.md)
- [Discovery and owner inventory](../ops/discovery.md)
- [Anonymous observation decisions](../ops/verify.md)
- [Evidence minimization](../ops/evidence.md) and [triage](../ops/triage.md)
- [Containment and fresh recheck](../ops/remediate.md)
- [Authorized local forensics](../ops/forensics.md)
