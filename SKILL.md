---
name: open-detective
description: Audit publicly reachable organization-owned assets for accidental personal-data or confidential-content exposure. Use for external inventory, public deployment discovery, anonymous observation, evidence classification, remediation tracking, and rechecks. Do not use for vulnerability scanning, authentication bypass, exploitation, credential use, or adjacent-record enumeration.
---

# Open-Detective

This installed skill defines the workflow; it does not install the Python package. Install the package with the [README instructions](README.md) before running `open-detective`.

Run **scope → inventory/discovery → ownership → anonymous observation → content classification → containment → recheck**. Never claim closure without a fresh observation.

## Mandatory policy

Read `ops/scope.md`. Measurement commands require an unexpired `--scope` file containing exact HTTPS origins, owners, ownership evidence, and path prefixes. Apply every `SUD-Rxx` rule. Company-specific values stay in local input.

Owner inventory may use explicitly authorized read credentials. Keep its credentials, process, browser profile, and output separate from anonymous target measurement. Discovery output is a candidate until ownership evidence links it to the organization.

```bash
open-detective probe --scope scope.json <url>
open-detective browser <url> --scope scope.json --duration 3
open-detective trace-assets --scope _local/scope.json --url https://app.example.test/public/ --output _local/case/asset-trace.json
open-detective inventory --provider import --scope-id TEAM --input inventory.json
open-detective discover --input candidates.json --scope-id TEAM
open-detective search-plan plan --output _local/plan.json --scope-id TEAM --company-en "<operator input>"
open-detective doctor --reference .
open-detective channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json
open-detective github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json
open-detective search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --channel-health _local/channel-health.json
open-detective search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --channel-health _local/channel-health.json
open-detective asset-profile --input _local/case/assets.json --output _local/case/asset-profile.json --markdown _local/case/asset-profile.md
open-detective asset-locations --input _local/case/asset-profile.json --locator-store _local/locators.sqlite --scope-id TEAM --output _local/case/private-locations.json
open-detective locators --store _local/locators.sqlite bind --scope-id TEAM --locator-ref "opaque:<id>" --scope _local/scope.json --db audit.sqlite --asset-id asset-1 --provider import
open-detective ledger --db audit.sqlite due
```

`forensics` is separate private-local work for an approved `--case` and owner-authorized read-only exports. Its case authorization is not a network measurement `--scope`. Read `ops/forensics.md`; do not authenticate, reuse credentials, acquire RAM/disk images, or infer no exfiltration from a missing log.

`asset-profile` is separate offline local analysis of owner-authorized, already available local bytes. A sanitized `probe` report or code-search metadata does not provide those bytes. It never fetches a locator or proves public/anonymous reachability, and its value-free category hints never confirm sensitive content or severity. Read `ops/asset-profile.md` for its manifest, bounds, and interpretation.

`asset-locations` resolves profile or inventory `locator_ref` values only against the existing local locator store in one `--scope-id`. It makes no network requests and writes exact locations only to a new private-local mapping. That mapping may contain sensitive URL components; never publish it. It does not inspect an index/file body or establish ownership, access, reachability, or exposure. Read `ops/asset-profile.md`.

After a bounded `probe` of an owned page, invoke `trace-assets` separately only when its related static files need checking. It is a scope-bound anonymous GET trace from one public HTML URL. Follow only explicit HTML `script` references and explicit GET JavaScript `fetch(...)` references that the unexpired scope authorizes. Keep aggregate request, byte, duration, depth, and deduplication bounds; do not execute JavaScript, render DOM, infer dynamic endpoints, authenticate, or mutate DOM gates. A sensitive-content candidate stops the trace early; an inline client password literal can therefore stop it before a later JSON fetch, which does not establish complete thin-gate tracing. It leaves `probe` and `browser` unchanged and they never invoke it automatically. The report contains asset links, content-profile hints, and gaps rather than source material; paired `--locator-store` and `--scope-id` retain final redirect locations locally while shared output keeps opaque references. Read `ops/asset-trace.md`.

`channel-discover` supports only bounded Cert Spotter CT and operator-configured query-bound JSON exports. `discovery-eval` and `asset-graph` are offline. Read `ops/discovery-optimization.md`; none establishes ownership or measurement authority.

For file-content discovery, first complete anonymous public-repository discovery, then enable optional `github_code` jobs with `search-plan plan --github-code --repository OWNER/REPO` or `search-plan enable-code --plan ... --repository OWNER/REPO` (repeat `--repository` for each approved public repository). Use `search-plan run-code` separately with an explicit search-token environment name, a fresh benign public-code fixture control, and private locator storage. Every token-authenticated query must have exactly one explicit `repo:` restriction; do not use it for global code search. Each invocation anonymously verifies the public fixture and selected repository before the authenticated search, and those preflights count toward its total request budget. Reuse existing query jobs; do not duplicate account discovery or treat code hits as deployed assets. Code-search authentication is restricted to the GitHub search API and never enters anonymous measurements. The generic importer cannot complete code jobs. Inspect their rate/pagination/index gaps and `ownership_pending` file candidates before following the existing ownership and target-scope workflow. Read `ops/github-code-search.md` for commands and control setup.

`tools/probe.sh` only wraps the Python probe. Do not recreate legacy classification or automatically replay calling-page headers.

## Decision contract

```text
access: BODY_SERVED | ACCESS_DENIED_OBSERVED | AUTH_REDIRECT_OBSERVED |
        NOT_FOUND_OBSERVED | INDETERMINATE
content: PUBLIC_UI | SENSITIVE_CONTENT_CONFIRMED | SENSITIVE_CANDIDATE |
         CLIENT_ENCRYPTED_OBSERVED | NOT_INSPECTED
confidence: confirmed | probable | unknown
```

Statuses describe one request. `BODY_SERVED` does not mean sensitive content. `SENSITIVE_CONTENT_CONFIRMED` requires a linked observation, minimal actual evidence, ownership evidence, and anonymous conditions. A password input is only `LOGIN_FORM_INDICATOR`, not an automatic `PUBLIC_UI`, protection, or sensitivity decision. A denied API is `ACCESS_DENIED_OBSERVED`. An IdP redirect supports only `AUTH_REDIRECT_OBSERVED` for that path.

For partial capture record `capture_complete=false`, inspected bytes, and stop reason. Distinguish full and prefix digests. Unsupported browser transports or unobserved Service Worker/WebSocket behavior remain `INDETERMINATE`; never claim total egress coverage.

## Intake and phase gates

Before any discovery, record local `audit-intake` data using `examples/audit-intake.example.json` and `schemas/audit-intake.schema.json`: exclusions with evidence; Korean/English identity, aliases, industry, functions, known URLs and domains; affiliate boundary; third-party declaration; owner/escalation references; and additional approval actions. It is neither executable scope nor a network grant. `third_parties.status="unknown"` is a gap, never a reason to infer ownership.

Use this order: (1) intake for boundary, exclusions, ownership references, and escalation; (2) offline identifiers and search plan; (3) `doctor --reference .`, which reports the runtime root actually loaded and compares it with the reviewed source tree at `.`; (4) fresh control-scope-authorized positive controls with `channels-doctor`, then public GitHub discovery under its separate `scope_id` and channel-health contract. Obtain administrator exports of contracts, assets, processor and outsourcer registers before approving an executable target scope and importing their candidates. Public-metadata discovery remains ownership-pending. Owner-inventory credentials remain a separate authorization path.

`channels-doctor` writes a local health report when its config and scope are valid, and prints changed channel rows. A control is `OK` only with HTTP 200, complete capture, and its configured `json_pointer` or `body_contains` expectation matched; prefer a specific JSON-pointer identity over a generic body marker, which can false-positive. Other reachable failures are `DEGRADED`; unreachable controls and HTTP 404/410 are `DEAD`. The report is local operational evidence with checked shape and freshness, not an electronic signature, remote attestation, or protection against a user who can change local files. Actual GitHub work needs fresh channel-specific controls: `github-repositories` for repository listing, and all three—`github-repositories`, `github-user-search`, `github-repository-search`—for a search seed because it can expand into repository listing. Imported results need health valid at `observed_at`; later expiry does not erase a historical result. Synthetic input never proves a real control. A successful control does not prove complete company discovery.

Match GitHub control IDs to `api.github.com`: repository detail or `/users|orgs/<owner>/repos`, `/search/users`, and `/search/repositories?q=…`. A marker from another endpoint is not a substitute; detail controls do not prove pagination or permissions.

## Inventory, discovery, and browser

The implemented owner inventory collects Vercel projects/deployments/aliases/domains and GitHub organization or approved-account repositories with optional recursive tree completeness. Follow pagination to completion and record cursor end, permissions, truncation, rate limits, and time windows. The anonymous `github-discover` command searches public users/repositories and expands known accounts or GitHub Pages links to repository metadata and Pages URL candidates. URLs not returned by those channels enter through normalized imports with provenance. Private repositories can still have public deployments. A zero from one channel is bounded non-observation, especially after failure.

Before initial public discovery, create a persistent `search-plan` from the supplied Korean/English names, aliases, industry terms, function terms, and known URLs. Run its bounded jobs and retain deferred work. Do not substitute a few handwritten queries or report generated candidates as executed searches. Use `tools/idgen.py` only for offline candidates. Platform validators filter invalid names. Similarity is never ownership evidence and does not authorize probing.

Use `brokered_anonymous_browser` only when static observation cannot answer whether content arrived. A fresh Playwright context routes approved GET document/script/stylesheet/XHR/fetch through the policy-bound transport broker without raw browser headers, cookies, auth, or referrer. Service Workers are off; WebSocket server connections are blocked and their messages discarded in a local sink; popups are closed and downloads refused. When DOM review finds no candidate, it also inspects bounded live `input`, `textarea`, and `select` values. Canvas pixels, shadow-DOM content outside the snapshot, JavaScript heap, post-interaction state, external protocols, and unsupported behavior are unmeasured. This is not an OS-firewall or total-egress guarantee. Do not enter credentials, remove DOM gates, solve challenges, enumerate IDs, or use stored sessions. Tests use synthetic fixtures.

## Evidence, remediation, and ledger

Stop after minimum proof. The runtime classifier is provisional: `SENSITIVE_CANDIDATE` or `NOT_INSPECTED`; `PUBLIC_UI` requires separate publication-intent review. A response candidate stops before body rendering; a runtime-state candidate stops further observation. Only human evidence review records real `SENSITIVE_CONTENT_CONFIRMED` in the ledger. `SYNTHETIC_CONTENT_CONFIRMED` is test-canary-only. If personal data or a usable secret appears, stop content collection and escalate. Do not test a discovered secret; live validity is unknown unless an authorized owner-side check provides separate evidence. Preserve `0` and `false` as actual values. Aggregates still require privacy controls and provenance.

Keep raw locators and sensitive artifacts in an access-controlled owner system. Shared output contains masked locations, types, approximate counts, appropriate hash/HMAC references, and evidence IDs. Sanitize query, fragment, userinfo, path, headers, redirects, logs, screenshots, and traces.

For active exposure, the accountable owner may decide urgent isolation and log preservation based on harm before final classification, while planning service continuity. Secret rotation and owner-side validity checks remain separate actions. Keep application authorization behind SSO. Verify the original URL, every known deployment and alias, caches, and authorized archive channels.

Use workflow states `candidate`, `ownership_pending`, `verification_pending`, `open`, `containment_pending`, `recheck_pending`, `partially_closed`, `closed`, and `reopened`. SQLite is the operational source of truth; Markdown is an export. Bind each asset and alias to its opaque locator `target_id` and `policy_id`; the ledger rejects a mismatch. Store append-only observations/events, aliases, controls, proof references, rechecks, and due dates. A current `BODY_SERVED`, unknown/incomplete result, or equal-time conflict after closure reopens or returns the finding to review. Notify on meaningful change, completion, failure, or required operator action.

`search-plan` distinguishes operator aliases from generated variants and keeps unrun work `deferred`; its status remains `PARTIAL` until all required channels are completed or explicitly `not_applicable`. Exact candidate URLs stay in the local locator store, while shared outputs retain only `locator_ref` and handoff state. A ref still requires scope authorization before `probe` or `browser`. `doctor` checks runtime/source parity only: repository changes or a push do not update an already installed runtime.

Report observation-backed facts, controls, owner and severity, unknowns and resolution conditions, containment and due dates, recheck evidence, and omitted actions. Express coverage as exact scopes, channels, and completed pages. Never describe synthetic tests as deployed or live verification.

Supporting files: `ops/discovery.md`, `ops/discovery-optimization.md`, `ops/verify.md`, `ops/triage.md`, `ops/evidence.md`, `ops/remediate.md`, `ops/forensics.md`, `ops/asset-profile.md`, `ops/asset-trace.md`, `surfaces/inventory.md`, `assets/ledger-template.md`.
