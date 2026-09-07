---
name: su-detect
description: Audit publicly reachable organization-owned assets for accidental personal-data or confidential-content exposure. Use for external inventory, public deployment discovery, anonymous observation, evidence classification, remediation tracking, and rechecks. Do not use for vulnerability scanning, authentication bypass, exploitation, credential use, or adjacent-record enumeration.
---

# su-detect

Run **scope → inventory/discovery → ownership → anonymous observation → content classification → containment → recheck**. Never claim closure without a fresh observation.

## Mandatory policy

Read `ops/scope.md`. Measurement commands require an unexpired `--scope` file containing exact HTTPS origins, owners, ownership evidence, and path prefixes. Apply every `SUD-Rxx` rule. Company-specific values stay in local input.

Owner inventory may use explicitly authorized read credentials. Keep its credentials, process, browser profile, and output separate from anonymous target measurement. Discovery output is a candidate until ownership evidence links it to the organization.

```bash
python -m sudetect probe --scope scope.json <url>
python -m sudetect browser <url> --scope scope.json --duration 3
python -m sudetect inventory --provider import --scope-id TEAM --input inventory.json
python -m sudetect discover --input candidates.json --scope-id TEAM
python -m sudetect search-plan plan --output _local/plan.json --scope-id TEAM --company-en "<operator input>"
python -m sudetect doctor --reference .
python -m sudetect channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json
python -m sudetect github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json
python -m sudetect search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --channel-health _local/channel-health.json
python -m sudetect search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --channel-health _local/channel-health.json
python -m sudetect locators --store _local/locators.sqlite bind --scope-id TEAM --locator-ref "opaque:<id>" --scope _local/scope.json --db audit.sqlite --asset-id asset-1 --provider import
python -m sudetect ledger --db audit.sqlite due
```

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

Use this order: (1) intake for boundary, exclusions, ownership references, and escalation; (2) offline identifiers and search plan; (3) `doctor --reference .`, which reports the runtime root actually loaded and compares it with the reviewed source tree at `.`; (4) fresh scope-authorized positive controls with `channels-doctor`, then public GitHub discovery. Obtain administrator exports of contracts, assets, processor and outsourcer registers before approving executable scope and importing candidates. Owner-inventory credentials remain a separate authorization path.

`channels-doctor` writes a local health report when its config and scope are valid, and prints changed channel rows. A control is `OK` only with HTTP 200, complete capture, and its configured `json_pointer` or `body_contains` expectation matched; prefer a specific JSON-pointer identity over a generic body marker, which can false-positive. Other reachable failures are `DEGRADED`; unreachable controls and HTTP 404/410 are `DEAD`. The report is local operational evidence with checked shape and freshness, not an electronic signature, remote attestation, or protection against a user who can change local files. Actual GitHub work needs fresh channel-specific controls: `github-repositories` for repository listing, and all three—`github-repositories`, `github-user-search`, `github-repository-search`—for a search seed because it can expand into repository listing. Imported results need health valid at `observed_at`; later expiry does not erase a historical result. Synthetic input never proves a real control. A successful control does not prove complete company discovery.

Match GitHub control IDs to `api.github.com`: repository detail or `/users|orgs/<owner>/repos`, `/search/users`, and `/search/repositories?q=…`. A marker from another endpoint is not a substitute; detail controls do not prove pagination or permissions.

## Inventory, discovery, and browser

The implemented owner inventory collects Vercel projects/deployments/aliases/domains and GitHub organization or approved-account repositories with optional recursive tree completeness. Follow pagination to completion and record cursor end, permissions, truncation, rate limits, and time windows. The anonymous `github-discover` command searches public users/repositories and expands known accounts or GitHub Pages links to repository metadata and Pages URL candidates. URLs not returned by those channels enter through normalized imports with provenance. Private repositories can still have public deployments. A zero from one channel is bounded non-observation, especially after failure.

Before initial public discovery, create a persistent `search-plan` from the supplied Korean/English names, aliases, industry terms, function terms, and known URLs. Run its bounded jobs and retain deferred work. Do not substitute a few handwritten queries or report generated candidates as executed searches. Use `tools/idgen.py` only for offline candidates. Platform validators filter invalid names. Similarity is never ownership evidence and does not authorize probing.

Use `brokered_anonymous_browser` only when static observation cannot answer whether content arrived. A fresh Playwright context routes approved GET document/script/stylesheet/XHR/fetch through the policy-bound transport broker without raw browser headers, cookies, auth, or referrer. Service Workers are off; WebSocket server connections are blocked and their messages discarded in a local sink; popups are closed and downloads refused. When DOM review finds no candidate, it also inspects bounded live `input`, `textarea`, and `select` values. Canvas pixels, shadow-DOM content outside the snapshot, JavaScript heap, post-interaction state, external protocols, and unsupported behavior are unmeasured. This is not an OS-firewall or total-egress guarantee. Do not enter credentials, remove DOM gates, solve challenges, enumerate IDs, or use stored sessions. Tests use synthetic fixtures.

## Evidence, remediation, and ledger

Stop after minimum proof. The runtime classifier is provisional: `SENSITIVE_CANDIDATE` or `NOT_INSPECTED`; `PUBLIC_UI` requires separate publication-intent review. A response candidate stops before body rendering; a runtime-state candidate stops further observation. Only human evidence review records real `SENSITIVE_CONTENT_CONFIRMED` in the ledger. `SYNTHETIC_CONTENT_CONFIRMED` is test-canary-only. If personal data or a usable secret appears, stop content collection and escalate. Do not test a discovered secret; live validity is unknown unless an authorized owner-side check provides separate evidence. Preserve `0` and `false` as actual values. Aggregates still require privacy controls and provenance.

Keep raw locators and sensitive artifacts in an access-controlled owner system. Shared output contains masked locations, types, approximate counts, appropriate hash/HMAC references, and evidence IDs. Sanitize query, fragment, userinfo, path, headers, redirects, logs, screenshots, and traces.

For active exposure, decide urgent isolation, secret rotation, and log preservation based on harm while planning service continuity. Keep application authorization behind SSO. Verify the original URL, every known deployment and alias, caches, and authorized archive channels.

Use workflow states `candidate`, `ownership_pending`, `verification_pending`, `open`, `containment_pending`, `recheck_pending`, `partially_closed`, `closed`, and `reopened`. SQLite is the operational source of truth; Markdown is an export. Bind each asset and alias to its opaque locator `target_id` and `policy_id`; the ledger rejects a mismatch. Store append-only observations/events, aliases, controls, proof references, rechecks, and due dates. A current `BODY_SERVED`, unknown/incomplete result, or equal-time conflict after closure reopens or returns the finding to review. Notify on meaningful change, completion, failure, or required operator action.

`search-plan` distinguishes operator aliases from generated variants and keeps unrun work `deferred`; its status remains `PARTIAL` until all required channels are completed or explicitly `not_applicable`. Exact candidate URLs stay in the local locator store, while shared outputs retain only `locator_ref` and handoff state. A ref still requires scope authorization before `probe` or `browser`. `doctor` checks runtime/source parity only: repository changes or a push do not update an already installed runtime.

Report observation-backed facts, controls, owner and severity, unknowns and resolution conditions, containment and due dates, recheck evidence, and omitted actions. Express coverage as exact scopes, channels, and completed pages. Never describe synthetic tests as deployed or live verification.

Supporting files: `ops/discovery.md`, `ops/verify.md`, `ops/triage.md`, `ops/evidence.md`, `ops/remediate.md`, `surfaces/inventory.md`, `assets/ledger-template.md`.
