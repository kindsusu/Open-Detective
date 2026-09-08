# Discovery and inventory procedure

Discovery produces provenance-bearing candidates. It does not establish ownership or authorize requests.

## Owner inventory first

Use explicitly authorized read-only owner APIs or exports in a credential-separated process (`SUD-R09`). Record provider, account/team scope, API version, retrieval time, credential identity reference, permissions, cursor/page, time filter, rate-limit state, truncation flag, and completion.

For Vercel collect teams → projects → deployments → aliases/domains and protection metadata. Follow deployment cursors through the requested retention window; distinguish production domain, project alias, branch/preview alias, and immutable deployment URL. Protection settings are metadata to verify, not proof of anonymous denial.

For GitHub the implemented collector lists repositories for an organization or the exact authenticated account and optionally inspects recursive tree completeness. Follow validated `Link` pagination. If a tree response is truncated, store the gap; this collector does not infer completeness from the partial tree. The separate anonymous `github-discover` channel derives conventional Pages URL candidates from public repository metadata. Owner deployment environments and exact private-source/custom-domain Pages inventories still require owner-provided normalized records. Repository visibility and deployment visibility are independent; a private repository can publish a public site.

For page inventories, retain page URL, parent project/deployment, source commit when available, alias relationship, and owner evidence. “Page complete” means all provider pages/cursors in the declared scope completed without unresolved permission, rate-limit, truncation, or time-window gaps.

## Provenance imports

Normalized JSON imports require these concepts even when field names differ:

```text
source, retrieved_at, owner_scope, locator, relationship,
ownership_evidence, completeness, cursor_or_page, source_record_id
```

Reject or quarantine rows without a source and retrieval time. Keep source record IDs for deduplication. Do not treat zero rows as complete unless the producer states a successful bounded query and its end condition. Imported credentials or secret-bearing URLs must be redacted before shared output.

## Public discovery

Supplement owner inventory with approved seeds across public repositories, search engines, CT, DNS records, archives, public storage metadata, document/share indexes, and known hosting platforms. The current `discover` command imports operator-collected normalized JSON and does not crawl or query these channels. Each imported record carries query/source channel, observation time, pagination/completeness, and limitations. Search indexes and archives are delayed and incomplete. Separately, `channel-discover` supports only bounded Cert Spotter CT and operator-configured query-bound JSON exports; it is not a general crawler or native web/document search. See [discovery-optimization.md](discovery-optimization.md).

Use exact public links found in owned metadata before generating names. Shared IPs, favicon similarity, naming resemblance, certificate adjacency, and reverse-IP output are graph edges with confidence, not ownership. Reapply CT/DNS/search to newly confirmed owned hosts without expanding to unrelated tenants.

```bash
python tools/idgen.py --ko "<name>" --en "<official Latin spelling>" --industry "<term>"
python tools/idgen.py --en "<name>" --targets github --limit 100
```

The generator is offline. Validate candidates with the platform-specific namespace rules and route them to ownership review. Candidate volume never authorizes mass scanning.

## Scheduling and output

Keep exploration budget for disconnected brands/teams while prioritizing high-evidence graph neighbors. A useful scheduling heuristic can consider ownership confidence, possible impact, freshness, information gain, request cost, and privacy cost, but must not be presented as a proven probability model.

Write candidates to the ledger with `workflow=candidate` or `ownership_pending`. Promote to `verification_pending` only when an exact scope grant and ownership evidence exist. Record unsupported channels as failures/unknowns; do not silently drop them.

## Private locator handoff and bounded plans

Keep an exact candidate URL only in an owner-controlled local locator store. Shared discovery records use an opaque `locator_ref` plus `handoff_state`: `ready` means the local store contains the exact locator; `blocked` means no measurement target is available. Resolving a ref does not authorize a request. `probe` and `browser` reapply the exact scope before connecting, and `locators bind` records the approved ref as an asset `target_id` with the current `policy_id`.

`search-plan` records distinct operator-supplied aliases and generated variants. It preserves unrun work as `deferred`; `PARTIAL` remains the status until every required channel is completed or explicitly `not_applicable` with a reason. `COMPLETE` is only declared-plan coverage. Inventory imports may use the same private-store/handoff pattern via `--locator-store`; inventory metadata is never a measurement grant.

## Anonymous GitHub metadata discovery

Before a real anonymous GitHub run, execute `python -m sudetect channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json [--previous _local/channel-health.previous.json]`. The config is local operator input and its control URLs still require executable scope; it grants no additional network access. `github-discover` and `search-plan run` require a fresh report. Repository listing requires `github-repositories`; a search seed requires `github-repositories`, `github-user-search`, and `github-repository-search`, because either search can expand into repository listing. A healthy channel does not imply health for the others or complete company discovery.

Each valid-config/scope run stores `OK`, `DEGRADED`, or `DEAD`, measurement time, expiry, minimum observation evidence, and no copied control body. `OK` requires HTTP 200, complete capture, and an expected JSON-pointer or body marker match; prefer a specific JSON-pointer identity because generic body markers can false-positive. `DEAD` includes an unreachable control and HTTP 404/410. The report is checked local operational evidence, not an electronic signature, remote attestation, or a boundary against local-file modification. Imported plan results require the control named by each external channel (`web`, `documents`, or `certificate_transparency`) to be valid at that job's `observed_at`; later expiry does not invalidate an already valid historical import. Stored health provenance contains only validated opaque control identifiers and times, never policy text. Synthetic fixtures do not validate a live channel.

GitHub control IDs must match the `api.github.com` endpoint family: `github-repositories` uses `/repos/<owner>/<repo>` or `/users|orgs/<owner>/repos`; `github-user-search` uses `/search/users`; and `github-repository-search` uses `/search/repositories`, each search with nonempty `q`. A generic public marker on another endpoint cannot substitute. Detail API controls proxy only the core repository family and do not establish pagination or permission coverage.

`python -m sudetect github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json` queries public repository metadata without credentials. Optional `--seed` searches users and repositories; `--known-url` derives an account/repository from a supplied GitHub or GitHub Pages link. Once an account is known, list its public repositories even if web search returned nothing. Read repository names, `has_pages`, and homepage metadata, and produce conventional Pages URL candidates. A candidate URL is not an observed deployment; custom domains and private-source Pages can remain missing.

The collector validates pagination and enforces request, time, response-size, account, and result budgets. Output includes methods executed, provenance graph, per-channel coverage and errors. `COMPLETE` applies only to those bounded metadata channels, never all company assets. Inputs and resulting identifiers belong in ignored `_local/`. Preserve separate tests for independent discovery from names and expansion from supplied URLs: feeding a missed URL back into discovery does not prove it could previously have been found.

An unresolved account hypothesis, failed API call, truncated search, or missing browser measurement must remain a coverage gap. Record known-example recall separately from sensitivity classification precision. Re-run anonymous observation only for exact authorized URLs; never automatically probe every generated deployment candidate.

The optional locator store is plaintext SQLite. Keep it on an owner-controlled encrypted volume with restricted permissions; its opaque references do not encrypt the underlying URLs. Local search manifests contain input names, queries, and public repository metadata and must not be published as masked reports.

## Pagination and negative observations

GitHub may return a numeric user-ID collection in its next-page Link. The anonymous collector accepts that transition only when every current repository row identifies the requested login with the same positive owner ID and the next URL matches that ID. Host, query filters, and the exactly increasing page number remain fixed. An account-expansion cap does not discard already returned repository candidates; deferred account work remains recorded.

An initial exact account/repository 404 is `not_found_observed`, a completed bounded metadata observation. It does not prove that the resource does not exist or that an organization has no other account. A search-endpoint 404 or a 404 on a later page remains incomplete. A 403 with explicit rate-limit headers and a 429 are `RATE_LIMITED`; other 403 responses are `ACCESS_DENIED`. Neither is a completed zero-result search.

Protocol references: [GitHub pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api), [GitHub REST troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api).

## Resuming discovery with explicit budgets

A normal `search-plan run` processes planned work under a total request budget (default 20) and a per-job cap (default 6). Exact supplied URLs run first. Full identity, industry-context, and function-context query families alternate while preserving order inside each family; short or broad terms and search-discovered account expansion remain later. Eligible queries alternate one-for-one with identity-account candidates. This is a bounded heuristic, so a full spelling can be delayed; it does not establish exhaustive or optimal recall. A query that reaches its cap remains incomplete. Increase `--per-job-request-budget` for a deliberate deeper retry, up to 30.

```bash
python -m sudetect search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --per-job-request-budget 6 --max-batches 30 --channel-health _local/channel-health.json
python -m sudetect search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --retry-failed --request-budget 20 --per-job-request-budget 10 --channel-health _local/channel-health.json
python -m sudetect search-plan status --plan _local/plan.json
```

`run-until-budget` requires an explicit total budget and also considers deferred GitHub jobs. Ordinary `run` does not implicitly promote existing deferred work; use `run-until-budget` or explicit `--resume-query-budget` / `--resume-account-budget` instead. `--retry-failed` selects failed work separately. Each selected job runs at most once in one invocation. A search result can report a newly found account expansion with `REQUEST_LIMIT_EXCEEDED` even though that expansion made exactly zero requests, pages, and items. That narrow, fully numeric zero marker is deferred as unobserved durable work and can be selected by an explicit deferred resume; its provider batch remains the provenance and no synthetic attempt is added. The originating search may independently be partial or failed and retains that evidence. A marker with any actual request, missing/malformed count, or boolean count remains a failure. Existing completed or failed account evidence is never rewritten by this marker; retry an older failed record explicitly with `--retry-failed`. Every batch is checkpointed atomically. Per-job attempts and raw batch metadata remain in the private plan; aggregate totals must match them. Status describes current job evidence and retained unresolved expansions, with a separate next-work reason. Past failures stay in history. Older partial/failed plans without per-job evidence retain a legacy coverage gap. Preserve them as history and create a fresh version-2 plan from the same identity inputs; a partial retry or arbitrary import cannot erase that gap. A completed declared plan still cannot prove exhaustive Internet discovery.
