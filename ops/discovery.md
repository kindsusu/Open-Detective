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

Supplement owner inventory with approved seeds across public repositories, search engines, CT, DNS records, archives, public storage metadata, document/share indexes, and known hosting platforms. The current `discover` command imports operator-collected normalized JSON and does not crawl or query these channels. Each imported record carries query/source channel, observation time, pagination/completeness, and limitations. Search indexes and archives are delayed and incomplete.

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

`python -m sudetect github-discover --scope-id TEAM --account approved-account` queries public repository metadata without credentials. Optional `--seed` searches users and repositories; `--known-url` derives an account/repository from a supplied GitHub or GitHub Pages link. Once an account is known, list its public repositories even if web search returned nothing. Read repository names, `has_pages`, and homepage metadata, and produce conventional Pages URL candidates. A candidate URL is not an observed deployment; custom domains and private-source Pages can remain missing.

The collector validates pagination and enforces request, time, response-size, account, and result budgets. Output includes methods executed, provenance graph, per-channel coverage and errors. `COMPLETE` applies only to those bounded metadata channels, never all company assets. Inputs and resulting identifiers belong in ignored `_local/`. Preserve separate tests for independent discovery from names and expansion from supplied URLs: feeding a missed URL back into discovery does not prove it could previously have been found.

An unresolved account hypothesis, failed API call, truncated search, or missing browser measurement must remain a coverage gap. Record known-example recall separately from sensitivity classification precision. Re-run anonymous observation only for exact authorized URLs; never automatically probe every generated deployment candidate.

The optional locator store is plaintext SQLite. Keep it on an owner-controlled encrypted volume with restricted permissions; its opaque references do not encrypt the underlying URLs. Local search manifests contain input names, queries, and public repository metadata and must not be published as masked reports.
