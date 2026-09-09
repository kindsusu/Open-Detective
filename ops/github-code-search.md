# Public GitHub code-search adapter

This optional channel adds repository-scoped file-content search to an existing discovery plan. It does not replace account/repository discovery, generate a second alias vocabulary, download source files, or invoke target measurements. Agent-Reach is not a dependency.

## Enable and run

First complete anonymous public-repository discovery. Choose each public repository explicitly, then add it repeatedly with `--repository OWNER/REPO`. A code job always contains one of these exact `repo:` qualifiers; the runner never performs a token-authenticated global code search.

For a new plan add `--github-code` and one or more repository values to `search-plan plan`. For an existing private plan:

```bash
open-detective search-plan enable-code --plan _local/search-plan.json \
  --repository OWNER/REPO \
  --repository OWNER/SECOND-REPO
```

Enabling is additive and idempotent. Each new code job pairs an existing GitHub search query or operator domain seed with one approved repository. Identity strings remain quoted data and cannot inject qualifiers. The existing query budget determines initially planned code jobs; other jobs remain deferred. Unsupported identity or repository syntax is rejected rather than silently reinterpreted.

Older plans with unrestricted code jobs are retained as migration evidence and deferred with `repository_scope_required`. When scoped jobs are added, those older jobs remain deferred as `superseded_by_repository_scoped_jobs`. Add explicit repositories to create new scoped jobs; do not convert an old unrestricted query into a token-authenticated global search.

A completed selected scope can be run again without making a request. Deferred work resumes only for a recorded transient provider or budget condition, or for an explicit `--resume-query-budget`; unrelated deferred work is never promoted automatically. A plan with an actual missing or invalid repository scope reports that gap without running the fixture control.

`run` and `run-until-budget` remain anonymous account/repository discovery. They do not execute code jobs. Use the explicit, separately credentialed runner:

```bash
open-detective search-plan run-code \
  --plan _local/search-plan.json \
  --token-env DETECT_GITHUB_CODE_TOKEN \
  --control _local/github-code-control.json \
  --locator-store _local/locators.sqlite \
  --output _local/github-code-result-01.json \
  --request-budget 10
```

Provision the named environment variable through the approved credential mechanism. Pass its name, never the token value. No ambient `gh` login, browser session, `GH_TOKEN`, or `GITHUB_TOKEN` is read unless that exact environment variable is explicitly selected. The token goes only to the fixed GitHub code-search endpoint; proxies, redirects, cookies, and text-match snippets are disabled. The private plan is updated in place and may already contain company identity and exact input URLs. Choose a new output filename for each run.

Each invocation anonymously verifies the selected repository's public metadata before it uses the explicit token for that repository-scoped search. This preflight and the fixture control both count toward the total request budget. A repository returned by discovery is still only `ownership_pending`; public repository metadata does not establish company ownership or deployment reachability.

An optional local launcher may capture an existing `gh auth token --hostname github.com` result only in its process memory, pass it as the selected environment variable to `run-code`, and restore the prior process environment in `finally`. This does not create a search-only token, alter its scopes, save a credential, or make the runner read ambient `gh` authentication. The launcher must never print or write the token.

## Positive control

Copy [the control template](../examples/github-code-control.example.json) into the private case directory. Replace every placeholder with a known, indexed, public fixture repository, an exact file path, a benign search term present in that file, and an approved future expiry. The template is expired and cannot run unchanged.

Each invocation first verifies the fixture repository anonymously, then searches for that benign term restricted to the fixture repository with the same token and endpoint. The response must be complete and include valid public metadata for the expected repository/path. The control is a known indexed, non-sensitive file used to confirm the search path is functioning; it is not a company search. Missing credentials make jobs deferred; a failed control leaves scoped company searches unexecuted. A control proves that this specific indexed result was available at that time, not index completeness or unrestricted account access. Injected test responses are marked `synthetic` and `SYNTHETIC_OK`; they never constitute a live control.

This control is separate from the anonymous `channels-doctor` contract. The generic plan importer cannot mark code jobs complete. The code runner owns their attempts and provenance.

## Limits, resume, and interpretation

- At most 10 HTTP requests per invocation, including anonymous public-repository preflights, the fresh token-authenticated control search, and scoped code-search pages. A persisted 60-second per-plan window prevents immediate resumes from resetting this allowance. GitHub account-wide limits may be lower because of other clients; rate-limit responses stop work and preserve a retry timestamp when supplied. The local window is not an account-wide lock: do not run concurrent writers against one plan.
- Responses are bounded to 2 MiB each and 8 MiB in aggregate, with a 60-second run deadline and bounded network timeouts. Only metadata is retained; source bodies and search fragments are not requested or copied.
- GitHub REST code search has indexed/default-branch, file-size, and result-count restrictions. Its documented limits include files smaller than 384 KB, up to 1,000 results per query, and 10 code-search requests per minute. These restrictions mean that finishing a query is never a complete inventory of company code. See [GitHub REST search](https://docs.github.com/en/rest/search/search#search-code).
- A successful page is checkpointed. Rerunning `run-code` resumes budget-deferred work from its next page. `--resume-query-budget N` promotes up to N additionally deferred queries, while `--retry-failed` explicitly retries failures. Index-change or overlapping-page failures restart that query on explicit retry and retain earlier observations.
- Incomplete results, invalid/nonpublic metadata, overlapping pages, changed totals, rate limits, missing pages, and provider caps remain errors or deferred work. A zero result is a bounded search observation only after its control and complete response, never proof of no exposure.

## Reuse existing asset and verification workflows

The result has `scope_id`, `plan_id`, `assets`, safe job summaries, code runs, selected-repository scope counts, opaque repository locator references, `global_search_performed: false`, and limitations. It does not export repository names or query strings in the scope summary. Coverage is `selected_scope_complete` only when all active scoped jobs complete; legacy superseded jobs remain separate migration history. Every file is `ownership_pending`, `NOT_INSPECTED`, with `public_exposure: not_measured`. Repository IDs and blob SHAs are metadata; a blob SHA is not a deployment commit. File identity is stable within the same locator store for a repository/path; multiple queries add evidence references to the same file, and observed revisions remain available. The first parent reference points to the repository's private locator. No repository listing or recursive tree scan is triggered for a code hit.

Resolve exact file locations using the existing command:

```bash
open-detective asset-locations \
  --input _local/github-code-result-01.json \
  --locator-store _local/locators.sqlite \
  --scope-id TEAM \
  --output _local/private-code-locations.json
```

Use the plan's actual scope ID in place of `TEAM`. Confirm ownership and create an executable target scope before handing a location to `probe`, `trace-assets`, or `browser`. Do not pass the search token to those commands. Discovery authentication says nothing about anonymous access to a deployment. Content classification and finding confirmation remain in the existing workflows. This adapter neither reads a discovered file nor discovers deployments hidden within its contents automatically.
