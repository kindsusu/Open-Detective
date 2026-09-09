# Public GitHub code-search adapter

This optional channel adds file-content search to an existing discovery plan. It does not replace account/repository discovery, generate a second alias vocabulary, download source files, or invoke target measurements. Agent-Reach is not a dependency.

## Enable and run

For a new plan add `--github-code` to `search-plan plan`. For an existing private plan:

```bash
open-detective search-plan enable-code --plan _local/search-plan.json
```

Enabling is additive and idempotent. Code jobs reuse the existing GitHub search-query jobs and operator domain seeds; domains are first, and the existing query order retains narrow names before broad terms. Identity strings are quoted as data, followed by `in:file is:public`. They cannot inject qualifiers. The existing query budget determines initially planned code jobs; other jobs remain deferred. Unsupported identity syntax is rejected rather than silently reinterpreted.

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

Provision the named environment variable through the approved credential mechanism. Pass its name, never the token value. No ambient `gh` login, browser session, `GH_TOKEN`, or `GITHUB_TOKEN` is read unless that exact environment variable is explicitly selected. The token goes only to `https://api.github.com/search/code`; proxies, redirects, cookies, and text-match snippets are disabled. The private plan is updated in place and may already contain company identity and exact input URLs. Choose a new output filename for each run.

## Positive control

Copy [the control template](../examples/github-code-control.example.json) into the private case directory. Replace every placeholder with a known, indexed, public fixture repository, an exact file path, a benign search term present in that file, and an approved future expiry. The template is expired and cannot run unchanged.

Each invocation first searches for that term restricted to the fixture repository with the same token and endpoint. The response must be complete and include valid public metadata for the expected repository/path. Missing credentials make jobs deferred; a failed control leaves company searches unexecuted. A control proves that this specific indexed result was available at that time, not index completeness or unrestricted account access. Injected test responses are marked `synthetic` and `SYNTHETIC_OK`; they never constitute a live control.

This control is separate from the anonymous `channels-doctor` contract. The generic plan importer cannot mark code jobs complete. The code runner owns their attempts and provenance.

## Limits, resume, and interpretation

- At most 10 search requests per invocation, including the fresh control. A persisted 60-second per-plan window prevents immediate resumes from resetting this allowance. GitHub account-wide limits may be lower because of other clients; rate-limit responses stop work and preserve a retry timestamp when supplied. The local window is not an account-wide lock: do not run concurrent writers against one plan.
- Responses are bounded to 2 MiB each and 8 MiB in aggregate, with a 60-second run deadline and bounded network timeouts. Only metadata is retained; source bodies and search fragments are not requested or copied.
- GitHub REST code search has indexed/default-branch, file-size, and result-count restrictions. Its documented limits include files smaller than 384 KB, up to 1,000 results per query, and 10 code-search requests per minute. These restrictions mean that finishing a query is never a complete inventory of company code. See [GitHub REST search](https://docs.github.com/en/rest/search/search#search-code).
- A successful page is checkpointed. Rerunning `run-code` resumes budget-deferred work from its next page. `--resume-query-budget N` promotes up to N additionally deferred queries, while `--retry-failed` explicitly retries failures. Index-change or overlapping-page failures restart that query on explicit retry and retain earlier observations.
- Incomplete results, invalid/nonpublic metadata, overlapping pages, changed totals, rate limits, missing pages, and provider caps remain errors or deferred work. A zero result is a bounded search observation only after its control and complete response, never proof of no exposure.

## Reuse existing asset and verification workflows

The result has `scope_id`, `plan_id`, `assets`, safe job summaries, code runs, and limitations. Every file is `ownership_pending`, `NOT_INSPECTED`, with `public_exposure: not_measured`. Repository IDs and blob SHAs are metadata; a blob SHA is not a deployment commit. File identity is stable within the same locator store for a repository/path; multiple queries add evidence references to the same file, and observed revisions remain available. The first parent reference points to the repository's private locator. No repository listing or recursive tree scan is triggered for a code hit.

Resolve exact file locations using the existing command:

```bash
open-detective asset-locations \
  --input _local/github-code-result-01.json \
  --locator-store _local/locators.sqlite \
  --scope-id TEAM \
  --output _local/private-code-locations.json
```

Use the plan's actual scope ID in place of `TEAM`. Confirm ownership and create an executable target scope before handing a location to `probe`, `trace-assets`, or `browser`. Do not pass the search token to those commands. Discovery authentication says nothing about anonymous access to a deployment. Content classification and finding confirmation remain in the existing workflows. This adapter neither reads a discovered file nor discovers deployments hidden within its contents automatically.
