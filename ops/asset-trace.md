# Static public asset tracing

`trace-assets` follows explicit static asset references from one already approved public HTML document. It is an anonymous, scope-bound GET observation, not a crawl, browser session, or discovery claim. It starts from the supplied `--url`, reads explicit HTML `script` references and JavaScript `fetch(...)` references, and follows only references that the same `--scope` authorizes.

## Run it

Use an unexpired scope whose exact HTTPS origins, path boundaries, owner, and ownership evidence cover the starting URL and every requested asset. Choose a new report path.

```bash
open-detective trace-assets \
  --scope _local/scope.json \
  --url https://app.example.test/public/ \
  --output _local/case/asset-trace.json
```

The default depth is 2; `--max-depth` accepts 1 through 4. The default request budget is the smaller of the scope limit and 20, with a hard cap of 100. The aggregate capture budget defaults to the smaller of `scope.max_bytes * request_budget` and 8 MiB; `--max-total-bytes` cannot exceed 8 MiB. `--max-duration` defaults to 30 seconds and cannot exceed 120 seconds. Redirect requests and their captured bodies count against the same totals. Each response also respects the scope byte limit. Effective values appear in `limits`. There are at most 256 static references per response and 1,000 queued or seen asset URLs; omitted work leaves a coverage gap.

To retain exact final redirect locations privately, supply both locator options:

```bash
open-detective trace-assets \
  --scope _local/scope.json \
  --url https://app.example.test/public/ \
  --locator-store _local/locators.sqlite \
  --scope-id TEAM \
  --output _local/case/asset-trace.json
```

The locator store is local, scope-isolated state. The report receives only an opaque `locator_ref`; an exact location is never copied into its asset or gap rows. Keep the store and report according to the approved evidence-access policy.

## What is followed

The initial HTML response may contribute executable `script src` URLs and inline `fetch` references. A fetched JavaScript response may contribute literal `fetch("/data.json")` or `fetch("/data.json", {method: "GET"})` calls. Other options, computed arguments, aliases, imports, and request libraries are not followed. Comments and quoted text do not become requests; ambiguous JavaScript slash syntax leaves the remaining source unresolved. This is a conservative extractor, not a full JavaScript parser. Relative references resolve in the document context, including references found in an external script; they do not resolve from the script's path. An HTML base URL must pass scope validation. A standalone JavaScript root has no document context, so its relative fetch references remain unresolved. The tracer deduplicates already requested authorized assets and represents the first parent relationship with `parent_asset_id`, `relation`, and `depth`; it is not a complete dependency graph.

It does not execute JavaScript, render a DOM, interact with a page, infer endpoints from bundled/minified code, make dynamic guesses, enumerate path or query variants, replay headers, or use authentication. A reference outside scope, an unsupported reference form, a failed request, or a budget stop is recorded as a gap rather than retried or treated as absence.

## Report and interpretation

The full JSON report is written only to `--output`; stdout contains the compact `{trace_id, assets, coverage}` summary. Top-level fields are `schema_version`, `trace_id`, `observed_at`, `policy_id`, `root_asset_id`, `mode`, `limits`, `usage`, `assets`, `gaps`, `coverage`, and `limitations`.

Each asset records a sanitized `target_ref` and, when configured, an opaque `locator_ref`, plus its parent link, relation, depth, observation identifier and time, access and HTTP observation, capture and analysis completeness, bounded reason, allowlisted content type, captured-byte count, digest, signals, structure, `asset_profile`, and authorized redirects. A partial capture has `analysis_scope: captured_prefix`; even a complete capture describes only the supplied response bytes. The stored locator identifies the last response actually observed, including when a redirect cannot finish. These are a trace report and content-profile hints, not copied response material or proof of sensitivity. A gap has only `parent_asset_id`, `relation`, and `reason`; it intentionally has no URL. When locator options are used, `scope_id` is also recorded and the report can be passed directly to `asset-locations` for a private location export.

`coverage.state` is `complete`, `partial`, or `stopped_sensitive`. `complete` means the declared, bounded static-reference work finished. It does not establish complete page behavior, complete asset discovery, ownership beyond the approved scope evidence, absence of sensitive content, or confidentiality. `partial` retains the applicable reason codes. When a sensitive-content candidate appears, the tracer stops early and records `stopped_sensitive`; do not continue tracing, render the material, or test a secret. An inline client password literal can therefore stop the trace before a later JSON fetch; do not describe this result as having traced a thin gate completely. Escalate through the approved route and use minimal human evidence review before any confirmation.

## Relationship to other commands

`trace-assets` is a separate command and must be invoked explicitly. It does not change `probe` or `browser`: use `probe` for one bounded transport observation, and use the brokered browser only when static observation cannot answer the content question. Neither existing command automatically invokes asset tracing.
