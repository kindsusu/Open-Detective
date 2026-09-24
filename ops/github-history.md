# Bounded GitHub history review

`github-history` reviews one explicitly named public repository and a fixed UTC commit window. It is not global discovery, proof of ownership, a deployment check, or a reconstruction of the repository's current state.

Create a private local manifest from [`examples/github-history.example.json`](../examples/github-history.example.json). `scope_id` is the locator-store boundary. `owner_ref` is the ownership-evidence record that must match the executable patch target. Manifest expiry limits reuse of the request; it does not replace executable `Scope` authorization.

Metadata mode performs an anonymous public-repository preflight and one GitHub commit-list request. It deliberately does not request the commit-detail API because that response can contain patch text. The shared report records `observed_at` and a branch digest instead of the operator's raw branch expression. A result at `max_commits` is marked truncated because later commits may exist. A zero result remains nonconclusive, and every run records `history_control_not_measured`: the public-repository preflight proves only that the selected repository was public at that observation, not that the history channel was complete.

```bash
open-detective github-history --manifest _local/github-history.json --locator-store _local/locators.sqlite --output _local/github-history-report.json
```

Patch mode additionally requires a current executable scope for the exact `https://github.com/OWNER/REPOSITORY/commit/` path or an exact listed SHA patch path. The matching target's `ownership_evidence` must equal `owner_ref`. Patch retrieval is anonymous and uses only the fixed commit SHA returned by the bounded listing; discovered URLs are never followed. Redirects, non-public DNS answers, non-identity encodings, non-plaintext responses, bad SHA provenance, request limits, byte limits, and time limits stop or leave an explicit gap. The combined metadata and patch response cap is 8 MiB; an individual patch capture is capped at 512 KiB and by the executable scope's smaller byte limit.

```bash
open-detective github-history --manifest _local/github-history.json --scope _local/github-patch-scope.json --inspect-patches --locator-store _local/locators.sqlite --output _local/github-history-report.json
```

Patch source, author headers, paths, URLs, and detected values are never copied to the shared report. A fully captured patch has its byte count and digest recorded for traceability; the digest identifies the observed bytes but does not prove authenticity. Changed files have opaque private locator references, path digests, value-free status and category hints, and `current_repository_state: not_measured`. Introduced and removed URL literals are separate opaque locator lists so a deleted reference is not presented as current. A provisional personal-data, secret, or client-side password signal stops URL collection and all later commit inspection in that run; do not test a discovered value. Classification is heuristic and a clean result does not establish absence of sensitive data. Binary, rename-only, malformed, and analysis-limited patches leave explicit gaps, including mixed binary and text patches.

The locator database is owner-controlled plaintext and can contain exact repository paths or URL literals. Keep it on an access-controlled encrypted volume. Resolve its entries only through an approved private-local workflow and its original `scope_id`; do not publish the database or treat a locator as measurement authority.

The report is limited to the selected repository, branch expression, UTC window, commit cap, captured patches, and observation time. It does not measure force-pushed history, unreachable commits, other refs, Git LFS bodies, submodule contents, binary patch bodies, current file existence, deployments, forks, caches, or server state.
