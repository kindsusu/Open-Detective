# Captured application runtime review

Use this separate capability only when the owner explicitly requests execution
of captured application JavaScript. Ordinary anonymous probes, static semantic
review, and inert gate projections retain their existing behavior.

## Inputs and provenance

Pin the primary captured source and each supplied dependency by SHA-256. The
authorization names the case, owner reference, action, and expiry. Use the same
case ledger and record the user's authorization before execution. A source hash
does not prove public access: retain its independent anonymous capture evidence.
Keep source bytes and exact locators private; reports contain only bounded
counts, controlled categories, digests, and coverage states.

Dependencies must be captured separately through the existing scope-checked
anonymous transport. The runtime itself cannot fetch missing dependencies.
Do not add unrelated repository revisions, third-party scripts, stored sessions,
or authentication credentials to make a replay succeed. Missing dependencies
remain explicit gaps. A JavaScript file without its original document is a
script harness, not reproduction of an application.

## Execution boundary

Each review uses a new sandboxed Chromium process and a fresh temporary browser
context. Only the hash-pinned resources are fulfilled locally, either at a
synthetic HTTPS origin or their exact captured HTTPS resource URL. Other requests are blocked; service workers, frames, downloads,
popups and unsupported transports are constrained. No user's browser profile,
cookies, account session, or local file URL is supplied. Execution has a parent
deadline and child-process cleanup. Browser controls are defense in depth, not
an operating-system network isolation or memory-quota guarantee.

Record the initial rendered state before any authorized client-UI reveal. A
local reveal changes the captured DOM and is reported as a separate step; it
does not submit a password or validate a credential. Do not silently stub a
missing library, suppress script failures, synthesize business records, or
invoke arbitrary functions to force a complete result.

## Completion

Keep execution attempted, original scripts executed, DOM rendering observed,
visible business-data signals, blocked dependencies, script errors, timeouts,
and unsupported interactions distinct. Successful startup does not establish
that every event handler or application branch was exercised. A rendered table
can establish local display of captured data; it cannot establish server
authorization, current deployment state, publication approval, customer identity,
or the validity of a discovered secret.

Append runtime results to the original case without rewriting static or visual
observations. Retain unresolved items with their exact cause. Do not claim the
entire organization or all application behavior verified from a finite replay.

## Local command

Install the browser extra and Chromium as described in the README. Save a private
manifest with `input`, `content_type`, `authorization`, optional `resources`,
`reveal_client_ui` (default true), and `max_seconds` (at most 30). Input paths are
resolved relative to the manifest when relative; absolute input paths are also
accepted. `resources` maps synthetic absolute paths such as
`/data.json`, or exact captured HTTPS resource URLs, to
`{ "input": "capture-data.json", "content_type": "application/json" }`.
URL keys are local replay identities, never instructions to fetch. External
response headers are not reproduced; their CORS/CSP semantics remain an explicit
gap even when supplied scripts execute successfully.

Media types are caller-supplied execution metadata, not part of the byte digest.
The capture runner must compare them with the anonymous response evidence and
record any normalization or mismatch; this command alone does not establish
faithful reproduction of the original HTTP response. Authorization fields are
an audit declaration, not a signed approval or an independent public-access proof.

The authorization requires `case_id` (`case_` followed by 32 hexadecimal digits),
`owner_ref`, `action: "execute_captured_javascript"`, a timezone-aware `expires_at`,
`source_sha256`, and `resource_sha256` (a dictionary of every resource
key and its digest; use an empty dictionary when there are none). This records
the owner's actual authorization; do not invent one from a source document.

For a client-only gate whose IDs were verified in the captured source, the
authorization may also contain `client_ui_reveal`, for example
`{ "hide_ids": ["gate"], "show_ids": ["app"], "display": "block" }`.
Each list accepts at most four exact IDs; display is limited to `block`, `flex`,
or `grid`. The action digest records the selection together with the source
digest; it does not authenticate the declaration or prove prior approval. Missing
or ambiguous targets and a gate containing a requested content region remain
explicit gaps. This changes only local DOM visibility, without calling login
handlers or using passwords. Without a custom selection, the original
`login-screen`/`app` convention remains available. Before/after counts and an
action digest distinguish the reveal from the initial rendering. Applying a
display change and observing the requested content as visible are separate
results; content still hidden by an ancestor or stylesheet preserves a gap.

```sh
open-detective runtime-review --manifest _local/case/runtime-manifest.json --output _local/case/runtime-result.json --case _local/case
```

The command rejects symlink/reparse paths and existing output files. The primary
source is capped at 128 MiB, each dependency at 64 MiB, and the combined bundle at
128 MiB with at most 32 dependencies. Exit 0 means the bounded observation
completed; exit 3 preserves a partial/blocked result; exit 2 reports invalid local
input. Always inspect coverage fields: exit 0 never means all application states,
current live deployment, or server authorization were verified.

The optional `--case` verifies the existing case ID against the authorization
before execution and appends a `CAPTURED_RUNTIME_REVIEW` evidence event. It does
not rewrite earlier observations or automatically close an asset finding.
