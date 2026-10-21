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
Do not add unrelated repository revisions, unapproved third-party scripts,
stored sessions, or authentication credentials to make a replay succeed. An
explicit request to validate a referenced public library may authorize capture
of that exact versioned HTTPS resource under a separate dependency scope.
Record the reference, request, digest, media type, and dependency purpose; do
not classify the CDN as an organization-owned asset or crawl adjacent versions.
Missing dependencies
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

Date-dependent UI may be tested with a separately declared fixed browser clock
and timezone. Preserve the real-time baseline and label each before/during/after
scenario as a simulated-time fixture. A successful simulated display establishes
the captured program's behavior under that fixture; it does not prove that the
content was publicly deployed or viewed at that historical time.

## Completion

Keep execution attempted, original scripts executed, DOM rendering observed,
visible business-data signals, blocked dependencies, script errors, timeouts,
and unsupported interactions distinct. Successful startup does not establish
that every event handler or application branch was exercised. A finite sequence
of declared UI actions can verify only its recorded expectations. Keep observed
script functions and execution ranges separate from semantic branch coverage;
zero-count ranges and unmapped UI paths remain explicit work. A rendered table
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
Synthetic paths may include canonical UTF-8 percent-encoded filenames and a
fixed query string. Bind the exact browser request key; query variants are not
wildcards. Invalid encodings, path traversal, and reserved document paths are
rejected.
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

## Declared UI scenarios

The authorization may include `ui_steps`, a sequence of at most 12 actions.
Use exact, unique `target_id` values observed in the captured document. For a
`click` on an ID-less button, `target_button_class` may instead name one exact
CSS class token. It must match exactly one button with no associated form;
arbitrary selectors and submission buttons are rejected. The source digest
binds this declaration to the reviewed capture. Supported actions are `click`, `select` with an existing option `index` (0–100), `check`
with `checked`, `fill` with a synthetic `TEST_`-prefixed value, and `wait` with
`milliseconds` (1–2000). Credential targets, password inputs, submission, file
uploads, and arbitrary JavaScript/function calls are not supported. Target
checks constrain the declared action, but do not sandbox the original handler
or guarantee that a script cannot mutate the DOM between inspection and a
browser click. The execution boundary remains the isolated context, absent
credentials, blocked uncaptured traffic, and parent deadline.

Each step may require `expect_visible_ids` (up to four IDs),
`expect_dom_change: true`, or `expect_png_download: true`. Record action applied,
expectation satisfied, observable transition, execution coverage, and errors
separately. A previously visible target does not establish that a click caused
a transition. Form-control state changes are recorded separately from changes
outside form controls, so a select/check/fill action alone cannot establish an
application response. Selecting one existing option does not test every combination.
Partition longer scenarios into independent fresh runs and retain their setup
requirements rather than silently carrying browser state across runs.

`observe_png_download: true` authorizes inspection of generated local PNG
downloads. Only the synthetic origin's blob URLs and PNG data URLs are accepted.
The engine accepts at most four downloads per run, cancels downloads observed
above 8 MiB, and stops the worker if temporary download storage exceeds 32 MiB.
Progress events and storage polling can allow transient overshoot; these are
not operating-system disk or memory quotas. It checks PNG chunk structure and
CRCs and records dimensions, byte count, and SHA-256, without decoding image
pixels. It deletes temporary output, including after parent timeout.
PNG structure verification is not visual-content verification. An expected export
may wait up to five seconds within the overall 30-second deadline.

`allow_local_render_frames: true` permits local blank/srcdoc rendering frames
used by captured libraries; external document navigation stays blocked. Keep it
off for scenarios that do not need local rendering frames. `viewport` can specify
width 320–1920 and height 240–2160 for distinct desktop/mobile scenarios.

For time-dependent fixtures, `clock_time` must be a timezone-aware ISO timestamp
between years 1900 and 2100. Declare `timezone_id` explicitly when local calendar
interpretation matters. The browser clock fixture is reported separately from
capture time; real timers and the parent execution deadline remain bounded.

Completed step evidence survives a later timeout. Observed function/range counts
describe instrumented execution, not exhaustive semantic branch coverage. Keep
external-header gaps, blocked requests, unsupported interactions, and unexecuted
scenarios visible even when the selected assertions pass.

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
