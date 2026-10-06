# Shared audit workflow

This is the canonical execution contract for Codex, Claude, and CLI operators.
Model versions and reasoning-effort settings are deliberately not fixed here.

## Start and resume

1. Record company seeds, ownership evidence, exclusions, and scope in private local
   inputs. `discovery` starts from those seeds; `recheck` may include known assets.
   Do not open a held-out reference during discovery or feed prior findings into a
   seed-only evaluation. A model's prior memory is not claimed to be erased.
2. Run `doctor --reference .` to check the installed runtime, and fresh channel
   controls before public metadata discovery. Similar names remain candidates.
3. Initialize once; subsequently inspect and resume the same case. Do not create
   another case just because the agent changes. Existing permissions apply to all
   matching discovered assets; ask only for scope or actions that are missing.
4. Execute ready work within explicit budgets, preserving blocked and retry work.
   A candidate in one response is not a reason to stop unrelated assets. Never
   interpret a failed channel, a truncated file, or a missing dependency as clean.
5. Inspect the generated results and gaps. Public access, content sensitivity,
   publication approval, and server authorization are separate determinations.
   UI display alone never proves a server authorization bypass.
6. Export reports from the case ledger. Evaluate held-out references only after
   discovery. Report actual tests and unresolved work; do not claim full-company
   coverage from a finite inventory or claim tests on unexecuted agent hosts.

## Model and independent work

Keep the primary agent's currently selected model unchanged for the task. Do not
switch models just because work is difficult. When available, Sol/Sonnet can do
independent analysis with a clearly stated scope and deliverable. Luna/Haiku fit
bounded extraction, normalization, and counting tasks with explicit inputs and
output fields. The primary agent resolves ambiguity and owns final judgments and
integration. Astra is used only when the user explicitly selects or requests it.
Do not pin model versions or reasoning effort in project adapters.

Public-data research may be assigned as independent work under the same approved
scope and budget. Assignment does not expand authorization, turn a candidate into
an owned asset, or make one worker's result proof of another worker's execution.
Keep workers on disjoint files and jobs; hand off evidence and gaps for integration.

```sh
open-detective audit init --case _local/new-case --intake _local/intake.json
open-detective audit plan --case _local/new-case --profile thorough
open-detective audit run --case _local/new-case --scope _local/scope.json --budget _local/budget.json --channel-health _local/health.json --agent codex
open-detective audit status --case _local/new-case --json
open-detective audit resume --case _local/new-case --scope _local/scope.json --budget _local/budget.json --channel-health _local/health.json --agent claude
open-detective audit worker --case _local/new-case --scope _local/scope.json --budget _local/budget.json --channel-health _local/health.json
open-detective audit report --case _local/new-case --output _local/report.json
open-detective audit evaluate --case _local/new-case --reference _local/held-out.json
```

The adapters run identical Python commands. `--agent` records the worker identity,
not a different decision policy. `plan` inspects the already persisted plan/queue;
it neither reads reference answers nor grants network authority. Resume requires
current scope again; stored ownership does not automatically renew expiry.

## Durable state and resource limits

The case uses the existing `Ledger` SQLite database and private `LocatorStore`.
Audit jobs/results extend that database rather than establishing another findings
database. Events are append-only, lease tokens identify individual attempts, and
expired work can be reclaimed without allowing a stale worker to finish it.

The budget JSON sets `max_requests`, `max_download_bytes`, `max_analysis_bytes`,
`max_seconds`, `max_attempts`, and `max_jobs`. Use explicit values suitable for the
approved scope. Each invocation is a separate approved budget interval. Request
and capture reservations are pessimistic, made before transport, and retained on
crash. They count redirects and retries. Actual capture sizes remain observations;
reservations are not reported as downloaded bytes. A retry must reserve a new
attempt, because a crashed request cannot be assumed not to have occurred.

Ready work is processed until the interval ends or there is no eligible work.
`retry_wait`, `blocked_scope`, `blocked_input`, failures, and partial analysis remain
visible and prevent an overall complete claim. Use the saved due time for a later
resume. The CLI does not install a service, launch itself later, or make the model
wake after the chat closes. A caller may keep resuming explicitly approved
intervals; never expand scope or budgets automatically.

`audit worker` is a foreground process that waits for eligible retries within the
same approved time interval and budget. It does not renew either. Interrupt it
normally to checkpoint the current job. `run` and `resume` return when no work is
currently eligible and report the next retry time instead of waiting.

The case directory contains private seeds/locators. Store it on an owner-controlled
volume and keep it out of Git. Raw response bodies stay transient; reports hold
sanitized classifier output and opaque references. Do not paste source, secrets,
unmasked personal values, or uncontrolled screenshots into tool output.

Discovery derives bounded identifier prefixes from supplied seed spellings and
records their derivation. A derived prefix is a search aid, not ownership evidence;
similar names remain candidates until independently supported. Search plans retain
per-job state and error information. Retry only errors classified as transient or
explicitly selected for retry, within a newly approved interval and its budget.
Keep permanent failures, blocked inputs, and retry-wait work visible; do not turn
an error into a clean result or silently retry unchanged missing inputs.

When a persisted seed plan is upgraded to version 2, migration adds missing-prefix
jobs idempotently and retains completed jobs. For a previously successful capture
with no `engine_review_version`, schedule one engine review under the current scope
and budget using the `engine-review:2:asset` deduplication key. Resuming the same
engine-review version must not fetch the asset again.

For an authorized repository candidate, the common audit may request up to five
commits (`per_page=5`) from the observed branch within the current scope and budget.
Queue a `repository_tree` job for each observed commit SHA that is eligible under
that same scope. Record `history_window_not_exhaustive`: this bounded recent window
does not establish exhaustive history coverage, inspect every past revision, or
recover deleted content. Do not increase scope or budget automatically.

## Content and gates

Inspect visible/hidden text, structured values, business tables, executable source
references, and supported documents. Actual values, templates, calculations, and
mere field names must stay distinguishable. Counts are occurrences unless a
specific unique-record count has actually been measured. Bounded static JSON
literals in JavaScript can contribute structural and category summaries; reports
must not expose raw literal values, and malformed or truncated input remains
incomplete. Literal document references may be queued for separately authorized
inspection; a reference alone does not establish that its document was retrieved
or reviewed.

PDF analysis records pages examined, per-page text/image state, and OCR state.
Image-bearing or text-empty pages can be marked `ocr_not_run`; this workflow does
not itself run OCR. Inline base64 image data can be separated from the analysis
projection while streaming, leaving other captured bytes available for analysis.
The original response is received only within the approved capture limit and kept
transient; the projection is capped at 4 MiB and is not the original capture. An
omitted image remains an explicit media/OCR gap. The default capture limit remains
256 KiB. An explicit `max_bytes` setting may raise it up to 128 MiB, but this never
widens the approved scope or budget automatically. Do not claim image review or OCR
coverage from text extraction or projection alone.

The gate parser is bounded to 4 MiB. If the original response exceeds that bound,
retain an explicit gap instead of implying that the entire response was parsed.

Keep capture, text/analysis, structure, media, gate, sensitivity, publication
approval, and server authorization as separate review dimensions. `NOT_INSPECTED`,
`not_applicable`, partial, and unverified states must remain distinguishable.
`case_status.complete` describes bounded scheduled work only: queue work is complete,
no search-plan work remains, and latest targets have no recorded gaps and complete
capture and analysis. It does not establish company-wide coverage, publication
approval, gate execution, OCR, or server authorization. Report these dimensions and
their gaps separately; never infer an overall review-complete state from one flag.

The anonymous `probe`/`browser` contract remains unchanged. The separate
`gate-review` capability describes already delivered content and an isolated
replay only when the exact target and capability are authorized. Read
`gate-review.md` before use; do not imply that arbitrary gates were executed or
that historical gate state was integrated. Never reuse a discovered value against
another service or treat a client gate as server authorization. A denied server
response requires separately authorized test conditions, not guessed credentials.

## Handoff and completion

Hand off case path, last run ID, current states, evidence references, and remaining
gaps. Do not duplicate completed requests to reconstruct a narrative. Scope-blocked
targets can be unblocked only after current scope authorizes the exact locator.
Input-blocked reviews require a real resolution; reporting alone is not completion.
Independent workers must own disjoint files and jobs. Synthetic regression results
must be labeled synthetic and not described as live verification.

## External discovery channels

GitHub metadata runs inside the audit coordinator. Other supported discovery
channels use the existing `channel-discover` command with an operator-configured
provider/export endpoint and fresh channel controls. They are not silently treated
as searched when a connector is unavailable. Use the case's `locators.sqlite` as
`--locator-store`, and bind the configuration to the exact work ID/query in its
private `search-plan.json`. Then import the resulting live report:

```sh
open-detective audit import --case _local/new-case --input _local/channel-report.json --channel-health _local/health.json
```

Import verifies the query, health provenance, counts, and every case-scoped opaque
locator before writing. It retains partial channel gaps, queues candidate captures
without granting ownership/scope, and is safe to repeat after interruption. Resume
reconciles completed channel reviews and inspects candidates authorized by the
current scope. Reports marked synthetic are rejected by the production import
path. Imported reports are operator-supplied evidence, not an independently
attested live execution: local metadata can be edited. This limitation is included
in the report. Older observations cannot overwrite newer channel status.
External channel requests have their own explicit scope/budget and are not counted
as requests made by the audit run. Run one discovery coordinator per case; stop it
before imports or other search-plan mutations. Capture jobs still use atomic leases.
