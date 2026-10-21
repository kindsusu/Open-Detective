# Visual and semantic follow-up

Use this follow-up after an owner explicitly requests review of remaining visual
or structural gaps. Keep the same case, exact selected revisions, current scope,
and anonymous-access evidence. A successful OCR run or lexical scan does not
complete this review.

## Image review

Collect only images already linked to the selected captured files, including
inline images. Deduplicate by the full image digest while retaining every parent
file and revision reference. A duplicate image review can be reused only for the
same bytes. Decode within pixel and byte limits; do not execute SVG scripts or
follow external resources. Retain failed decodes and omitted frames explicitly.

Use private, numbered contact sheets for triage and inspect individual images
at adequate resolution when text or detail is unclear. Record which image IDs
were actually viewed, the evidence digest, reviewer, observation time, category,
and remaining uncertainty. Do not infer publication approval from a product
photograph, or infer absence of metadata, QR codes, or hidden content from a
visible thumbnail. Screenshots and source values stay out of shared reports.

## Structure and runtime review

Distinguish valid JSON, supported static JavaScript literals, unsupported dynamic
expressions, malformed source, and resource limits. Never execute expressions to
make a static parser report complete. Field counts describe captured data fields,
not customers, transactions, vehicles, or records unless that unit was separately
established. An expression or external dependency remains unverified.

`sudetect.semantic_review.review_semantic_source` reviews already captured UTF-8
JSON, HTML, or JavaScript in a separate, time-limited process. It returns only
categories, counts, and explicit incomplete reasons. JSON traversal can inspect
up to 500,000 nodes, with a 128-level depth limit; unsupported content types and
non-finite numbers cannot be reported as complete. Input and traversal limits
are not an operating-system memory quota.

For HTML and JavaScript, `source_structure_complete` describes the supported
static subset only. DOM proximity counts are lexical candidates, including
possible comments or strings; `lexical_scan_complete` is not control-flow or
runtime validation. `original_script_executed` and `runtime_flow_verified` remain
false. Never use lexical completion as an overall case-completion condition.

Use [offline gate review](gate-review.md) for its supported isolated projections.
Record the exact response digest and whether the original DOM and scripts were
replayed. A sanitized projection proves local display of already delivered data;
it does not validate the original application, backend authorization, or a live
credential. Unknown original scripts are not implicitly authorized by a static
analysis result. Do not follow newly discovered endpoints without scope review.

## Evidence and completion

Append value-free review evidence to the existing case ledger. Preserve the
original automated result and connect any narrower resolved gap to the same
file/image digest. Report visual inspection, static structure, supported local
replay, server authorization, and publication intent as separate dimensions.
Historical anonymous file access proves exposure of that revision at observation
time; it does not prove the same content is currently deployed. Unresolved
dimensions remain visible even when every supported analysis has run.
