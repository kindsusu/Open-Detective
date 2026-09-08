# Bounded discovery adapters and offline evaluation

The discovery adapters extend the existing provenance-import workflow; they do not make a candidate owned or authorize target measurement. Public channel work still needs an exact executable `--scope`, fresh channel-specific health, a bounded local config, and an owner-controlled locator store. The resulting opaque `locator_ref` still needs ownership evidence and a new scope decision before `probe` or `browser` can connect.

`channel-discover` currently supports two bounded adapters only. `certspotter` handles certificate-transparency names as ownership candidates. `generic_json_export` consumes an operator-configured, query-bound JSON search or export endpoint; it does not claim native web or document search coverage. Both record provider, channel, source, query work ID, observation time, requests, pages, end condition, partial/error state, health provenance, and opaque candidate references. They never copy exact candidate URLs to shared output.

```bash
open-detective channel-discover --config _local/channel.json --scope _local/scope.json --channel-health _local/channel-health.json --locator-store _local/locators.sqlite --output _local/channel-result.json
open-detective channel-discover --config _local/channel.json --scope _local/scope.json --channel-health _local/channel-health.json --locator-store _local/locators.sqlite --output _local/channel-result.json --plan _local/search-plan.json --import-output _local/search-plan-import.json
open-detective discovery-eval --input _local/evaluation.json --output _local/evaluation-result.json
open-detective asset-graph --input _local/asset-records.json --previous _local/asset-graph.previous.json --output _local/asset-graph.json
```

The channel config is versioned local operator input. It declares one provider (`certspotter` or `generic_json_export`), a permitted channel (`certificate_transparency`, `web`, or `documents`), opaque source ID, query work ID/value, endpoint shape, required expected control IDs, and hard request/page/body/candidate limits. The run accepts health provenance only when it matches a declared expected control ID. A provider result with zero rows is not complete unless its declared end condition and coverage support that conclusion. Failed, stale, or partial channels remain gaps and can be imported into a search plan as such.

The report's `search_plan_import` keeps only safe health provenance. When both `--plan` and `--import-output` are supplied, `channel-discover` verifies the live report against the exact private-plan work ID, query digest, and health at `observed_at`, then writes a private import payload with the complete health report. Synthetic reports cannot produce that payload. Pass the payload to the existing private plan-import workflow; do not assemble one manually.

`discovery-eval` is offline. Its versioned dataset fixes candidate IDs, costs, order, declared train/test split, family labels, known positives, known false positives, and unlabeled unknowns. It compares baseline and proposed ordering at the same budget, reports recall@budget and precision only against labeled positives/known false positives, and reports unknowns separately. It is an evaluation artifact, not proof of company discovery, ownership, channel health, or live recall. Include wrong-company and similar-name negatives; no evaluator result may automatically confirm ownership.

An asset graph reconciles owner-provided CMDB, cloud, and IdP snapshots with normalized discovery records. It must retain snapshot provenance, explicit ownership references, relationship edges, diffs, and scope-completion gaps. An absent source, cursor gap, permission failure, or incomplete export remains a gap rather than a negative asset claim.
