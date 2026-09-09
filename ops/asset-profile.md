# Local asset profiling

`asset-profile` is an offline, value-free review of files that have already been captured under the appropriate approval process. It never fetches a locator, sends a request, or proves that an asset is publicly or anonymously reachable. Use it to organize a local review queue; keep reachability measurement and finding confirmation as separate steps.

## Run it

Place a manifest and any approved local captures in the same owner-controlled directory, then choose new output names. Outputs are created exclusively: the command refuses an existing output, a symlink, an unsafe input, or an input/output collision.

```bash
open-detective asset-profile \
  --input _local/case/assets.json \
  --output _local/case/asset-profile.json \
  --markdown _local/case/asset-profile.md
```

The command prints only the number of declared assets and the number locally analyzed. The JSON report contains `version`, `assets`, `profile_input_omitted_asset_count`, `profile_coverage`, and `limitations`; a native inventory also preserves its valid `scope_id` and a compact `source_coverage` (`state`, `error_count`). `--markdown` is an optional compact table of the per-asset results. It never emits raw values, field names, local paths, or URLs.

## Manifest

The simple input is a JSON object with exactly one `assets` array. Every row has a unique `asset_id`; `parent_asset_id` can describe an already known parent relationship. `locator_ref` is optional and, when present, must be an opaque `opaque:<32-hex>` or keyed `hmac-sha256:<64-hex>` reference rather than a URL. `local_file` is optional; it is a relative, regular file below the manifest directory. Start with [examples/asset-profile-input.example.json](../examples/asset-profile-input.example.json); its companion shape is [schemas/asset-profile-input.schema.json](../schemas/asset-profile-input.schema.json).

```json
{
  "assets": [
    {
      "asset_id": "pricing-export",
      "parent_asset_id": "sales-tool",
      "kind": "data_file",
      "locator_ref": "opaque:0123456789abcdef0123456789abcdef",
      "content_type": "application/json",
      "local_file": "captures/pricing-export.json"
    },
    {
      "asset_id": "sales-tool",
      "kind": "webpage"
    }
  ]
}
```

Allowed row fields are `asset_id`, `parent_asset_id`, `kind`, `locator_ref`, `content_type`, and `local_file`. Parent IDs must be declared in the same manifest and cannot form a cycle. An existing offline inventory report with `inventory_id` can also be supplied directly: its `contains` edges become parent relationships; asset ID, kind, locator reference, and strictly validated safe file metadata are carried into the profile. Its declared coverage state and error count become `source_coverage`. The simple manifest is limited to 100 assets and 1 MiB; an individual local capture is examined only up to 256 KiB. A larger native inventory is bounded to 100 represented assets while retaining valid displayed parent relationships.

## Interpreting the report

Every asset has `exposure: NOT_ESTABLISHED_BY_LOCAL_ANALYSIS`. For a native inventory, `source_coverage` records only the source report's declared coverage state and error count; it neither validates the source nor fills its gaps. For an inventory larger than the bound, `profile_coverage: partial` and `profile_input_omitted_asset_count` identify that not every inventory asset is represented; otherwise profile coverage is `complete`. A row with no `local_file` is `NOT_INSPECTED` and needs authorized capture or separate reachability measurement. A locally supplied file becomes `LOCAL_CONTENT_ANALYZED`, with a next action to measure authorized reachability separately.

`content_profile.asset_kind_hint` is a structural hint such as `data_file`, `webpage`, `dashboard`, `calculator`, `source_code`, or `unknown`. `business_data_categories` lists candidate category labels and their evidence basis, for example structured field names, markup attribute names, markup text labels, or source text terms. It omits values and reports candidate and filled-field counts only. A category is not proof that protected data, a secret, or confidential business content exists.

Native inventory rows can additionally carry `asset_metadata`: an allowlisted extension, nonnegative byte size, Git object SHA, repository visibility, `public_exposure: not_measured`, and locator mutability. This is file/repository metadata only. A public visibility label, byte size, extension, or mutable branch reference neither proves the file body was inspected nor establishes public reachability or severity.

Check `analysis_complete`, `bytes_examined`, and `truncated` before relying on a hint. Parse failure, capture bounds, or an incomplete JSON walk make the local analysis incomplete. `automated_sensitivity_is_provisional` is always true: the command does not assign severity or confirm sensitive content.

## What to do next

Keep the capture and its report in the approved local evidence system. If a category needs review, use the minimum authorized metadata or human evidence review described in [ops/triage.md](triage.md) and [ops/evidence.md](evidence.md). Confirm ownership and use an unexpired scope before any anonymous `probe` or `browser` observation. Only an observation plus minimal evidence and ownership support can support `SENSITIVE_CONTENT_CONFIRMED`; a local profile cannot.

## Private location mapping

The public profile keeps `locator_ref` rather than an exact URL. When an authorized owner needs the traceable exact location, resolve existing **opaque** references only into a separate private-local file:

```bash
open-detective asset-locations \
  --input _local/case/asset-profile.json \
  --locator-store _local/locators.sqlite \
  --scope-id TEAM \
  --output _local/case/private-locations.json
```

`asset-locations` reads the report and the existing locator store in the selected scope; it makes no network request. It writes a new `PRIVATE_LOCATION_MAPPING_DO_NOT_PUBLISH` file whose rows are `RESOLVED`, `NOT_FOUND_IN_SCOPE`, or `NO_REFERENCE`. `hmac-sha256:` references are profile-safe but cannot be resolved by this command and must not be substituted for an opaque locator-store reference. A resolved row contains `private_location`, which can include path segments, document IDs, or tokens. Store it only with the owner's access controls and do not attach, publish, or copy it into shared findings.

Resolving a location only joins an opaque reference to a local URL. It does not inspect an index, file body, or metadata beyond the supplied report, and it does not establish ownership, access, public reachability, or sensitive exposure.
