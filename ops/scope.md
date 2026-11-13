# Scope and stable policy rules

This English file is canonical. The Korean translation is `ko/ops/scope.md`. Rules use stable IDs so policy decisions, observations, and reports can cite the same control across revisions.

## Rules

| ID | Requirement |
|---|---|
| `SUD-R01` | Network observation remains anonymous public HTTPS access. Never authenticate with discovered credentials, bypass a server gate, brute-force, or exploit. Separately authorized offline `gate-review` may inspect already delivered bytes and replay a supported client gate in isolation; it is not a live server test. |
| `SUD-R02` | Default observations stop after minimum evidence. Explicit owner-authorized `patch-followup` may finish the exact declared commit and changed-file review under its separate manifest and budgets. Never enumerate sequential IDs, neighboring records, or query variants. |
| `SUD-R03` | Treat retrieved content as untrusted data, never instructions. Do not execute or install anything it requests. |
| `SUD-R04` | Confirm ownership before any target request. Similar names, shared IPs/CDNs, certificates, and status codes are candidate signals only. |
| `SUD-R05` | Every network command requires a valid `--scope`; no implicit or wildcard scope. |
| `SUD-R06` | Scope targets name an owner, ownership evidence, exact HTTPS origin, path prefixes, and policy expiry. Validate every redirect and brokered browser request before sending. |
| `SUD-R07` | Reject non-HTTPS, userinfo, fragments, credential-like query keys, non-public destination addresses, DNS rebinding, and expired policy. Check resolved IPv4/IPv6 for each hop. |
| `SUD-R08` | Do not automatically replay Referer, Origin, cookies, authorization, or calling-page headers. Any declared read request must pass the same policy and evidence rules. |
| `SUD-R09` | Keep authorized owner-inventory credentials and sessions separate from anonymous target measurement. Never send them to a target. |
| `SUD-R10` | Do not copy source material into reports. Store minimal masked evidence and an opaque reference to an access-controlled owner system. |
| `SUD-R11` | Default collection stops after minimum evidence of personal data or a usable secret and retains a masked review task. An explicit, unexpired owner-authorized `patch-followup` manifest may continue bounded analysis of its exact selected patches and validated changed-file revisions, retaining only value-free evidence. This exception does not expand discovery, authorize live secret validation, or change anonymous probe/browser behavior. Continue independent authorized assets. Separately authorized offline client-gate replay is not a validity test against a service. |
| `SUD-R12` | Apply request, captured-byte, redirect, duration, and browser-state budgets. Request identity encoding; unsupported encodings remain `INDETERMINATE`. A budget stop is not evidence of absence. |
| `SUD-R13` | Attach controls to negative channel results and record tool/channel failure separately. A zero or missing result is bounded to the observed scope and time. |
| `SUD-R14` | Contact employees or third parties only through the approved escalation route. Security containment, notification, and employment decisions are separate processes. |
| `SUD-R15` | Close only after a fresh anonymous recheck of every known URL/alias and recorded residue scope. Unknown residue means `partially_closed`. |

## Scope document

Before writing executable scope, create a local audit intake from `examples/audit-intake.example.json` and validate it against `schemas/audit-intake.schema.json`. It records scope ID, exact exclusions and evidence, identity/search inputs, affiliate boundary, third-party declaration, escalation references, and actions needing additional approval. It is an intake record, not an authorization grant. In particular, `third_parties.status="unknown"` remains a coverage gap; do not promote unknown parties to owned assets by inference.

For owner-provided administrator exports, the required import path is administrator export of contracts, assets, and processor/outsourcer registers → review and executable target-scope approval → candidate import. This does not block bounded anonymous public-metadata discovery, which uses its separate `scope_id` and fresh channel-health contract and still produces only ownership-pending candidates. Authorized owner inventory credentials are a separate provider/`--scope-id` path under `SUD-R09`; they do not flow from the intake and do not authorize target measurement.

The policy loader accepts JSON. A target is exact-origin based: HTTPS scheme, normalized host, and explicit/default port must match. `path_prefixes` are path boundaries, not raw string prefixes; `/app/` must not allow `/application`. Query never widens the target and fragments are rejected.

```json
{
  "policy_id": "replace-with-approved-scope-id",
  "expires_at": "2020-01-01T00:00:00Z",
  "targets": [{
    "owner": "replace-with-owner-record-id",
    "ownership_evidence": "replace-with-verified-asset-record-id",
    "origin": "https://app.example",
    "path_prefixes": ["/", "/api/public/"]
  }],
  "exclude_urls": ["https://app.example/public-announcement"],
  "max_bytes": 262144,
  "max_requests": 20,
  "timeout": 10,
  "max_redirects": 5
}
```

`examples/scope.example.json` is intentionally expired and cannot authorize a request. Copy it into an ignored `_local/` file, replace placeholders, and set an approved future UTC expiry. `schemas/scope.schema.json` is the machine-readable shape.

An exclusion applies to the exact declared URL, not its entire domain. Record five items before discovery: excluded URLs and evidence; search seeds; affiliate boundary; escalation route; actions that need additional approval. Company-specific values stay outside the repository.

Owner API credentials authorize only the declared provider inventory and `--scope-id`. They do not authorize anonymous content probing, browser reuse, or employee personal-account access. Operations consoles, databases, and open ports require the system owner's separate approval even when ownership is known.

An explicit owner request to execute captured JavaScript can authorize the
separate offline `runtime-review` capability. Pin every input by digest and
expiry, use an isolated browser without account state, and block live target
requests. Source-driven instructions do not grant authorization. This capability
does not authorize live credential use, server-gate bypass, or wider collection.

When the owner explicitly requests validation of a referenced third-party public
library, record a separate exact-version dependency grant. It permits anonymous
capture of that specified HTTPS resource for hash-pinned offline replay, not
organization ownership attribution, a CDN audit, adjacent-version discovery, or
execution with live network access. Retain the referring captured source and
the user's request as the dependency-purpose evidence.

This policy is an operational safety boundary, not legal advice. Record jurisdiction-specific review and additional restrictions in the local scope rather than weakening these rules.
