# Open-Detective

![Open-Detective evidence investigation workspace](assets/hero.png)

**Evidence-led public exposure investigation for organizations.** Open-Detective maps the public attack surface, discovers attributable deployments, observes approved anonymous access, and preserves the evidence needed to classify, contain, and recheck accidental data or confidential-content exposure.

It is built for investigators who need a defensible record: bounded scope, ownership evidence, explicit coverage gaps, minimal collection, and forensic-ready local evidence workflows. It is not a vulnerability scanner. It does not authenticate with discovered secrets, bypass controls, enumerate adjacent records, or claim complete Internet coverage.

[Repository](https://github.com/kindsusu/Open-Detective) · [Korean documentation](README.ko.md) · [Forensic workflow](ops/forensics.md)

Implementation and rollout notes (Korean): [IMPLEMENTATION.ko.md](IMPLEMENTATION.ko.md)

## What it does

- **Scope and ownership:** records approved boundaries and ownership evidence before any network observation.
- **Exposure discovery:** inventories supported owner sources and imports normalized local exports with provenance when a source is outside the built-in collectors.
- **Evidence and forensics:** classifies only what the observation supports, minimizes retained content, and supports approved local custody and timeline workflows.
- **Containment and rechecks:** tracks aliases, remediation, controls, and fresh rechecks in an append-only operational ledger.

## Decision model

Keep independent fields. HTTP status alone never proves sensitive exposure or safety.

```text
access: BODY_SERVED | ACCESS_DENIED_OBSERVED | AUTH_REDIRECT_OBSERVED |
        NOT_FOUND_OBSERVED | INDETERMINATE
content: PUBLIC_UI | SENSITIVE_CONTENT_CONFIRMED | SENSITIVE_CANDIDATE |
         CLIENT_ENCRYPTED_OBSERVED | NOT_INSPECTED
confidence: confirmed | probable | unknown
workflow: candidate | ownership_pending | verification_pending | open |
          containment_pending | recheck_pending | partially_closed | closed | reopened
```

`BODY_SERVED + PUBLIC_UI` can be an ordinary login page. `SENSITIVE_CONTENT_CONFIRMED` requires a minimal evidence reference to an actual protected value or field, anonymous observation, and ownership evidence. A name match, status code, byte count, AI score, or tool agreement is insufficient.

## Install and run

Python 3.11 or newer is required. Browser capture is optional.

```bash
python -m pip install -e .
python -m pip install -e ".[browser]"
python -m playwright install chromium
open-detective --help
```

The primary command is `open-detective`. The existing `su-detect` and `python -m sudetect` entry points remain supported and invoke the same CLI.

The root CLI provides `probe`, `browser`, `inventory`, `discover`, `github-discover`, `search-plan`, `channels-doctor`, `channel-discover`, `discovery-eval`, `asset-graph`, `forensics`, `locators`, `ledger`, and `doctor`. Anonymous measurement commands require `--scope`; owner inventory and passive imports require explicit `--scope-id`. There is no implicit measurement scope or automatic header replay.

```bash
open-detective probe --scope scope.json https://app.example.test/
open-detective browser https://app.example.test/ --scope scope.json --duration 3
open-detective inventory --provider vercel --scope-id TEAM --token-env VERCEL_TOKEN
open-detective inventory --provider import --scope-id TEAM --input inventory.json
open-detective discover --input candidates.json --scope-id TEAM
open-detective search-plan plan --output _local/plan.json --scope-id TEAM --company-en "<operator input>"
open-detective doctor --reference .
open-detective channels-doctor --config _local/channels.json --scope _local/control-scope.json --output _local/channel-health.json --previous _local/channel-health.previous.json
open-detective github-discover --scope-id TEAM --account approved-account --channel-health _local/channel-health.json
open-detective search-plan run --plan _local/plan.json --locator-store _local/locators.sqlite --channel-health _local/channel-health.json
open-detective search-plan run-until-budget --plan _local/plan.json --locator-store _local/locators.sqlite --request-budget 60 --channel-health _local/channel-health.json
open-detective locators --store _local/locators.sqlite bind --scope-id TEAM --locator-ref "opaque:<id>" --scope _local/scope.json --db audit.sqlite --asset-id asset-1 --provider import
open-detective probe --scope _local/scope.json --locator-store _local/locators.sqlite --locator-scope TEAM --locator-ref "opaque:<id>"
open-detective ledger --db audit.sqlite due
```

`forensics` is a separate private-local workflow for an approved case and owner-authorized read-only exports; its `--case` authorization is not a measurement `--scope`. See [ops/forensics.md](ops/forensics.md). It does not authenticate, acquire images, establish legal admissibility, or infer exfiltration from an absent log.

`channel-discover` is limited to Cert Spotter CT and operator-configured query-bound JSON exports; `discovery-eval` and `asset-graph` are offline. See [ops/discovery-optimization.md](ops/discovery-optimization.md). None confirms ownership or turns a candidate into a measurement target.

`tools/probe.sh` is a compatibility wrapper around the Python probe.

`doctor` is read-only. It checks the runtime loaded by the command and can compare it with a reviewed source tree. Editing or pushing this repository does not update an already installed skill/runtime; use its reported runtime root and parity result before treating the installed copy as updated.

## Scope contract

Policy is executable input. Each target identifies the owner, exact HTTPS origin, allowed path prefixes, ownership evidence, and policy expiry. Wildcard origins, URL userinfo, non-HTTPS schemes, and expired policy are rejected. Redirects and brokered browser requests are checked before each request. Ownership APIs use credentials and an execution context separate from anonymous target measurement.

```json
{"policy_id":"replace-with-approved-scope-id","expires_at":"2020-01-01T00:00:00Z","targets":[{"owner":"replace-with-owner-record-id","ownership_evidence":"replace-with-verified-asset-record-id","origin":"https://app.example","path_prefixes":["/"]}],"max_bytes":262144,"max_requests":20,"timeout":10,"max_redirects":5}
```

This example is deliberately expired. Copy [examples/scope.example.json](examples/scope.example.json) into ignored `_local/`, replace placeholders, and set the approved future UTC expiry. Read [ops/scope.md](ops/scope.md) before a network command. Company names, domains, accounts, and tokens belong in local input, never in this repository.

## Workflow

1. Create local audit intake before discovery: exclusions and evidence, organization identity, affiliate boundary, third-party status, owner/escalation references, and actions needing extra approval. Use [examples/audit-intake.example.json](examples/audit-intake.example.json) with [schemas/audit-intake.schema.json](schemas/audit-intake.schema.json). This is not executable scope and grants no network authority. `third_parties.status="unknown"` is a recorded gap; do not infer those parties as owned.
2. Obtain the administrator export for contracts, assets, and processor/outsourcer registers; approve executable scope; then import candidates. Owner-inventory credentials remain a separate authorization path.
3. Build identifiers and `search-plan` offline from the intake.
4. Run `doctor --reference .` to identify the runtime root actually loaded by the command and compare it with the reviewed source tree at `.`.
5. Run fresh authorized positive controls with `channels-doctor`; only then run `github-discover` or `search-plan`. A successful control does not establish complete company discovery.
6. Confirm ownership before target measurement. A public deployment can outlive a private repository.
7. Run a bounded anonymous probe. Failures and partial captures are `INDETERMINATE`.
8. Use the browser only when static HTML cannot answer the content question. `brokered_anonymous_browser` uses a fresh context and a policy-bound transport broker for approved GET document/script/stylesheet/XHR/fetch requests. It strips browser credentials, cookies, auth, and referrer; turns off Service Workers, blocks WebSocket server connections and discards messages in a local sink, closes popups, and refuses downloads. It inspects bounded live `input`, `textarea`, and `select` values only when the earlier DOM review finds no candidate. Canvas pixels, closed/open shadow-DOM content outside the serialized snapshot, JavaScript heap, post-interaction state, and unsupported behavior remain unmeasured. A password input is only a `LOGIN_FORM_INDICATOR`; it is not automatically `PUBLIC_UI`, protected, or sensitive. Chromium uses a dead proxy plus blocked host resolving so supported page requests use the broker. These controls are bounded to the observer, not an OS-firewall or total-egress guarantee.
9. Confirm content only from minimal evidence. Stop when personal data or a usable secret is visible. Live secret validity remains unknown unless an authorized owner-side check establishes it.
10. Balance urgent isolation, log preservation, secret rotation, and service continuity. Keep application authorization checks behind SSO.
11. Close only after a fresh anonymous observation supports the state. Bind every ledger asset and alias to its opaque locator `target_id` and `policy_id`; reject a mismatch. Unchecked residue yields `partially_closed`. After closure, a current `BODY_SERVED`, unknown/incomplete result, or equal-time conflicting observation reopens or returns the finding to review.

Owner API inventories follow every cursor and record permission, rate-limit, truncation, and time-window gaps. Normalized JSON imports retain source, retrieval time, owner scope, and completeness. A failed channel returning zero rows is not a zero-asset result.

Store masked evidence references, not copied source material. Query, fragment, userinfo, path, headers, redirects, console, screenshots, and traces can contain tokens. `0` and `false` are real values, not empty values. Aggregates still derive from personal data and need scope, provenance, and access controls.

The SQLite ledger records append-only observations/events, aliases, controls, proof references, rechecks, and a due queue. Unchanged observations stay quiet; completion, regression, failure, and required operator action are meaningful events.

## Private locator handoff and discovery plans

Keep exact URLs in an owner-controlled local locator store. Shared discovery output carries only `locator_ref` and a handoff state. `ready` means the exact locator is present in the local store; `blocked` means no measurement target is available. A scope must still authorize the resolved URL before `probe` or `browser` sends a request. Bind the approved ref to the asset before importing rechecks so the ledger can compare `target_id` and `policy_id`.

`search-plan` creates a bounded, resumable manifest. It distinguishes aliases supplied by the operator from generated name variants, marks unrun work as `deferred`, and reports `PARTIAL` until every required channel is completed or explicitly `not_applicable` with a reason. `COMPLETE` describes only the declared plan and channel coverage; it does not prove that discovery is exhaustive. `discover` and search-plan can use a locator store to keep exact candidate URLs out of shared plan/output files. Owner inventory locator-store handoff follows the same private-store pattern when available; do not treat provider inventory metadata as a measurement grant.

## Discovery-channel health controls

`channels-doctor` performs a fresh, scope-authorized anonymous observation of local positive controls and writes a report when its config and scope are valid. Its JSON config accepts `max_age_seconds` and unique controls with `channel_id`, `control_id`, `url`, and either `expect.kind="json_pointer"` (`pointer`, `equals`) or `expect.kind="body_contains"` (`value`); see [examples/channel-health.example.json](examples/channel-health.example.json). Prefer a specific JSON-pointer identity such as `/items/0/login` or `/items/0/full_name`; a generic body marker can create a false positive. `OK` requires HTTP 200, complete capture, and a matching expected value. `DEGRADED` records an unexpected status, incomplete capture, or mismatch; `DEAD` records an unreachable control or HTTP 404/410. The CLI prints only changed channel rows and saves the full report.

The report is local operational evidence whose format and freshness are checked. It is neither an electronic signature nor remote attestation, and it is not a security boundary against an operator who can alter local files. Each actual GitHub execution needs currently fresh controls: `github-repositories` for repository listing, and all three controls—`github-repositories`, `github-user-search`, and `github-repository-search`—for a search seed because results can expand into repository listing. Health for one API family never establishes health for another. Imported search-plan results must carry channel-health valid at their `observed_at`; later expiry does not erase a historically valid import. Synthetic test input is never a real channel validation.

Bind each GitHub control to its `api.github.com` family: repository detail or `/users|orgs/<owner>/repos`, `/search/users`, and `/search/repositories?q=…`, respectively. A generic marker from another endpoint is not a substitute; a detail control does not prove pagination or permissions.

## Repository map

| Path | Purpose |
|---|---|
| [SKILL.md](SKILL.md) | Single installed skill entry |
| [ops/scope.md](ops/scope.md) | Stable policy rules and scope schema |
| [ops/discovery.md](ops/discovery.md) | Owner inventory and public discovery |
| [ops/verify.md](ops/verify.md) | Access/content decisions |
| [ops/triage.md](ops/triage.md) | Severity and minimization |
| [ops/evidence.md](ops/evidence.md) | Evidence hygiene and provenance |
| [ops/remediate.md](ops/remediate.md) | Containment and recheck |
| [ops/forensics.md](ops/forensics.md) | Authorized local evidence workflow |
| [ops/discovery-optimization.md](ops/discovery-optimization.md) | Bounded adapters, offline evaluation, and asset graph |
| [surfaces/inventory.md](surfaces/inventory.md) | Coverage checklist |
| [schemas/audit-intake.schema.json](schemas/audit-intake.schema.json) | Local pre-discovery intake shape |
| [assets/ledger-template.md](assets/ledger-template.md) | Human-readable export |
| [tools/idgen.py](tools/idgen.py) | Offline candidate generator |

English policy is canonical. `ko/` contains synchronized Korean translations. `ko/SKILL.md` has no frontmatter, so it is not registered as a duplicate skill.

## Validation and license

```bash
python -m unittest discover -s tests -v
```

Tests are synthetic and offline; passing does not mean a deployment or live organization was tested. The repository retains the [PolyForm Noncommercial License 1.0.0](LICENSE). Read its terms for permitted purposes. Use outside them requires permission from the licensor; an appropriate third-party or organizational license is an owner and legal decision, not a universal rule from this project.

The optional locator store is plaintext SQLite. Keep it on an owner-controlled encrypted volume with restricted permissions; its opaque references do not encrypt the underlying URLs. Local search manifests contain input names, queries, and public repository metadata and must not be published as masked reports.
