# Changelog

## Unreleased

- Added `trace-assets`, an explicitly invoked scope-bound anonymous GET trace for explicit HTML script and JavaScript fetch references. It enforces aggregate request, byte, duration, depth, and deduplication bounds; records asset-linked content-profile hints and gaps; retains only opaque report locators; and stops early on a sensitive-content candidate. It does not execute JavaScript, render a DOM, guess dynamic endpoints, authenticate, or alter `probe` or `browser`.

- Added offline `asset-profile` for bounded, value-free structural review of already captured local content, including parent asset relationships, native inventory coverage context, and provisional business-data categories. Added `asset-locations` to resolve opaque asset references into a separate private-local URL mapping without network access. Neither command establishes ownership, reachability, sensitive content, or severity.

- Rebranded the project and installed skill as Open-Detective. Documentation now uses the `open-detective` CLI.

- Added separate approved-local forensic case commands and documentation for read-only export acquisition, custody verification, and evidence-linked timelines. Case authority remains distinct from anonymous measurement scope; hashes support integrity checks but do not establish legal admissibility or artifact authenticity.

- Added a strict local audit-intake schema and neutral examples for exclusions, identity inputs, affiliate boundary, third-party declaration, escalation, and approval-dependent actions. Intake is explicitly separate from executable scope and network authorization.
- Added documented anonymous discovery-channel positive controls. `channels-doctor` reports fresh `OK`/`DEGRADED`/`DEAD` health for separate GitHub repository and search API families; GitHub discovery and plan execution require channel-specific health evidence.

- Added bounded source-word initialisms, explicit industry-tail brand compounds, and multiword alias boundaries to offline identifier generation. Derived abbreviations remain lower-priority candidates, not ownership evidence.
- Fixed anonymous GitHub numeric-ID pagination, scoped 404 observations, case-insensitive account deduplication, and rate-limit termination. Repository retention no longer depends on available account-expansion slots.
- Added checkpointed multi-batch discovery, explicit total/per-job request budgets, separate failed-work retries, preserved batch and attempt provenance, and next-work diagnostics. Interleaved name/industry/function/numeric candidates improve bounded recall without treating similarity as ownership.
- Preserved a search-discovered account expansion as deferred when its provider records only a strict zero-request `REQUEST_LIMIT_EXCEEDED` marker. Real failures and prior completed/failed evidence remain unchanged; deferred resumption is explicit.
- Refined bounded plan scheduling to round-robin full identity, industry context, and function context while preserving order within each family. Short or broad work remains later, identity/context account candidates alternate one-for-one, and ordinary runs do not implicitly promote existing deferred work.
- Analyze already-captured truncated response prefixes for provisional signals while keeping capture and analysis incomplete.

- Added bounded `search-plan`, private locator-store handoff, locator/policy-bound ledger rechecks, and read-only `doctor` runtime/source parity checks. Exact locators remain local; a repository push does not update an installed runtime.
- Moved the identifier generator canonical implementation to `sudetect/idgen.py`; `tools/idgen.py` remains a compatibility wrapper. Search plans distinguish operator aliases from generated Korean compound/spacing, brand/industry, and English joined/spaced variants, with broad terms deferred behind bounded higher-value work.
- Clarified browser observation as `brokered_anonymous_browser`: password inputs are indicators only, bounded live form values are inspected after a clean DOM review, and canvas/shadow-DOM/heap/post-interaction limits remain incomplete coverage.

- Replaced the legacy single exposure verdict with independent access, content, confidence, and workflow fields.
- Added executable exact-origin HTTPS scope policy with stable `SUD-Rxx` rule IDs, ownership evidence, path limits, expiry, and per-request enforcement.
- Added root Python commands for policy-bound probe/browser observation, owner inventory and provenance imports, discovery, local analysis, and SQLite ledger operations.
- Added controlled optional Playwright observation with fresh contexts and explicit unsupported-mode reporting.
- Added paginated Vercel project/deployment/alias/domain inventory and GitHub repository/tree inventory, plus completeness metadata, normalized JSON provenance import for other assets such as Pages, append-only ledger events, aliases, controls, proof references, rechecks, and due queue.
- Hardened the offline identifier generator: normalized runtime terms, boundary-aware legal suffix removal, platform-specific target validation, and positive limit/tier validation.
- Rewrote and synchronized English/Korean documentation. The Korean skill file is translation-only and has no install frontmatter.

No release note in this section claims a live deployment or organization was tested. Validation uses offline and synthetic fixtures.
