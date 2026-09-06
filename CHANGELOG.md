# Changelog

## Unreleased

- Fixed anonymous GitHub numeric-ID pagination, scoped 404 observations, case-insensitive account deduplication, and rate-limit termination. Repository retention no longer depends on available account-expansion slots.
- Added checkpointed multi-batch discovery, explicit total/per-job request budgets, separate failed-work retries, preserved batch and attempt provenance, and next-work diagnostics. Interleaved name/industry/function/numeric candidates improve bounded recall without treating similarity as ownership.
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
