# Evidence handling

Evidence proves a decision while minimizing a second exposure. Capture metadata at the source and redact before logs, model input, reports, screenshots, or exports.

Each observation records an opaque ID, UTC time, policy/rule/tool versions, anonymous mode, masked canonical locator, redirect observations, access/content/confidence, bytes inspected, completeness, digest type/value, stop reason, control result, and evidence references. Raw artifacts live only in an owner-approved encrypted/access-controlled system with retention and audit logging.

The probe's `target_id` is a random `opaque:` identifier by default. If the operator explicitly sets `SUDETECT_LOCATOR_HMAC_KEY`, it becomes a stable keyed `hmac-sha256:` reference for authorized cross-run matching. Never use a plain hash of the locator: paths, document IDs, and share tokens may have low entropy. Protect and rotate the HMAC key outside reports and source control; without the same key, random opaque IDs intentionally cannot be correlated across runs.

For a local locator handoff, the opaque store reference itself is the measurement `target_id`. Bind it with the exact `policy_id` before a recheck enters the ledger. A changed, missing, or mismatched target/policy binding is not closure evidence.

Sanitize URL userinfo, path segments, query, fragment, headers, cookies, redirects, console output, DOM text, filenames, screenshots, HAR, and traces. Preserve structure with placeholders such as `<email>`, `<token>`, or `<record-id>`. A stable secret comparison uses an access-controlled keyed HMAC; a plain hash of a low-entropy secret can leak it.

For personal data record type and bounded approximate count, not a roster. For secrets record provider/type, masked prefix/suffix only when safe, location class, and `live_validity=unknown`. Never log in, call a data API, or rotate a secret from the audit process. Owner-side validity/rotation evidence is a separate event.

`0` and `false` remain typed values. Null, absent, empty string, redacted, truncated, and not inspected are distinct. Every aggregate records source, selection boundary, and whether sampling stopped early.

Reports separate confirmed facts, candidates, unknowns, and failures. Access is limited by role and purpose; privacy, security, legal, HR, and third-party recipients receive only the minimum fields needed for their task.
