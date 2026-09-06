# Anonymous verification and decision rules

Verification answers two questions separately: **what access behavior was observed?** and **what did minimal content evidence establish?** It does not infer site-wide protection from one URL.

## Access

| Value | Evidence |
|---|---|
| `BODY_SERVED` | The transport observed a 2xx response (including a bounded partial 206 capture). It may contain no bytes, public UI, an error document, or sensitive content. |
| `ACCESS_DENIED_OBSERVED` | The transport observed HTTP 401 or 403 for this request. This is a status observation, not confirmation that the response is a real authorization boundary. |
| `AUTH_REDIRECT_OBSERVED` | Separate classifier or human evidence review identifies an observed redirect as an authentication flow. The current probe does not infer this value from an IdP-like name. An unapproved cross-origin redirect is `INDETERMINATE`. |
| `NOT_FOUND_OBSERVED` | The transport observed HTTP 404 or 410 for this request. This is a status observation, not confirmation that the resource is absent. |
| `INDETERMINATE` | Timeout, DNS/TLS/policy/budget failure, partial unsupported behavior, ambiguous challenge, or insufficient evidence. |

The current probe JSON records observation/time/policy IDs, masked target reference, HTTP status, authorized redirect references, access/content, captured bytes when available, completeness, full or prefix digest, and a bounded reason code. Response content type and resolved connection addresses are transient enforcement inputs and are not serialized. A downstream ledger may add tool/rule version and protected network metadata when its evidence policy permits. A full SHA-256 applies only to a complete capture; partial captures use `prefix_sha256`.

Challenge/error-page indicators and soft-404 semantics belong to the provisional classifier or human evidence review. They may revise the content interpretation or keep the workflow pending, but the probe's `ACCESS_DENIED_OBSERVED` and `NOT_FOUND_OBSERVED` remain literal status observations. Neither value proves safety, authorization correctness, or resource absence.

## Content

| Value | Evidence |
|---|---|
| `PUBLIC_UI` | Evidence supports intentionally public UI/content such as a login form or public brochure. |
| `SENSITIVE_CONTENT_CONFIRMED` | Minimal actual evidence confirms protected personal/confidential data in an anonymous response. Requires observation and ownership evidence. |
| `SENSITIVE_CANDIDATE` | Parser, name, field, or context suggests sensitivity but actual protected value or ownership is not established. |
| `CLIENT_ENCRYPTED_OBSERVED` | Only ciphertext was observed; plaintext/key exposure and effective protection remain separate questions. |
| `NOT_INSPECTED` | Content was not inspected or the access result did not permit a decision. |

Content certainty is `confirmed`, `probable`, or `unknown`; workflow status is separate. An AI explanation must cite evidence IDs and cannot promote a candidate to confirmed.

## Measurement sequence

1. Load and validate the unexpired policy (`SUD-R05`–`SUD-R07`).
2. Match exact origin, path boundary, owner, and ownership evidence before connecting. The measurement transport sends GET only.
3. Resolve A and AAAA, reject non-public addresses, and bind the request to validated addresses. Repeat before every followed redirect.
4. Disable ambient credentials/configuration, cookies, proxy inheritance unless explicitly brokered, Referer, and automatic auth (`SUD-R08`, `SUD-R09`).
5. Enforce redirect/request/time/captured-byte budgets (`SUD-R12`). The transport requests identity encoding and marks a non-identity content encoding unsupported; it does not claim a decompression budget.
6. Sanitize evidence at capture time. Compare an appropriate control before interpreting a negative (`SUD-R10`, `SUD-R13`).

There is no automatic legacy “weak gate” retry. A 401/403 followed by a different-header 2xx can reflect routing, public UI, or data; only actual minimal sensitive-content evidence can establish exposure.

## Browser escalation

Escalate when static HTML is a shell, JavaScript initiates anonymous data requests, hidden DOM or hydration data may already contain content, or content type is ambiguous. A fresh context has no saved cookies, extensions, cache, or Service Worker state. Install routing before navigation; supported HTTP requests are checked against policy, while unsupported behavior remains unmeasured.

`brokered_anonymous_browser` sends approved GET document/script/stylesheet/XHR/fetch through the pinned policy transport without raw browser headers, cookies, auth, or referrer. It configures Service Workers off, blocks WebSocket server connections and discards messages in a local sink, closes popups, refuses downloads, and launches Chromium with a dead proxy plus blocked host resolving so supported page requests use the broker. A WebSocket attempt is recorded as `websocket_not_observed` and makes the browser result incomplete. If DOM review has no candidate, it inspects bounded live `input`, `textarea`, and `select` values. Canvas pixels, shadow-DOM content outside the serialized snapshot, JavaScript heap, and post-interaction state are not measured. A password input only produces `LOGIN_FORM_INDICATOR`; it does not establish `PUBLIC_UI`, protection, or sensitive content. External protocols and other unsupported behavior remain `INDETERMINATE`. These are observer controls, not an OS-firewall guarantee or total egress proof.

The browser analyzes response bytes and a bounded DOM snapshot transiently, then emits sanitized observation/classifier summaries without raw DOM. It does not produce screenshots, HAR, or traces.

## Controls and rechecks

Choose a control that exercises the same channel without accessing another person's data: a known public endpoint, configured missing path, or owner-provided protected fixture. If target and control fail together, record channel failure. Volatile services require bounded repeat observations; silence or unchanged state does not prove that no event was missed.

Recheck the exact original locator, every known alias/deployment, relevant cache, and authorized archive channel with a new anonymous context. Dynamic digest changes alone do not prove remediation or recurrence. Compare access/content evidence and record unknown residue as `partially_closed`.
