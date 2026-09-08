# Evidence-based triage

Triage begins only after access and content are separated. Severity describes confirmed impact, not how surprising a URL looks.

| Grade | Minimum basis | Response |
|---|---|---|
| S | Confirmed private credential/key material or privileged secret; live validity remains separate | Stop, restrict evidence, owner-side rotation and log review |
| A | Confirmed personal data or protected individual record | Stop, privacy escalation, contain and preserve required logs |
| B | Confirmed confidential business content | Contain, notify owner, assess contractual/operational impact |
| C | Internal structure/configuration without confirmed secret or protected data | Owner review and least-disclosure cleanup |
| D | Public UI/brand content or candidate with no protected value confirmed | Record intent/ownership; no exposure claim |

`SENSITIVE_CANDIDATE` is not a confirmed S/A/B finding. Human evidence review records `SENSITIVE_CONTENT_CONFIRMED` in the ledger with observation ID, masked proof reference, owner evidence, anonymous condition, reviewer, and time. Automated real-content classifiers remain provisional. Synthetic canaries may produce a synthetic-only confirmed label in tests and must never appear as live proof.

Inspect the minimum necessary metadata first: content type, field names, document properties, worksheet names, archive member names, and masked examples. Hidden sheets, failed redaction, document metadata, EXIF, embedded JSON, source maps, hydration data, and anonymous fetches are relevant only when policy and budgets permit inspection.

Treat `0` and `false` as populated values. Keep null, empty, redacted, sampled, and actual values distinct. Counts and fill rates still require processing the source data, so record sample/boundary, provenance, privacy purpose, access control, and stop condition. Never claim aggregates eliminate privacy obligations.

Public/publishable keys and private/service-role secrets have different impact. Identify type and context without attempting authentication or data access. Client ciphertext does not establish effective protection or plaintext exposure.

Route organization-owned assets to the accountable service/data owner. Route employee personal-account material through the approved security/takedown path, separate from employment action. Route third-party assets through approved notification without additional probing. Unconfirmed ownership stays `ownership_pending`.
