# Evidence Handling — So the Audit Record Is Not Itself a Leak

The audit exists to reduce exposure. **Making copies along the way increases it.**

## Absolute rules

1. **Never record real keys, values, or personal data verbatim.** Type, location, and a masked value only.
2. **Never copy or download originals to local storage.** The moment you make a copy, the auditor's
   machine becomes a new leak point.
3. **If personal data is identified, stop reading immediately.** If it appears on screen, stop there and
   hand it to the data-protection officer.
4. **Never move originals into notes, wikis, or chat.** Record only that they exist.

## Masking format

| Item | How to record |
|---|---|
| API keys and tokens | `AKIA****...****` — **first four characters only**, plus type, issuer, location, discovery date |
| Passwords | `(present)` — the value is never written in any form |
| Personal data | `1 name`, `approximately 40 contact records` — **type and approximate count only** |
| Files | Path, size, sha256. **Never quote the contents** |
| URLs | Record as-is, but **mask identifiers in the query string** (`?id=****`) |

**Do not verify validity.** Never log in with the key (invariant 3).
Whether a key is live gets answered naturally **when the issuer rotates it.**

## Header and log hygiene

**Header dumps leak tokens.** This has actually happened — dumping headers with `curl -D` printed a live
session token straight into the output.

```bash
curl -sI "$URL" | grep -ivE '^(set-cookie|authorization|proxy-authorization|x-api-key|cookie)'
```

- The same applies to the **final URI**: authentication redirects carry a JWT in the query string.
  Strip the query before recording.
- Script output, terminal scrollback, and session logs are all records subject to these rules.
- When writing response bodies to a file, **truncate per request**.
  Otherwise a failed request shows you the previous response body — a measurement error and a hygiene
  problem at once.

## When you genuinely must obtain an original

Only when remediation or legal action requires it, and only if all of the following hold.

1. **Minimum scope** — just enough to demonstrate the exposure
2. **Masked copy first** — the deliverable is the masked version, not the original
3. **Encryption and access control** — one designated path, with access logged
4. **Destroy after remediation** — set the retention deadline up front
5. **Record only the path** — reports and notes carry **the file path and the fact of existence**, nothing more

## What goes into which deliverable

Separate what the auditor sees from what the data-protection officer sees.

| Deliverable | Recipient | Contents |
|---|---|---|
| Exposure ledger | Auditor, management | Asset, verdict, grade, owner, deadline, re-measurement date. **Stops at "exposed / not exposed / how much"** |
| Escalation report | DPO, legal | The above plus **type and approximate count** of personal data. No originals |
| Original evidence | Designated handler under the DPO | Only when required, following the procedure above |

**The auditor does not read customer personal data in detail.**
Viewing by someone who is not a designated handler may constitute out-of-purpose use or unauthorized
access (invariant 11).
