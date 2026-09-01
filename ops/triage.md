# Triage — Separate "Open" from "Leaked"

**"The asset is open" and "the data leaked" are different facts.** Mixing them destroys the report.
Overstate and you lose credibility; understate and remediation comes too late.

> Precedent: in one audit the repository was public, but no password was hardcoded and the vehicle data
> was fetched from an API rather than embedded in the HTML. **"Public" did not mean "everything leaked."**
> Holding that distinction is what made the report accurate.

## Grades

| Grade | Contents | Deadline |
|---|---|---|
| **S** | Live credentials (API keys, tokens, passwords, private keys) | Immediate — **rotate first** |
| **A** | Personal data (names, contacts, addresses, dates of birth, licence numbers, account numbers, contract details) | Immediate — **escalate to the data-protection officer** |
| **B** | Confidential business data (pricing, cost structure, margins, competitor analysis, contract terms, unannounced plans) | Same day |
| **C** | Internal structure (API endpoints, server layout, admin behaviour, internal paths) | Within the week |
| **D** | Branding and layout only | Cleanup backlog |

**When a national identifier is involved (identity numbers, passport numbers, driver's licence numbers),
treat grade A with the same urgency as S.** In vehicle-rental and similar industries, licence numbers are
handled routinely, so this comes up often.

## Order of determination

```
1. Is the asset open to anonymous visitors?          -> ops/verify.md
2. If so, what is inside it?                         -> steps 3-5, minimizing reading
3. First pass on file listings (metadata only)       -> git/trees, directory listings
4. Flag dangerous extensions and filename patterns   -> table below
5. If personal data is indicated, stop immediately   -> invariant 11, hand to the DPO
```

**Stop at step 3 whenever you can.** You can rank priorities without ever fetching a file body.

## First-pass signals — filenames and extensions

| Signal | Implication |
|---|---|
| `.env`, `.mcp.json`, `.cursorrules`, agent config files, `.claude/settings.json` | **AI agent configuration.** Internal URLs, connection strings, and keys concentrated in one file |
| `config.*`, `*.yaml`, `*.ini`, `credentials`, `*.pem`, `*.key`, `*.p12` | Possible credentials |
| `*.json`, `*.csv`, `*.xlsx`, `*.sql`, `*.db`, `*.bak` | **Data files.** May carry personal or confidential records |
| `*.pdf`, `*.docx`, `*.pptx`, local office formats | Documents. **File-internals inspection required** |
| `*.map` | Source maps — front-end original code can be reconstructed |
| Filenames containing `backup`, `old`, `bak`, `temp`, `test` | Leftovers nobody cleaned up |

> Working rule: **a repository containing configuration or data files is the most dangerous kind.**

## File-internals inspection — what is still inside what you found

Knowing *where* to look is not enough. This is a **mandatory follow-up step** for every file you obtain.
Even a small number of exposed files matters, because **a single file can hold a large number of records**,
which makes the expected damage high.

| Format | What to check |
|---|---|
| Spreadsheets | Hidden sheets, hidden rows and columns, pivot caches, data hidden by filters, external paths referenced by formulas |
| PDF | **Failed redaction** — the original text still sits under the black box. Document properties. Annotations |
| Local office formats | Author, department, **internal file-server paths**, revision history |
| Images | **EXIF GPS** (depot and workshop locations), capture device, timestamp |
| Office formats generally | Author, last modified by, company name, template path |

**Never copy originals to local storage** (invariant 10). Inspect minimally, mask, and destroy after
remediation.

### Structured data — a field existing is not a value existing

In JSON and API responses, **do not call something leaked from the field name alone.** A schema can
carry an alarming name whose values are all `null`, `0`, or empty — that item is not going out. The
reverse holds too: a plainly named field can carry the bulk of the records.

**Confirm by tallying per-field fill rates.** That is an aggregate, not a read of individual values, so
it does not collide with invariants 10 and 11. Only fields that **actually hold values** belong in the
grading table.

> Precedent for skipping this step: cost, commission-rate and residual-value fields were present in a
> schema and were reported as "margin structure leaked." The tally showed every one of them empty —
> what was actually exposed was the published price list.
> **Overstating breaks a report as thoroughly as understating.**

## Separate confirmed from unconfirmed

Split the report into two columns. Mixing them makes the whole thing suspect.

**Confirmed** — only facts that reproduce under anonymous measurement.
> Example: "anonymous GET returns 200, ~82KB, sha256 `a1b2c3...`, body served in full"

**Unconfirmed** — anything you cannot assert for lack of evidence.
**State what additional measurement would confirm it.**
> Example: "An external scan service reports port 9200 open. However (1) the address is shared by five
> domains, (2) that service's staleness is demonstrated (a live 443 was missing), and (3) the service
> type and authentication state are unknown.
> **To confirm**: identify the operator, then check `ss -lntp`, firewall policy, and authentication
> settings on the host."

**Without server code or internal access, never assert whether server-side defences exist.**
The audit must finish even if a tool dies mid-run — **separate tool failure from judgment failure.**

## Handling by owner

| Owner | Handling |
|---|---|
| Your organization | Remediate directly |
| Employee or former employee's personal account | Work instruction and takedown. **Keep security action separate from HR action** (invariant 15) |
| Third party (processor, agency, platform) | **Notification only.** No further probing or harvesting (invariants 5, 12, 14) |
| Ownership unconfirmed | **Do not record it as an asset.** No probing before confirmation (invariant 12) |
