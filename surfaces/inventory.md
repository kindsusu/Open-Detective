# Exposure Surfaces — Where to Look

Structured as **primary axis (where it is stored) x sub-axis 1 (who owns it) x sub-axis 2 (time)**.
An earlier draft mixed channels, tools, and artifacts on one axis, which caused double counting.
Tools (dorks, CT lookups, API enumeration, HTTP measurement) are not channels — they are an
**execution layer**, and they live in `ops/discovery.md`.

## Sub-axes — these multiply across every storage location

**Ownership**

| Category | Meaning | Remediation path |
|---|---|---|
| Yours | Assets in the organization's name | Remediate directly |
| Employee or former employee | Company material in a personal account | Work instruction and takedown. **Separate from HR action** (invariant 15) |
| Third party | Processors, agencies, partners, platforms | **Notification only.** No probing (invariants 5, 12, 14) |

**Time**

| Category | Meaning |
|---|---|
| Current | Being served right now |
| Residue | What survives closure — archives, commit history, registry back-versions, AI citations |

> Residue is not a separate channel. It is a **dimension that applies to every channel.**
> "We deleted it" stays unconfirmed until the residue check is done.

---

## Axis 1 — Code repositories
Code hosts (repositories, gists, static pages, CI artifacts, issue attachments, releases,
**commit history**), and model or dataset hubs.

- **Working rule**: private repositories do not matter. **Only what is published.** Among those, a
  repository containing **configuration or data files** (`json`, `env`, `yaml`, `csv`) is the most dangerous.
- **Residue**: a direct commit-SHA lookup still works after the commit is removed from a branch, until
  garbage collection.
- Skip code hosts your organization demonstrably does not use — a channel nobody uses is noise.

## Axis 2 — Deployment hosting
Static page hosts, edge platforms, serverless app platforms, container app hosts, notebook and data-app
hosts, script web apps, tunnelling services, public wiki or note pages.

- **Vibe-coding platforms**: prompt-to-app builders.
  Apps built by non-engineers are **public by default, with hardcoded keys and no authentication** as the
  norm. This is the inevitable output of "AI rolled out company-wide plus non-engineers."
- **Backend-as-a-service rules left unset**: an anonymous public key is *supposed* to be public, so the
  verdict is not "the key leaked" but **whether row-level security or access rules are configured.**
- **The page's own data endpoint**: edge workers, serverless functions, script web apps and BaaS REST
  URLs that a published page fetches from. **A page and the endpoint behind it are two assets**, and
  moving data off the repository into an endpoint narrows nothing if the endpoint answers anonymously.
  Extract them from the page source (`fetch`/XHR targets, a config block) and from §discovery 5b
  network observation, then measure each one — including any that answered `403`, per
  `ops/verify.md` §"A 403 is not a boundary either".
- Code playgrounds are better covered by **a single dork** than by checking each one.

## Axis 3 — Object storage
Major cloud object stores plus regional and local providers.

- **Three-way verdict (established by measurement)**: `403` = bucket exists, listing blocked (normal) /
  `404` = does not exist / **`200` = listing public (dangerous)**.
- **The rule is S3/GCS-only.** It collapses on other providers — see the bucket section in `ops/verify.md`.
- **A 403 means neither "safe" nor "yours."** Blocking the listing while leaving individual objects public
  is a common real-world leak, and a generic-word bucket name almost certainly belongs to someone else.

## Axis 4 — Documents, sheets, and forms  (highest priority)
Cloud document suites, **form response spreadsheets**, **"publish to web" sheet exports**,
enterprise file sync services, large-file transfer services, note and wiki platforms,
slide-sharing sites, public boards, low-code databases, self-hosted wikis and trackers.

- **Regional collaboration suites**: checking only the globally dominant tools misses the platforms that
  mid-sized companies in your market actually use. Enumerate the local ones explicitly.
- **"Publish to web" is a separate feature from sharing permissions.** It passes a permissions audit and
  still gets indexed by search engines.
- **In a non-engineering organization, personal data lives in spreadsheets, not in code.**

## Axis 5 — AI output  (newest, and highest priority)
- **Conversation share links**: every major assistant. One click on "share" creates a
  **permanent public URL with no authentication.**
- **AI meeting notes**: transcription services. Among non-engineers these have the highest adoption, and
  **link sharing is the default interaction.** The transcript carries customer names, contract terms, and pricing.
- **Custom assistants and notebook tools**: policies, price lists, and contracts uploaded as knowledge
  files can be extracted with a few prompts.
- **AI document and slide generators**: default exposure settings are permissive.
- **Generation service galleries**: some image services default to a public gallery.
- **Residual citations in AI search**: a page you deleted keeps getting cited. The removal channel differs
  from ordinary search.
- **AI agent configuration files**: `.env`, MCP configs, agent instruction files, editor rule files.
  Internal URLs, connection strings, and keys concentrate in one file — a leading new leak class since 2025.
- **Your own `llms.txt` can backfire**: written for AI-search visibility, it may actively advertise
  internal paths you meant to keep quiet.

## Axis 6 — Messaging and community
Group chats and open chat rooms, customer-support chat widgets, blogs and cafes, developer Q&A sites,
public chat servers, professional networks, job postings, employer-review sites, business-card apps.

- **Operational group chats are often the top industry channel.** Dispatch sheets and handover forms
  carry customer names, phone numbers, addresses, and asset identifiers, and circulate as images to
  external contractors. In field-operations businesses this is **a daily, continuous flow.**
- Job postings, professional networks, and public filings are **reconnaissance and background**, not leaks.
  Keep them out of the leak metrics.

## Axis 7 — Infrastructure surface
Certificate Transparency (**run two sources**), passive DNS, **no-auth host lookup services**, open ports,
TLS certificate consistency, `robots.txt` and `X-Robots-Tag`.

- **Observability stacks**: public dashboards from BI and monitoring tools, public error-tracker issues,
  `.map` source maps. A public BI question link **renders the customer data itself.**
- **API docs and automation**: public API workspaces, OpenAPI specs, no-code automation scenarios, webhook URLs.
- **Asset-pivot identifiers**: analytics and tag-manager IDs, ad-network IDs, shared emails and phone
  numbers, favicon hashes. This is the most efficient way to find **sites an agency built that you never
  knew about.**
- **Impersonation and typosquatting**: look-alike domains. In industries where fake-site payment fraud is
  common this matters, and CT can detect it.
- **Standard business portals**: `mail.`, `erp.`, `groupware.` subdomains surface through CT logs.

## Axis 8 — Third parties and the supply chain  (a missing axis in most inventories)
Processors, agencies, maintenance vendors, logistics contractors, website builders, finance and insurance partners.

- **Your own privacy policy's list of processors is your target list.**
- **Agency landing pages and lead-capture forms** are a top priority: shadow landing pages built on
  site-builders and cheap hosting, collecting personal data into databases you do not control, and
  **absent from your asset register entirely.**
- **Notification is the answer.** No additional probing or harvesting (invariants 5, 12, 14).
- If the third party is a processor, the controller carries oversight responsibility, so this becomes
  your compliance problem too.

## Axis 9 — Industry-specific channels
Every industry has channels that generic inventories miss. Build this axis from your own operations.
Examples from asset-heavy, customer-facing operations:

- **Resale and marketplace listings** of retired assets: listing photos expose identifiers and service history.
- **Fleet-tracking or telematics dashboards**: unauthenticated exposure means live location of every
  asset — and of customers. Location-privacy law compounds the damage.
- **Aggregator and brokerage platforms**: inventory, pricing, and inquiries accumulate on a third-party
  platform, and review sections collect contract photographs.
- **Incident footage uploads**: identifiers and faces unblurred.
- **Photo EXIF**: depot and workshop GPS, capture device identifiers.
- **Public regulatory registries**: per-operator asset counts and identifiers complete your inventory for
  an outsider.

---

## Cross-cutting step — file-internals inspection
The inventory answers "**where** do I find the file." It must also answer
"**what is still inside** the file I found." This is a **mandatory follow-up** to axes 1-9.

- Spreadsheets: hidden sheets, hidden rows, pivot caches, filtered-away data
- PDF: **failed redaction** — the original text under the black box
- Local office formats: author, department, internal file-server paths, revision history
- Images: **EXIF GPS**, device information
- Office formats generally: author, last modified by, company name

> **Never copy originals to local storage** (invariant 10). Inspect minimally, mask, destroy after remediation.

---

## Priority — likelihood x impact

Rank for a **non-engineering organization rolling out AI company-wide**, where personal data means
customer records.

| # | Channel | Reasoning |
|---|---|---|
| 1 | Cloud drives and sheets, **form response spreadsheets**, publish-to-web | Where a non-engineering organization's personal data actually lives. Misconfigured link sharing approaches certainty |
| 2 | Operational group chats and personal devices | A daily, continuous flow. National identifiers trigger statutory notification duties |
| 3 | AI conversation share links and AI meeting notes | **Being created right now** during a company-wide rollout, with no controls and no user awareness |
| 4 | Agency landing pages and lead-capture forms (third party) | Absent from the asset register, and what they collect is personal data |
| 5 | **Unintended exposure on the official domain** (upload directories, backup files, staging) | Cheapest to find (CT plus dorks), and immediately actionable |
| 6 | Supply-chain servers (processors, builders) | Copies you do not control, in numbers you cannot see |
| 7 | Vibe-coded apps with backend rules unset | The inevitable output of non-engineers plus AI tools; opens the whole database |
| 8 | Archive residue | Cheap and reliable. The only way to prove "we already deleted it" is false |
| 9 | Former-employee and personal-account residue | High likelihood, hard to detect; access carries over wholesale |
| 10 | File-internals residue (hidden sheets, failed redaction, metadata) | One file can hold many records, so expected damage is high |
| 11-13 | Fleet or telematics dashboards, public buckets, look-alike domains | Maximum impact but unknown likelihood / verdict method established / industry fraud pattern |

## Exclusions — what was removed, and why
**Listing a tool that does not work produces false negatives.**

| Removed | Reason |
|---|---|
| Retired search caches, blocked code-search sites, dead search APIs, paywalled source-search services | Measured as blocked, retired, paid, or rate-limited |
| Commercial scan and threat-intel APIs, breach-database domain search | Paid keys (401 measured). A free no-auth host lookup covers the needed range |
| Bulk web-crawl indexes | Overlap heavily with web archives and cost a lot to parse |
| Public event-archive bulk files | Tens of MB per hour file; disproportionate to a narrow purpose |
| Code hosts and package registries irrelevant to the organization's stack | No basis to believe such assets exist |
| Search engines with negligible share in the target market | Negligible index contribution |
| Collaboration tools with negligible local adoption | Replace with the platforms that market actually uses |
| Public filings and registries | Lawful disclosure. Demote from leak channel to **background information** |
| Secret-scanning binaries | Not channels — they are tools, and they need a local repository to scan |

**Keep** low-cost channels even if the hit rate is low: local marketplaces, public procurement
attachments, public project boards. They cost almost nothing to check.
