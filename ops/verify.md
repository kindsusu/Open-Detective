# Verdicts — What Makes You Say "This Is Exposed"

Explaining a conclusion in words does not convince anyone. **Showing the response values ends the argument.**
But misreading those values is worse — you end up reporting safety that does not exist.

## The six rules

### 1. Anonymous and authenticated have different jobs — use both, never conflate them

| Vantage point | Question it answers | Canonical tool |
|---|---|---|
| **Anonymous** | "Can an outsider see this?" = **exposure verdict** | REST listing, direct URL (not the search API) |
| **Authenticated** | "What exists?" = **inventory** | `gh api`, organization repository listing |

> **Do not use a search API for the anonymous verdict.** Search is affected by index lag and
> tokenization, so "it doesn't come up" does not mean "it isn't there." The canonical sources for an
> exposure verdict are REST listings and direct URLs.
>
> Measured: anonymous `orgs/<org>` returned `public_repos: 0` while the authenticated listing returned
> six, all private. The conclusion was the same, but **the comparison used asymmetric tools.**
> Compare like with like.

### 2. The invariant for reproducibility is a digest, not a byte count

Identical byte counts mean **the content has not changed** — not that the technique reproduces.
Had the content changed, the technique would have worked identically and only the size would differ.

Record: **`sha256` + `ETag` + `Last-Modified`** + status code + final URI.
Use size only as a secondary indicator.

### 3. Do not trust status codes — the catalogue of failures that look like negatives

If you cannot tell zero results from a failed request, **you will report safety that does not exist.**

| Symptom | Looks like | Actually |
|---|---|---|
| Google cache `200` | Cache hit | Body is `<title>Google Search</title>` — the endpoint was retired |
| archive.today `302` | Rate limited | **No signal at all.** Domain rotation between mirrors. Follow with `-L` to distinguish 404 (no snapshot) from a real snapshot |
| crt.sh `404` | Zero certificates | An Apache error page |
| Common Crawl `504` / `"No index found"` | Zero results | Gateway timeout / wrong collection ID |
| Azure Blob `000` (curl exit 6) | Not found | DNS NXDOMAIN. An existing account's root returns `400`, so the 403/404 rule collapses |
| Malformed CDX query | Zero results | Missing `output=json` and the trailing wildcard. **If the control also returns zero, suspect the query** |
| Reused output file | Previous result | A failed request shows you the **previous response body**. Truncate per request and check the exit code |
| Search page `200` | Results found | Board and document platforms all return 200. **Judge by content** |
| `403` on a data endpoint | Blocked, boundary holds | A header allowlist. Replay the calling page's `Origin`/`Referer` with a browser UA and the body is served in full. See **A 403 is not a boundary either** |
| `403` to a tool user agent | Blocked | Some edge gates blocklist non-browser UAs. **The scanner's own UA manufactured the negative** |

### 4. Attach a control to every negative

Run a positive control (something that must be found) and a negative control with the same tool and the
same query format. If the control fails too, **the measurement is wrong, not the result.**

> Real failure: while re-checking an archive, the target and the control both returned zero — the query
> format was wrong. Without the control it would have been recorded as "no residue."

### 5. Cross-check external intel by connecting directly

**Port lists from public scan-data services can be stale.**

> Measured counterexample: the service reported `ports: [80, 3000, 5601, 9200]` while **443 was live and
> serving a full page.** The response carries no per-port observation timestamp. Data that omits an open
> port can equally retain a closed one.

- **Exclude the `vulns` field from reports.** A CPE without a version (for example `cpe:/a:apache:tomcat`)
  matches every CVE for that product, dragging in items over a decade old. That is noise, not signal.
- **"Ports are the reliable signal" is also wrong** — the missing 443 disproves it.

### 6. Confirm tenancy before attributing an IP to an asset

Never call something "the company's IP" without a reverse lookup.

> Measured: one address hosted `<company-domain>`, `dev.<company-domain>`, `<domain-B>` (plus www and
> dev), `<domain-C>`, and `<domain-D>`. The default vhost on `:80` redirected to `www.<domain-B>` — the
> domain under audit was not even the primary site on that box.
> **There is no basis for attributing a port to a specific service.**

A reverse IP lookup **surfaces assets the original audit never found** in a single step. Running CT
against one apex domain only will miss them.

---

## Exposure verdict procedure

```
1. Request from the anonymous vantage point (no auth token, no cookies)
2. Record status code + sha256 + ETag/Last-Modified + final URI
3. If the final URI is an auth gate (identity provider), the verdict is AUTH-GATE
4. If the body is served in full, the asset is EXPOSED
5. Measure controls the same day, the same way
6. Report confirmed and unconfirmed separately
```

**Example controls (measured)**

| Target | Response | Verdict |
|---|---|---|
| `<internal-site>.pages.dev` | 200, redirected to an identity provider, body not served | AUTH-GATE |
| `<user>.github.io/<repo>/` | 200, ~82KB body served in full | **EXPOSED** |

Those two lines prove "a login screen is not a security boundary" without any explanation.

## Verdicts the tool emits

| Verdict | Meaning |
|---|---|
| `EXPOSED` | The body was served in full to an anonymous request |
| `AUTH-GATE` | The final host is a **configured** identity provider, and the body was not served |
| `WEAK-GATE` | 401/403 to a bare request, **but the body was served** when the calling page's own headers were replayed. Triage and remediate as `EXPOSED` |
| `BLOCKED` | 401/403, and it stayed blocked |
| `ABSENT` | 404/410 |
| `NO-BODY` | 2xx with an empty body |
| `UNKNOWN` | Could not be classified. **Deliberately not EXPOSED** |
| `REJECTED` | Out of scope by design: non-http(s) scheme, or a non-public address |
| `ERR` | DNS failure, TLS mismatch, transfer error |

### Runtime-observed verdicts — the browser's eye

These verdicts are recorded **by the auditor** from a §5b browser pass (`ops/discovery.md`). They are
**not emitted by `probe.sh`** — the tool does not run JavaScript.

| Runtime observation | Recorded verdict |
|---|---|
| A cosmetic client-side gate whose data was already transmitted, or a page that loads its real data via JS with no auth | **EXPOSED** — record what the network/DOM revealed |
| Client-side encryption (an encrypted blob, the password derives the key) | **CLIENT-ENCRYPTED (not decrypted)** — a distinct recorded state, never brute-forced or decrypted; remediation routes to real server-side auth |
| Anything you cannot classify without acting on the system | **UNKNOWN** |

**A browser-observed fetch is a Confirmed fact.** An anonymous page loading `GET /api/…` → 200 with a
body is on equal footing with a curl-observed `EXPOSED`, because it reproduces exactly what any
anonymous visitor's browser receives. This resolves the ambiguity in triage's "Confirmed" definition:
a browser-observed anonymous fetch counts, not only a curl `GET`.

### Why UNKNOWN exists
An unproven exposure is not an exposure. The tool returns `UNKNOWN` rather than guessing when
the request lands off-site on a host it cannot classify, when a 3xx is left unresolved, and
when there is no HTTP status code at all.

### Auth-gate matching is host-exact, never substring
Matching an identity provider by substring against the whole final URL is **wrong in both
directions**, and this was demonstrated: `https://example.com/?redir=okta.com` was classified
`AUTH-GATE` — an exposed asset reported as controlled, which is the worst error this tool can
make. Match on the **parsed host** with an exact or dot-boundary suffix comparison.

**Your own identity provider will not be in the default list.** Set `SU_IDP_HOSTS` to the hosts
your organization actually redirects to, or every controlled asset behind a custom IdP will read
as `EXPOSED`.

> A same-host `/login` page that returns 200 with a body **is** `EXPOSED`, and that is correct —
> it is the central claim of this skill. A login screen rendered in the browser is not a boundary.
> Only a server that refuses to transmit is.

### A 403 is not a boundary either

The same claim, one layer down. A login screen is not a boundary because the body already
travelled. **A header allowlist is not a boundary because the string it checks is written by the
caller.** Both look like control from the outside; neither refuses to transmit.

The shape to watch for is a public page that fetches its data from a separate endpoint:

| Request | Response |
|---|---|
| bare `GET <data-endpoint>` | `403`, a short error body |
| same `GET` + `Origin`/`Referer` of `<page>` + a browser UA | `200`, **the full dataset** |
| `Origin` of an unrelated site | `403` — the allowlist is real, and it is still not a boundary |

A first sweep that only sends a bare request records `BLOCKED` and closes the asset as safe.
That is a **false negative**, and it is the failure this verdict exists to prevent. Worse, some
gates blocklist non-browser user agents, so the scanner's own UA can manufacture the negative
on its own.

**The replay is fenced by four conditions. Break one and this becomes the tool the skill forbids.**

| Condition | Why |
|---|---|
| **Opt-in** — only when the operator names the calling page | That naming is the ownership assertion (invariant 12). Never inferred, never applied blanket across a batch |
| **One shot** — a single request | No enumeration, no credential guessing (invariants 1, 4, 9) |
| **Same page** — headers derived from that page's own URL | Reproduces a request an anonymous browser already makes. Inventing an allowlist value would be circumvention |
| **No body** — `-o /dev/null` | Measures *whether* the body is served, never *what is in it* (invariants 10, 11). Hence no `sha256` on this verdict |

Within those four, this is reproduction, not circumvention: loading the page in a browser already
causes exactly this request. Outside them it is not.

**Reading the row**: `CODE` is the bare-request status, `BYTES` is what the replay was served, and
`SHA256` is `-` because nothing was retained.

```
<endpoint>   403   <error-body>     <digest>   BLOCKED     # no calling page named - opt-in held
<endpoint>   403   <full-dataset>   -          WEAK-GATE   # calling page named - the gate opened
<hard-403>   403   0                -          BLOCKED     # a real refusal stays a refusal
```

Those three lines are the control set: the verdict fires on the gate that opens, and on nothing else.

### The measurement tool is itself an attack surface
Four high-severity defects were found by *running* `probe.sh`, not by reading it:

| Defect | Symptom |
|---|---|
| Query string in the default label | The final URI was masked while the label printed `?token=...` verbatim |
| No scheme restriction | `file:///etc/passwd`-style paths were read and reported `EXPOSED` |
| Substring auth-gate matching | Any URL containing a provider name anywhere was `AUTH-GATE` |
| No HTTP status required | A response with status `000` still produced an exposure verdict |

Restrict the scheme to http/https, refuse loopback, private, link-local and reserved addresses (IPv4 and IPv6 literals alike)
on both the first and final hop, cap the response body, and clean the temp buffer on
`EXIT INT TERM`. Run `tools/test_probe.sh` before changing the script.

**Known limit**: curl validates the scheme of every redirect hop, but the script can only resolve
the **first and final** hosts. A chain that transits a private address in between is not detected.
Saying so is better than advertising safety that does not exist.

## When you print headers

**Always filter `Set-Cookie`, `Authorization`, `Proxy-Authorization`, and `X-Api-Key`.**

> Real incident: dumping headers with `curl -D` printed a live session token straight into the output.
> The audit record itself becomes a leak source.

The final URI needs the same treatment — **authentication redirects carry a JWT in the query string.**
Strip the query before recording it.

## Residue verdicts — how to verify "we deleted it"

**A negative from one channel is not evidence of absence.** Until you have checked all of the following,
do not write "no residue." What you can write is a **point-in-time statement**.

| Vector | How to check | Notes |
|---|---|---|
| Wayback | CDX API (`url=<target>*&output=json`) | Wrong format produces a false negative |
| Common Crawl | Check **several collections** | One is not enough. Beware 504 and "No index found" |
| archive.today | Follow with `-L`, then confirm 404 | A 302 carries no signal |
| Software Heritage | Origin search | Crawls code hosts continuously — **absent today does not mean absent tomorrow** |
| **Third-party CDN mirrors** | `cdn.jsdelivr.net/gh/<user>/<repo>@<ref>/<path>` | **A commit-pinned path is effectively permanent** |
| Commit SHA | Direct SHA lookup | Still returns 200 after removal from a branch, until garbage collection |
| Event archives | Search the repository name in public event data | Deletion does not remove past events |
| Fork network | Check forks | Zero today can change |
| Search-engine index | Each engine separately | **Check before you close the asset**, not after |

> **Demonstrated counterexample**: a GitHub Pages host had zero Wayback snapshots, yet
> **jsDelivr was already serving `<repo>@main/index.html` with a byte-for-byte identical hash.**
> "Not in Wayback" does not equal "no residue."
>
> In the same organization, another development server did have archived snapshots. Assuming
> "it won't get archived" has no basis either.

**Closing an asset can itself create residue** — re-check the archives after you close it.

## Bucket verdicts — an S3/GCS-only rule

| Response | Meaning for S3/GCS |
|---|---|
| `404` NoSuchBucket | Does not exist |
| `403` AccessDenied | Exists, listing blocked |
| `200` listing | **Public (dangerous)** |

**Do not extend this rule as-is.**

- **Azure breaks it**: a nonexistent account is DNS NXDOMAIN (`000`); an existing account's root returns
  `400`. You need `?restype=container&comp=list` to get a verdict.
- **403 does not mean safe**: blocking the listing while leaving **individual objects public** is a
  common real-world leak. Classifying only a 200 listing as dangerous misses that case entirely.
- **403 does not prove ownership**: a generic-word bucket such as `brandword` is overwhelmingly likely to
  belong to someone else. Apply invariant 12 to buckets too.

## Certificate Transparency — run two sources, not one

- Public CT search sites can be **unstable rather than dead**. In one session of eight attempts: one 200,
  two 404s, five 502s, one timeout. Wrap them in retries.
  **A 404 there is an error page, not "zero certificates."**
- **Free tiers of CT monitoring APIs often return only currently valid certificates.**
  Retired subdomains — old staging hosts and the like — will never appear.
  Such an API is a **complement, not a replacement.**
- **Do not run CT against a single apex.** Run it separately against every domain the reverse IP lookup
  surfaced.
