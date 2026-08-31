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
3. If the final URI is an auth gate (identity provider), the asset is CONTROLLED
4. If the body is served in full, the asset is EXPOSED
5. Measure controls the same day, the same way
6. Report confirmed and unconfirmed separately
```

**Example controls (measured)**

| Target | Response | Verdict |
|---|---|---|
| `<internal-site>.pages.dev` | 200, redirected to an identity provider, body not served | Controlled |
| `<user>.github.io/<repo>/` | 200, ~82KB body served in full | **Exposed** |

Those two lines prove "a login screen is not a security boundary" without any explanation.

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
