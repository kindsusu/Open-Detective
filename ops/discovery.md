# Execution Layer — How You Find Things

If the inventory says *where* to look, this document says *with what*.
**Everything here was actually run and confirmed working.**
A tool that does not work produces false negatives, so failed tools are quarantined in the last section
with the reason.

> Endpoints change. Re-verify before you trust any of this, and record the date you did.
> The failure catalogue in `ops/verify.md` explains how to tell "zero results" from "the tool broke."

## 1. Account and repository enumeration — anonymously

This is the canonical exposure verdict. Use **REST listings, not the search API**.

```bash
# Is it an organization or a personal account? A 404 means it is not an organization
curl -s "https://api.github.com/users/<account>"        # type: User | Organization

# What an anonymous visitor sees — this is the exposure verdict
curl -s "https://api.github.com/users/<account>/repos?per_page=100&sort=pushed"
curl -s "https://api.github.com/orgs/<org>/repos?per_page=100"
```

- Anonymous rate limit is **60 requests/hour**. Authenticated: 5000/hour core, 30/min search,
  **10/min code search** (the tightest constraint, and the one that shapes your plan).
- An authenticated `gh search` **mixes the auditor's own private repositories into the results.**
  Use it only to build inventory.
- Once you find one account, **pivot**: commit authors, organization members, forks, affiliate name
  combinations.

**Classifying risk without fetching file contents** — the honest way to minimize contact with personal data.

```bash
curl -s "https://api.github.com/repos/<account>/<repo>/git/trees/HEAD?recursive=1"
```

Flag extensions such as `json`, `env`, `ya?ml`, `csv`, `xlsx?`, `sql`, `pem`, `key`, `bak`.
**A repository containing configuration or data files is the most dangerous kind.**

## 2. Subdomain and asset discovery

### 2-1. Certificate Transparency — run two sources

```bash
# A CT monitoring API: stable, but free tiers often return only currently valid certificates
curl -s "https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names"

# A public CT search site: shows retired history, but is unstable, so retry
for i in 1 2 3 4 5; do
  curl -s -f "https://crt.sh/?q=%25.<domain>&output=json" && break
  sleep 5
done
```

- The public search site is **unstable rather than dead** (one session: one 200, two 404s, five 502s,
  one timeout).
- Its **404 is an error page**, not "zero certificates."
- The monitoring API's free tier returns **valid certificates only**, so retired subdomains never appear.
  It is a **complement, not a replacement.**

### 2-2. Reverse IP — the single highest-yield move

```bash
IP=$(python -c "import socket;print(socket.gethostbyname('<domain>'))")
curl -s "https://internetdb.shodan.io/$IP"        # no auth: hostnames, ports, cpes
```

**Running CT against one apex only will miss things.** When other domains on the same box appear,
run section 2-1 against each of them.

> Measured: a single reverse lookup surfaced three additional domains, one of which hosted a
> development server exposed without authentication.

- **Always cross-check the `ports` list by connecting directly.** Staleness is demonstrated — a live
  443 was missing from the list.
- **Exclude the `vulns` field from reports.** A version-less CPE matches every CVE for that product.

### 2-3. Subdomain guessing — a secondary method

`dev`, `staging`, `test`, `admin`, `api`, `mail`, `erp`, `groupware`, `metabase`, `grafana`, `kibana`.
Check only whether DNS resolves. **Less reliable than CT, so run CT first.**

## 3. Archives and residue

```bash
# Wayback CDX — the wrong format produces a false negative
curl -s "http://web.archive.org/cdx/search/cdx?url=<target>*&output=json&collapse=urlkey&fl=original,timestamp,statuscode"

# Quick single-URL check
curl -s "https://archive.org/wayback/available?url=<target>"

# Third-party CDN mirror — a commit-pinned path is effectively permanent
curl -sI "https://cdn.jsdelivr.net/gh/<account>/<repo>@<ref>/<path>"

# Direct commit SHA lookup — still 200 after removal from a branch, until garbage collection
curl -s "https://api.github.com/repos/<account>/<repo>/commits/<SHA>"
```

- **Without the trailing `*` and `output=json`, the CDX query looks like zero results.** Run a control.
- archive.today needs **`-L`** to distinguish a 404 (no snapshot) from a real one. A 302 carries no signal.
- Software Heritage crawls code hosts continuously — **absent today does not mean absent tomorrow.**

> **A negative from one channel is not evidence of absence.** Demonstrated: a Pages host had zero Wayback
> snapshots while a CDN was already mirroring the same file with an identical hash.

## 4. Search-engine dorks

Use a web-search tool or each engine directly. **Always add the dominant local-language engine.**

| Purpose | Query |
|---|---|
| Leaked documents | `"<company>" filetype:pdf OR filetype:xlsx OR filetype:docx` |
| Local office formats | `"<company>" filetype:hwp OR filetype:hwpx` |
| Cloud documents and sheets | `site:docs.google.com "<company>"` |
| AI conversation share links | `site:chatgpt.com/share OR site:claude.ai/share "<company>"` |
| AI meeting notes | `site:<note-service-domain> "<company>"` |
| Deployment hosting | `site:github.io OR site:pages.dev OR site:vercel.app "<company>"` |
| Code playgrounds | `site:codepen.io OR site:jsfiddle.net OR site:codesandbox.io "<company>"` |
| Public boards | `site:trello.com OR site:notion.site "<company>"` |

> **Dorks alone are not enough.** Demonstrated: eight exposed Pages sites were **not found by dorks at
> all** because they were never indexed. Account enumeration found them.
> **Coverage differs per channel — run them in parallel.**

## 5. Exposure measurement

See `tools/probe.sh`. Full verdict rules in `ops/verify.md`.

```bash
bash tools/probe.sh "https://<target>/" "<label>"
bash tools/probe.sh --batch targets.tsv
```

Record: status code, **sha256**, ETag, Last-Modified, final URI, body size.
**Size is a secondary indicator.** The invariant for reproducibility is the digest.

## 6. Storage buckets

```bash
curl -s -o /dev/null -w "%{http_code}" "https://<name>.s3.amazonaws.com/"
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/<name>/"
curl -s -o /dev/null -w "%{http_code}" "https://<account>.blob.core.windows.net/?restype=container&comp=list"
```

Follow the bucket section of `ops/verify.md`. **The rule is S3/GCS-only and collapses on Azure.**
**A 403 means neither "safe" nor "yours."**

## 7. Package and artifact registries

```bash
curl -s "https://registry.npmjs.org/-/v1/search?text=<keyword>&size=20"
curl -s "https://hub.docker.com/v2/search/repositories/?query=<keyword>&page_size=20"
curl -s "https://huggingface.co/api/models?search=<keyword>&limit=20"
```

Registries unrelated to the organization's language stack are worth checking **only when there is a
reason to believe such an asset exists.**

## 8. Tools that do not work — do not use them

| Tool | Measured result | Verdict |
|---|---|---|
| Google cache | 200, but the body is `<title>Google Search</title>` | **Retired.** Confirmed with a positive control |
| grep.app | 429, security checkpoint interstitial | Blocked |
| searchcode API | 404 on two endpoints | Retired |
| publicwww | 200, but the page says "Sign Up" | Paid |
| Commercial scan APIs (Shodan, Censys) | 401 | Paid key. **Use the free no-auth host lookup instead** |
| VirusTotal, breach-database domain search | 401 | Paid key |
| Common Crawl | Works, but overlaps Wayback and costs a lot to parse | Only when you need residue cross-confirmation |
| Public event archives | Work, but tens of MB per hour file | Only for tracing deleted repositories |
| Postman public search API | 404 | Use a dork instead |
| Supabase / preview-URL enumeration | DNS miss / 404 | **Not enumerable.** You need the real project ref from app source |
