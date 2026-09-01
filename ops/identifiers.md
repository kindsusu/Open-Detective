# Identifier generation — what to search for

Phase 0 tells you to collect "company name, abbreviations, brands, account names." That is a
list of *categories*, not a *method*, and the gap between them is where audits fail.

**The account hosting a leak is almost never the registered company name.** It is a coinage an
employee invented at signup, under three pressures: the platform namespace (no spaces, lowercase,
ASCII, length caps), uniqueness (the obvious name was taken), and personal shorthand habit.
Searching the company name reaches none of that.

> Precedent: an exposed personal account was found only after a human manually tried
> `<stem>+<business-function word>`. The function word appears **nowhere in the company name**.
> Once that one account was found, pivoting off it surfaced eight exposed repositories at once —
> and search-engine dorks had found **zero** of them.

Two phases, and the second one is where the yield is.

## Phase A — generate the search space

```bash
python3 tools/idgen.py --ko "<name in your script>" --en "<name in Latin, as the company writes it>" \
                       --industry "<line of business>" --limit 200
python3 tools/idgen.py --en "<name>" --targets github > targets.tsv   # probe.sh-ready rows
python3 tools/idgen.py --selftest
```

Five transformation classes. A tool that applies only the first two will miss the leak.

### 1. Segmentation
A compound name is not one token. Split it, and **search each unit separately** — the account may
use only one half. Strip legal and geographic tails first (`Inc`, `Ltd`, `Holdings`, `Group`,
country names): they carry no identity. In scripts without spaces, split at a known industry tail;
the tail itself remains searchable on its own.

### 2. Transliteration — and the trap in it
Three directions, not one:

| Direction | Example |
|---|---|
| Local script → romanization rule | `코스모스` → `koseumoseu` |
| Local script → **origin spelling** | `코스모스` → `cosmos` |
| Latin → local script variants | `rentcar` → two accepted spellings, both in use |

**The trap**: when a stem is a loanword, the official romanization is *not* what the company writes.
The rule yields `koseumoseu`; the company registers `cosmos`. A tool that applies only the
romanization rule misses the target completely. `idgen.py` emits the rule-based form, and the
operator must supply the origin spelling via `--en`. **This is the single most common miss.**

Orthographic wobble matters too: where a loanword has two accepted local spellings, both are live,
and so is the spaced/unspaced pair.

### 3. Abbreviation — including the one Latin-centric tools skip
- **Syllable initials**: one letter per syllable of the local-script stem. A three-syllable stem
  becomes a three-letter tag. This is not English vowel-dropping and is generated separately.
- Vowel-dropping: `cosmos` → `csms`
- Truncation: first three or four letters
- Initialism across the whole compound name

### 4. Business-function affixes — the class that finds accounts
`{stem}{joiner}{function}`, where the function word is **absent from the company name**: sales,
partners, dev, admin, team, official, corp, group, service, support, cs, hr, ops, lab, biz, tech,
data, api, web, app, shop, media, marketing, and the local-language equivalents. Joiners: none,
hyphen, underscore. This is the class that produced the precedent above.

### 5. Industry vocabulary and numeric suffixes
The line of business as a word, plus `1`, `2`, `01`, a year, or a four-digit tag.

### Ranking, and why it is not cosmetic
Anonymous rate limits are real (a public code host allows on the order of 60 requests/hour), so the
list is measured from the top down and the tail is never reached. `idgen.py` ranks by **stem
quality first** — a name the company actually writes outranks one the script invented by chopping
letters — then by affix class. Sorting by length instead floats junk abbreviations above the real
name; that was measured and fixed.

> Calibration: replaying a known real case, the identifier a human had found by hand came out at
> **rank 28**, with two more true positives at ranks 3 and 38. One hour inside the anonymous rate
> limit covers that.

## Phase B — pivot (higher yield than generating more)

Generation exists to find the **first entry point**. After one confirmed hit, stop generating and
pivot: affiliates and brands share no morpheme with the parent name and will never be generated.

| Pivot | What it gives |
|---|---|
| Commit author name and email on a found repository | Other accounts by the same person |
| Account's organizations, followers, forks, stars | Adjacent accounts |
| **Descriptions and READMEs of found repositories** | **New stems in the company's own words** — feed them back into Phase A |
| Reverse IP on a known domain | Other domains on the same box; run CT against each |
| Certificate Transparency per domain | Subdomains, retired staging names |
| Shared analytics/tag IDs, favicon hash | Sites built by the same agency |

The third row is the loop that matters: a repository description written by an employee contains the
vocabulary that employee uses, which is the vocabulary the *next* account was named with. Run Phase
A again with those words.

## Boundaries

- **A candidate is a guess, not an asset.** A generic coinage very often belongs to someone else.
  Confirm ownership before probing (invariant 12); a name resembling yours is not yours.
- Generation is offline. `idgen.py` makes no network requests — it writes candidates, and
  `probe.sh` measures them. Keep those two jobs separate.
- Candidate volume does not license mass scanning (invariant 4). Rank, take the top, and pivot as
  soon as something confirms.
- **No company values belong in this repository.** Seeds come in as arguments at runtime. The
  lexicons in `idgen.py` are generic business vocabulary, and they must stay that way — a skill
  carrying a real company's naming map is a reconnaissance map.
